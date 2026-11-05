"""FastAPI server: SOC dashboard API + Telegram webhook (for Vercel / serverless).

Security model
  * /api/webhook   -> only Telegram (verified with X-Telegram-Bot-Api-Secret-Token)
  * every other /api/* route requires the ADMIN_TOKEN (Bearer or X-Admin-Token)
  * uploads are size-limited and web scans are rate-limited per IP
"""
import hmac
import logging
import os
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ai_analyzer import AIThreatAnalyzer
from config import (
    ADMIN_TOKEN,
    DANGEROUS_EXTENSIONS,
    HOST,
    MAX_UPLOAD_BYTES,
    PORT,
    PUBLIC_BASE_URL,
    TELEGRAM_BOT_TOKEN,
    USER_RATE_LIMIT_PER_MIN,
    WEBHOOK_SECRET,
)
from database import aget_recent_scans, aget_soc_stats, aget_user_analytics, alog_scan_event
from scan_service import SCORES, UserRateLimiter, scan_text
from vt_scanner import VirusTotalScanner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ServerAPI")

app = FastAPI(title="NSSF Security Scan API", version="2.0.0", docs_url=None, redoc_url=None)

static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if not os.path.isdir(static_dir):
    static_dir = os.path.join(os.getcwd(), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

ai_analyzer = AIThreatAnalyzer()
vt_scanner = VirusTotalScanner()
web_rate_limiter = UserRateLimiter(USER_RATE_LIMIT_PER_MIN)


# --- security helpers ----------------------------------------------------------
def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def require_admin(request: Request) -> None:
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="ADMIN_TOKEN is not configured on the server")
    supplied = request.headers.get("x-admin-token", "")
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        supplied = auth[7:].strip()
    if not supplied or not hmac.compare_digest(supplied.encode(), ADMIN_TOKEN.encode()):
        raise HTTPException(status_code=401, detail="Unauthorized")


def limit_web_scans(request: Request) -> None:
    if not web_rate_limiter.allow(get_client_ip(request)):
        raise HTTPException(status_code=429, detail="Too many scans, slow down")


# --- Telegram webhook app (lazy, for serverless) ---------------------------------
_telegram_app = None
_telegram_ready = False


def get_telegram_app():
    global _telegram_app
    if _telegram_app is None and TELEGRAM_BOT_TOKEN:
        try:
            import bot

            _telegram_app = bot.build_application(with_post_init=False)
        except Exception:
            logger.exception("Telegram app init failed")
    return _telegram_app


# --- pages -----------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    return HTMLResponse("<h1>NSSF Security Scan API is running.</h1>")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


# --- admin API ---------------------------------------------------------------------
@app.get("/api/stats", dependencies=[Depends(require_admin)])
async def api_stats():
    return await aget_soc_stats()


@app.get("/api/scans", dependencies=[Depends(require_admin)])
async def api_scans(limit: int = 50):
    return await aget_recent_scans(limit=max(1, min(limit, 200)))


@app.get("/api/users", dependencies=[Depends(require_admin)])
async def api_users():
    return await aget_user_analytics()


class ScanTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=4000)
    chat_type: Optional[str] = "web_simulator"


@app.post("/api/scan/text", dependencies=[Depends(require_admin), Depends(limit_web_scans)])
async def api_scan_text(payload: ScanTextRequest, request: Request):
    text = payload.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Text cannot be empty")

    ai_report, vt_reports, level = await scan_text(ai_analyzer, vt_scanner, text)
    await alog_scan_event(
        chat_id="WEB_SIMULATOR", chat_type="web", sender_id="web_user",
        scan_type="URL" if ai_report.get("urls_found") else "TEXT", input_summary=text,
        risk_level=level, risk_score=ai_report["risk_score"], threat_details=ai_report,
        virustotal_details=vt_reports[0] if vt_reports else {},
        user_name="Web Simulator User", ip_address=get_client_ip(request),
    )
    return {"status": "success", "highest_risk": level, "ai_report": ai_report, "vt_reports": vt_reports}


@app.post("/api/scan/file", dependencies=[Depends(require_admin), Depends(limit_web_scans)])
async def api_scan_file(request: Request, file: UploadFile = File(...)):
    filename = os.path.basename(file.filename or "upload")
    ext = os.path.splitext(filename)[1].lower()

    chunks, total = [], 0
    while chunk := await file.read(1024 * 1024):
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail=f"File too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)}MB)")
        chunks.append(chunk)

    vt_result = await vt_scanner.scan_file_hash(b"".join(chunks), filename)
    status = vt_result.get("status", "UNKNOWN")
    await alog_scan_event(
        chat_id="WEB_SIMULATOR", chat_type="web", sender_id="web_user", scan_type="FILE",
        input_summary=f"File: {filename} ({ext})", risk_level=status, risk_score=SCORES.get(status, 0),
        threat_details={"filename": filename, "extension": ext,
                        "description": DANGEROUS_EXTENSIONS.get(ext, "File")},
        virustotal_details=vt_result, user_name="Web Simulator User", ip_address=get_client_ip(request),
    )
    return {"status": "success", "filename": filename, "extension": ext,
            "risk_level": status, "virustotal": vt_result}


# --- Telegram webhook ----------------------------------------------------------------
@app.post("/api/webhook")
async def telegram_webhook(request: Request):
    global _telegram_ready
    if not WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="WEBHOOK_SECRET is not configured")
    supplied = request.headers.get("x-telegram-bot-api-secret-token", "")
    if not hmac.compare_digest(supplied.encode(), WEBHOOK_SECRET.encode()):
        raise HTTPException(status_code=403, detail="Forbidden")

    tg_app = get_telegram_app()
    if not tg_app:
        return JSONResponse({"status": "disabled"}, status_code=200)
    try:
        from telegram import Update

        update = Update.de_json(await request.json(), tg_app.bot)
        if not _telegram_ready:
            await tg_app.initialize()
            _telegram_ready = True
        await tg_app.process_update(update)
    except Exception:
        # Always answer 200 so Telegram does not retry the same update forever.
        logger.exception("Error processing webhook update")
    return JSONResponse({"status": "ok"}, status_code=200)


@app.post("/api/set_webhook", dependencies=[Depends(require_admin)])
async def api_set_webhook(url: Optional[str] = None):
    """Register the webhook with Telegram (uses WEBHOOK_SECRET as secret_token)."""
    if not WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="WEBHOOK_SECRET is not configured")
    tg_app = get_telegram_app()
    if not tg_app:
        raise HTTPException(status_code=500, detail="Bot token not configured")
    target = url or (f"{PUBLIC_BASE_URL}/api/webhook" if PUBLIC_BASE_URL else "")
    if not target.startswith("https://"):
        raise HTTPException(status_code=400, detail="Provide an https url or set PUBLIC_BASE_URL")
    await tg_app.initialize()
    ok = await tg_app.bot.set_webhook(url=target, secret_token=WEBHOOK_SECRET)
    return {"status": "success" if ok else "failed", "webhook_url": target}


if __name__ == "__main__":
    uvicorn.run("server:app", host=HOST, port=PORT)
