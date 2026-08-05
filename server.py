import os
import logging
import uvicorn
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional

from config import HOST, PORT, DANGEROUS_EXTENSIONS, TELEGRAM_BOT_TOKEN
from ai_analyzer import AIThreatAnalyzer
from vt_scanner import VirusTotalScanner
from database import log_scan_event, get_recent_scans, get_soc_stats

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ServerAPI")

app = FastAPI(title="Security SOC Scan API", version="1.0.0")

# Lazy-loaded Telegram Application instance for Serverless compatibility
_telegram_app = None

def get_telegram_app():
    global _telegram_app
    if _telegram_app is None and TELEGRAM_BOT_TOKEN:
        try:
            import bot
            from telegram.ext import Application, CommandHandler, MessageHandler, filters
            app_builder = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
            app_builder.add_handler(CommandHandler("start", bot.start_command))
            app_builder.add_handler(CommandHandler("help", bot.help_command))
            app_builder.add_handler(CommandHandler("status", bot.status_command))
            app_builder.add_handler(CommandHandler("scan", bot.handle_message))
            app_builder.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
            app_builder.add_handler(MessageHandler(filters.Document.ALL, bot.handle_document))
            _telegram_app = app_builder
        except Exception as e:
            logger.error(f"Telegram App Lazy Init Error: {e}")
    return _telegram_app

# Static Directory setup
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if not os.path.exists(static_dir):
    static_dir = os.path.join(os.getcwd(), "static")

ai_analyzer = AIThreatAnalyzer()
vt_scanner = VirusTotalScanner()


class ScanTextRequest(BaseModel):
    text: str
    chat_type: Optional[str] = "web_simulator"

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """
    Serve main Web SOC Security Dashboard with robust fallback.
    """
    try:
        index_path = os.path.join(static_dir, "index.html")
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
    except Exception as e:
        logger.error(f"Error serving index.html: {e}")
    return HTMLResponse("<h1>Security SOC Scan API is Running.</h1>")

@app.get("/static/css/{file_name}")
async def serve_css(file_name: str):
    file_path = os.path.join(static_dir, "css", file_name)
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), media_type="text/css")
    return JSONResponse({"error": "CSS File not found"}, status_code=404)

@app.get("/static/js/{file_name}")
async def serve_js(file_name: str):
    file_path = os.path.join(static_dir, "js", file_name)
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), media_type="application/javascript")
    return JSONResponse({"error": "JS File not found"}, status_code=404)

@app.get("/api/stats")
async def api_stats():
    """
    Get aggregated SOC Dashboard metrics.
    """
    return get_soc_stats()

@app.get("/api/scans")
async def api_scans(limit: int = 50):
    """
    Get recent scan logs.
    """
    return get_recent_scans(limit=limit)

@app.post("/api/scan/text")
async def api_scan_text(payload: ScanTextRequest):
    """
    Analyze message content or links sent via Web Simulator.
    """
    text = payload.text
    if not text:
        raise HTTPException(status_code=400, detail="Text cannot be empty")

    ai_report = await ai_analyzer.analyze_message(text)

    vt_reports = []
    if ai_report.get("urls_found"):
        for url in ai_report["urls_found"][:3]:
            vt_res = await vt_scanner.scan_url(url)
            vt_reports.append(vt_res)

    highest_risk = ai_report["risk_level"]
    for vt in vt_reports:
        if vt.get("status") == "DANGEROUS":
            highest_risk = "DANGEROUS"
            ai_report["risk_score"] = max(ai_report["risk_score"], 95)
        elif vt.get("status") == "SUSPICIOUS" and highest_risk != "DANGEROUS":
            highest_risk = "SUSPICIOUS"

    # Log to Database
    log_scan_event(
        chat_id="WEB_SIMULATOR",
        chat_type="web",
        sender_id="web_user",
        scan_type="URL" if ai_report.get("urls_found") else "TEXT",
        input_summary=text,
        risk_level=highest_risk,
        risk_score=ai_report["risk_score"],
        threat_details=ai_report,
        virustotal_details=vt_reports[0] if vt_reports else {}
    )

    return {
        "status": "success",
        "highest_risk": highest_risk,
        "ai_report": ai_report,
        "vt_reports": vt_reports
    }

@app.post("/api/scan/file")
async def api_scan_file(file: UploadFile = File(...)):
    """
    Analyze uploaded file (.apk, .exe, .zip, .pdf) using VirusTotal v3 API.
    """
    filename = file.filename
    file_bytes = await file.read()
    file_ext = os.path.splitext(filename)[1].lower()

    vt_result = await vt_scanner.scan_file_hash(file_bytes, filename)
    status = vt_result.get("status", "SAFE")
    risk_score = 90 if status == "DANGEROUS" else (60 if status == "SUSPICIOUS" else 10)

    log_scan_event(
        chat_id="WEB_SIMULATOR",
        chat_type="web",
        sender_id="web_user",
        scan_type="FILE",
        input_summary=f"File: {filename} ({file_ext})",
        risk_level=status,
        risk_score=risk_score,
        threat_details={"filename": filename, "extension": file_ext, "description": DANGEROUS_EXTENSIONS.get(file_ext, "File")},
        virustotal_details=vt_result
    )

    return {
        "status": "success",
        "filename": filename,
        "extension": file_ext,
        "risk_level": status,
        "virustotal": vt_result
    }

@app.post("/api/webhook")
async def telegram_webhook(request: Request):
    """
    24/7 Telegram Serverless Cloud Webhook Endpoint hosted on Vercel.
    """
    tg_app = get_telegram_app()
    if not tg_app:
        return JSONResponse({"status": "disabled", "message": "Bot token not configured"}, status_code=200)
    
    try:
        data = await request.json()
        from telegram import Update
        update = Update.de_json(data, tg_app.bot)
        
        if not getattr(tg_app, "_initialized", False):
            await tg_app.initialize()

        await tg_app.process_update(update)
        return JSONResponse({"status": "ok"}, status_code=200)
    except Exception as e:
        logger.error(f"Error processing webhook update: {e}")
        return JSONResponse({"status": "ok", "error": str(e)}, status_code=200)

@app.get("/api/set_webhook")
async def api_set_webhook(url: Optional[str] = None):
    """
    Helper endpoint to register Vercel 24/7 Webhook URL with Telegram API.
    """
    tg_app = get_telegram_app()
    if not tg_app:
        return JSONResponse({"status": "disabled", "message": "Bot token not configured"}, status_code=500)
    
    target_url = url or "https://nssfscanfile.vercel.app/api/webhook"
    try:
        res = await tg_app.bot.set_webhook(url=target_url)
        return {"status": "success", "webhook_url": target_url, "result": res}
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)

if __name__ == "__main__":
    uvicorn.run("server:app", host=HOST, port=PORT, reload=True)
