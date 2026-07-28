import os
import uvicorn
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional

from config import HOST, PORT, DANGEROUS_EXTENSIONS
from ai_analyzer import AIThreatAnalyzer
from vt_scanner import VirusTotalScanner
from database import log_scan_event, get_recent_scans, get_soc_stats

app = FastAPI(title="Security SOC Scan API", version="1.0.0")

# Mount Static Files safely
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if not os.path.exists(static_dir):
    static_dir = os.path.join(os.getcwd(), "static")

if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

ai_analyzer = AIThreatAnalyzer()
vt_scanner = VirusTotalScanner()


class ScanTextRequest(BaseModel):
    text: str
    chat_type: Optional[str] = "web_simulator"

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """
    Serve main Web SOC Security Dashboard.
    """
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>Security SOC Scan API is Running. Index file initializing...</h1>")

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

if __name__ == "__main__":
    uvicorn.run("server:app", host=HOST, port=PORT, reload=True)
