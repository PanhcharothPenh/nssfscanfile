import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, Any, List
from config import DB_PATH, SUPABASE_URL, SUPABASE_KEY

logger = logging.getLogger(__name__)

supabase_client = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        from supabase import create_client, Client
        supabase_client: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
        logger.info("Supabase cloud client initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize Supabase client: {e}")

def init_db():
    """
    Initialize SQLite tables locally (if not using Supabase).
    """
    if supabase_client:
        return

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                chat_id TEXT,
                chat_type TEXT,
                sender_id TEXT,
                scan_type TEXT,
                input_summary TEXT,
                risk_level TEXT,
                risk_score INTEGER,
                threat_details TEXT,
                virustotal_details TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS group_settings (
                chat_id TEXT PRIMARY KEY,
                chat_title TEXT,
                auto_scan_enabled INTEGER DEFAULT 1,
                block_dangerous_files INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Could not initialize local SQLite database: {e}")


def log_scan_event(chat_id: str, chat_type: str, sender_id: str, scan_type: str, 
                   input_summary: str, risk_level: str, risk_score: int, 
                   threat_details: Dict[str, Any], virustotal_details: Dict[str, Any] = None):
    """
    Log a scan event into Supabase or SQLite.
    """
    threat_json = json.dumps(threat_details or {}, ensure_ascii=False)
    vt_json = json.dumps(virustotal_details or {}, ensure_ascii=False)

    if supabase_client:
        try:
            supabase_client.table("scan_logs").insert({
                "chat_id": str(chat_id),
                "chat_type": chat_type,
                "sender_id": str(sender_id),
                "scan_type": scan_type,
                "input_summary": input_summary[:200],
                "risk_level": risk_level,
                "risk_score": risk_score,
                "threat_details": threat_json,
                "virustotal_details": vt_json
            }).execute()
            return
        except Exception as e:
            logger.error(f"Supabase logging error: {e}")

    # Fallback to local SQLite
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_logs 
        (chat_id, chat_type, sender_id, scan_type, input_summary, risk_level, risk_score, threat_details, virustotal_details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        str(chat_id),
        chat_type,
        str(sender_id),
        scan_type,
        input_summary[:200],
        risk_level,
        risk_score,
        threat_json,
        vt_json
    ))
    conn.commit()
    conn.close()

def get_recent_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieve recent scan logs.
    """
    if supabase_client:
        try:
            response = supabase_client.table("scan_logs").select("*").order("id", desc=True).limit(limit).execute()
            results = []
            for r in response.data:
                results.append({
                    "id": r.get("id"),
                    "timestamp": r.get("created_at") or r.get("timestamp", ""),
                    "chat_id": r.get("chat_id"),
                    "chat_type": r.get("chat_type"),
                    "sender_id": r.get("sender_id"),
                    "scan_type": r.get("scan_type"),
                    "input_summary": r.get("input_summary"),
                    "risk_level": r.get("risk_level"),
                    "risk_score": r.get("risk_score"),
                    "threat_details": json.loads(r["threat_details"]) if isinstance(r.get("threat_details"), str) else (r.get("threat_details") or {}),
                    "virustotal_details": json.loads(r["virustotal_details"]) if isinstance(r.get("virustotal_details"), str) else (r.get("virustotal_details") or {})
                })
            return results
        except Exception as e:
            logger.error(f"Supabase get_recent_scans error: {e}")

    # Fallback to SQLite
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "chat_id": r["chat_id"],
            "chat_type": r["chat_type"],
            "sender_id": r["sender_id"],
            "scan_type": r["scan_type"],
            "input_summary": r["input_summary"],
            "risk_level": r["risk_level"],
            "risk_score": r["risk_score"],
            "threat_details": json.loads(r["threat_details"]) if r["threat_details"] else {},
            "virustotal_details": json.loads(r["virustotal_details"]) if r["virustotal_details"] else {}
        })
    conn.close()
    return results

def get_soc_stats() -> Dict[str, Any]:
    """
    Get aggregated statistics for SOC Dashboard counters.
    """
    if supabase_client:
        try:
            # Quick count from Supabase
            res = supabase_client.table("scan_logs").select("risk_level, scan_type", count="exact").execute()
            data = res.data or []
            total = res.count or len(data)
            dangerous = sum(1 for d in data if d.get("risk_level") == "DANGEROUS")
            suspicious = sum(1 for d in data if d.get("risk_level") == "SUSPICIOUS")
            safe = sum(1 for d in data if d.get("risk_level") == "SAFE")
            file_scans = sum(1 for d in data if d.get("scan_type") == "FILE")
            url_scans = sum(1 for d in data if d.get("scan_type") == "URL")

            return {
                "total_scans": total,
                "dangerous_count": dangerous,
                "suspicious_count": suspicious,
                "safe_count": safe,
                "file_scans": file_scans,
                "url_scans": url_scans,
                "protected_groups": 1
            }
        except Exception as e:
            logger.error(f"Supabase get_soc_stats error: {e}")

    # Fallback to SQLite
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scan_logs")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE risk_level = 'DANGEROUS'")
    dangerous_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE risk_level = 'SUSPICIOUS'")
    suspicious_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE risk_level = 'SAFE'")
    safe_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE scan_type = 'FILE'")
    file_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE scan_type = 'URL'")
    url_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM group_settings")
    protected_groups = cursor.fetchone()[0]

    conn.close()

    return {
        "total_scans": total_scans,
        "dangerous_count": dangerous_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "file_scans": file_scans,
        "url_scans": url_scans,
        "protected_groups": protected_groups
    }

# Initialize tables on load
init_db()
