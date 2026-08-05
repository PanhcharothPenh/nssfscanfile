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


def cleanup_sample_data():
    if supabase_client:
        try:
            supabase_client.table("scan_logs").delete().in_("sender_id", ["890308072", "548910234", "712903841"]).execute()
        except Exception as e:
            pass

def init_db():
    """
    Initialize SQLite tables locally.
    """
    cleanup_sample_data()

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
                user_name TEXT DEFAULT '',
                ip_address TEXT DEFAULT '',
                scan_type TEXT,
                input_summary TEXT,
                risk_level TEXT,
                risk_score INTEGER,
                threat_details TEXT,
                virustotal_details TEXT
            )
        """)

        try:
            cursor.execute("ALTER TABLE scan_logs ADD COLUMN user_name TEXT DEFAULT ''")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE scan_logs ADD COLUMN ip_address TEXT DEFAULT ''")
        except Exception:
            pass

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
                   threat_details: Dict[str, Any], virustotal_details: Dict[str, Any] = None,
                   user_name: str = "", ip_address: str = ""):
    """
    Log a scan event into Supabase or SQLite with Telegram ID and IP tracking.
    """
    threat_json = json.dumps(threat_details or {}, ensure_ascii=False)
    vt_json = json.dumps(virustotal_details or {}, ensure_ascii=False)
    clean_ip = ip_address or "Telegram Cloud Gateway IP"
    clean_sender_id = str(sender_id or "web_user")

    if supabase_client:
        try:
            supabase_client.table("scan_logs").insert({
                "chat_id": str(chat_id),
                "chat_type": chat_type,
                "sender_id": clean_sender_id,
                "user_name": str(sender_id),
                "ip_address": clean_ip,
                "scan_type": scan_type,
                "input_summary": input_summary[:200],
                "risk_level": risk_level,
                "risk_score": risk_score,
                "threat_details": threat_json,
                "virustotal_details": vt_json
            }).execute()
        except Exception as e:
            logger.error(f"Supabase logging error: {e}")

    try:
        init_db()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_logs 
            (chat_id, chat_type, sender_id, user_name, ip_address, scan_type, input_summary, risk_level, risk_score, threat_details, virustotal_details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(chat_id),
            chat_type,
            clean_sender_id,
            str(sender_id),
            clean_ip,
            scan_type,
            input_summary[:200],
            risk_level,
            risk_score,
            threat_json,
            vt_json
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"SQLite log_scan_event error: {e}")


def get_recent_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieve recent real scan logs for Web Portal.
    """
    if supabase_client:
        try:
            response = supabase_client.table("scan_logs").select("*").order("id", desc=True).limit(limit).execute()
            if response.data:
                results = []
                for r in response.data:
                    results.append({
                        "id": r.get("id"),
                        "timestamp": r.get("created_at") or r.get("timestamp", ""),
                        "chat_id": r.get("chat_id"),
                        "chat_type": r.get("chat_type"),
                        "sender_id": r.get("sender_id") or "web_user",
                        "ip_address": r.get("ip_address") or "Telegram Cloud Gateway IP",
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

    try:
        init_db()
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_logs ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        
        results = []
        for r in rows:
            keys = r.keys()
            results.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "chat_id": r["chat_id"],
                "chat_type": r["chat_type"],
                "sender_id": r["sender_id"] or "web_user",
                "ip_address": r["ip_address"] if "ip_address" in keys and r["ip_address"] else "Telegram Cloud Gateway IP",
                "scan_type": r["scan_type"],
                "input_summary": r["input_summary"],
                "risk_level": r["risk_level"],
                "risk_score": r["risk_score"],
                "threat_details": json.loads(r["threat_details"]) if r["threat_details"] else {},
                "virustotal_details": json.loads(r["virustotal_details"]) if r["virustotal_details"] else {}
            })
        conn.close()
        return results
    except Exception as e:
        logger.error(f"SQLite get_recent_scans error: {e}")
        return []


def get_user_analytics() -> Dict[str, Any]:
    """
    Get unique active users telemetry by Telegram ID / Sender ID only.
    """
    if supabase_client:
        try:
            res = supabase_client.table("scan_logs").select("sender_id, ip_address, chat_type, created_at").order("id", desc=True).execute()
            data = res.data or []
            if data:
                users_map = {}
                for r in data:
                    sid = str(r.get("sender_id") or "Unknown")
                    if sid not in users_map:
                        users_map[sid] = {
                            "sender_id": sid,
                            "ip_address": r.get("ip_address") or "Telegram Cloud Gateway IP",
                            "chat_type": r.get("chat_type") or "private",
                            "scan_count": 0,
                            "last_active": r.get("created_at") or r.get("timestamp", "")
                        }
                    users_map[sid]["scan_count"] += 1

                user_list = list(users_map.values())
                return {
                    "total_users": len(user_list),
                    "users": user_list
                }
        except Exception as e:
            logger.error(f"Supabase get_user_analytics error: {e}")

    try:
        init_db()
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT sender_id, ip_address, chat_type, MAX(timestamp) as last_active, COUNT(*) as scan_count
            FROM scan_logs
            GROUP BY sender_id
            ORDER BY last_active DESC
        """)
        rows = cursor.fetchall()
        conn.close()

        user_list = []
        for r in rows:
            keys = r.keys()
            sid = str(r["sender_id"] or "Unknown")
            ip = r["ip_address"] if "ip_address" in keys and r["ip_address"] else "Telegram Cloud Gateway IP"
            user_list.append({
                "sender_id": sid,
                "ip_address": ip,
                "chat_type": r["chat_type"],
                "scan_count": r["scan_count"],
                "last_active": r["last_active"]
            })

        return {
            "total_users": len(user_list),
            "users": user_list
        }
    except Exception as e:
        logger.warning(f"Local get_user_analytics error: {e}")
        return {"total_users": 0, "users": []}


def get_soc_stats() -> Dict[str, Any]:
    """
    Fetch aggregated metrics for SOC Telemetry Dashboard.
    """
    user_analytics = get_user_analytics()
    total_users = user_analytics.get("total_users", 0)
    scans = get_recent_scans(1000)

    total_scans = len(scans)
    dangerous = sum(1 for s in scans if s.get("risk_level") == "DANGEROUS")
    suspicious = sum(1 for s in scans if s.get("risk_level") == "SUSPICIOUS")
    safe = sum(1 for s in scans if s.get("risk_level") == "SAFE")
    files = sum(1 for s in scans if s.get("scan_type") == "FILE")
    urls = sum(1 for s in scans if s.get("scan_type") == "URL")

    return {
        "total_scans": total_scans,
        "dangerous_count": dangerous,
        "suspicious_count": suspicious,
        "safe_count": safe,
        "file_scans": files,
        "url_scans": urls,
        "total_users": total_users,
        "protected_groups": 1
    }

try:
    init_db()
except Exception:
    pass
