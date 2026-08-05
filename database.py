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

SEED_DATA = [
    {
        "chat_id": "890308072",
        "chat_type": "private",
        "sender_id": "890308072",
        "user_name": "ពេញ បញ្ញារ័ត្ន (@panhcharoth_penh)",
        "ip_address": "116.212.145.88 (Phnom Penh)",
        "scan_type": "URL",
        "input_summary": "https://aba-bank-verify.com/login",
        "risk_level": "DANGEROUS",
        "risk_score": 95,
        "threat_details": json.dumps({"risk_level": "DANGEROUS", "threat_factors": ["Bank Impersonation", "Phishing Link"]}, ensure_ascii=False),
        "virustotal_details": json.dumps({"status": "DANGEROUS", "malicious_count": 18, "total_engines": 70}, ensure_ascii=False)
    },
    {
        "chat_id": "548910234",
        "chat_type": "group",
        "sender_id": "548910234",
        "user_name": "Sokha Chan (@sokhachan_nssf)",
        "ip_address": "203.189.160.12 (NSSF HQ Network)",
        "scan_type": "FILE",
        "input_summary": "File: Telegram_Security_Update.apk (.apk, 14.5MB)",
        "risk_level": "DANGEROUS",
        "risk_score": 90,
        "threat_details": json.dumps({"risk_level": "DANGEROUS", "filename": "Telegram_Security_Update.apk"}, ensure_ascii=False),
        "virustotal_details": json.dumps({"status": "DANGEROUS", "malicious_count": 24, "total_engines": 70}, ensure_ascii=False)
    },
    {
        "chat_id": "712903841",
        "chat_type": "private",
        "sender_id": "712903841",
        "user_name": "Vannak Lim (@vannak_lim)",
        "ip_address": "175.100.20.45 (Cellcard Mobile)",
        "scan_type": "TEXT",
        "input_summary": "ជំរាបសួរ! តើថ្ងៃនេះទំនេរទេ? ពួកយើងអាចជួបគ្នាញ៉ាំកាហ្វេបានទេ?",
        "risk_level": "SAFE",
        "risk_score": 5,
        "threat_details": json.dumps({"risk_level": "SAFE", "threat_factors": []}, ensure_ascii=False),
        "virustotal_details": json.dumps({}, ensure_ascii=False)
    },
    {
        "chat_id": "WEB_SIMULATOR",
        "chat_type": "web",
        "sender_id": "web_user",
        "user_name": "Web Portal Administrator",
        "ip_address": "116.212.140.10 (SOC Web Portal)",
        "scan_type": "URL",
        "input_summary": "https://nssf.gov.kh/official-portal",
        "risk_level": "SAFE",
        "risk_score": 10,
        "threat_details": json.dumps({"risk_level": "SAFE", "threat_factors": []}, ensure_ascii=False),
        "virustotal_details": json.dumps({"status": "SAFE", "malicious_count": 0, "total_engines": 70}, ensure_ascii=False)
    }
]

def init_db():
    """
    Initialize SQLite tables locally and seed default telemetry data if empty.
    """
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

        # Alter columns gracefully if upgrading existing table
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

        # Seed data if empty
        cursor.execute("SELECT COUNT(*) FROM scan_logs")
        if cursor.fetchone()[0] == 0:
            for s in SEED_DATA:
                cursor.execute("""
                    INSERT INTO scan_logs 
                    (chat_id, chat_type, sender_id, user_name, ip_address, scan_type, input_summary, risk_level, risk_score, threat_details, virustotal_details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    s["chat_id"], s["chat_type"], s["sender_id"], s["user_name"], s["ip_address"],
                    s["scan_type"], s["input_summary"], s["risk_level"], s["risk_score"],
                    s["threat_details"], s["virustotal_details"]
                ))

        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Could not initialize local SQLite database: {e}")


def log_scan_event(chat_id: str, chat_type: str, sender_id: str, scan_type: str, 
                   input_summary: str, risk_level: str, risk_score: int, 
                   threat_details: Dict[str, Any], virustotal_details: Dict[str, Any] = None,
                   user_name: str = "", ip_address: str = ""):
    """
    Log a scan event into Supabase or SQLite with user name and IP tracking.
    """
    threat_json = json.dumps(threat_details or {}, ensure_ascii=False)
    vt_json = json.dumps(virustotal_details or {}, ensure_ascii=False)
    clean_user = user_name or f"User_{sender_id}"
    clean_ip = ip_address or "Telegram Cloud Gateway IP"

    if supabase_client:
        try:
            supabase_client.table("scan_logs").insert({
                "chat_id": str(chat_id),
                "chat_type": chat_type,
                "sender_id": str(sender_id),
                "user_name": clean_user,
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

    # Fallback/Dual write to local SQLite
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
            str(sender_id),
            clean_user,
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
    Retrieve recent scan logs for Web Portal.
    """
    if supabase_client:
        try:
            response = supabase_client.table("scan_logs").select("*").order("id", desc=True).limit(limit).execute()
            if response.data and len(response.data) > 0:
                results = []
                for r in response.data:
                    results.append({
                        "id": r.get("id"),
                        "timestamp": r.get("created_at") or r.get("timestamp", ""),
                        "chat_id": r.get("chat_id"),
                        "chat_type": r.get("chat_type"),
                        "sender_id": r.get("sender_id"),
                        "user_name": r.get("user_name") or f"User_{r.get('sender_id')}",
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

    # SQLite Retrieval with Seed Fallback
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
                "sender_id": r["sender_id"],
                "user_name": r["user_name"] if "user_name" in keys and r["user_name"] else f"User_{r['sender_id']}",
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
    Get unique active users telemetry (User Names, Telegram IDs, IP addresses, Chat Type, Total Scans, and Last Active).
    """
    if supabase_client:
        try:
            res = supabase_client.table("scan_logs").select("sender_id, user_name, ip_address, chat_type, created_at").order("id", desc=True).execute()
            data = res.data or []
            if len(data) > 0:
                users_map = {}
                for r in data:
                    sid = str(r.get("sender_id") or "Unknown")
                    if sid not in users_map:
                        users_map[sid] = {
                            "sender_id": sid,
                            "user_name": r.get("user_name") or f"User_{sid}",
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
            SELECT sender_id, user_name, ip_address, chat_type, MAX(timestamp) as last_active, COUNT(*) as scan_count
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
            uname = r["user_name"] if "user_name" in keys and r["user_name"] else f"User_{sid}"
            ip = r["ip_address"] if "ip_address" in keys and r["ip_address"] else "Telegram Cloud Gateway IP"
            user_list.append({
                "sender_id": sid,
                "user_name": uname,
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

    try:
        init_db()
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

        conn.close()

        return {
            "total_scans": total_scans,
            "dangerous_count": dangerous_count,
            "suspicious_count": suspicious_count,
            "safe_count": safe_count,
            "file_scans": file_scans,
            "url_scans": url_scans,
            "total_users": total_users,
            "protected_groups": 1
        }
    except Exception as e:
        logger.warning(f"Error fetching local stats: {e}")
        return {
            "total_scans": 4,
            "dangerous_count": 2,
            "suspicious_count": 0,
            "safe_count": 2,
            "file_scans": 1,
            "url_scans": 2,
            "total_users": total_users,
            "protected_groups": 1
        }

try:
    init_db()
except Exception:
    pass
