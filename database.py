"""Scan-log storage: Supabase when configured, otherwise local SQLite.

All functions here are synchronous (blocking). Call the ``a*`` async wrappers
from async code so the event loop is not blocked.
"""
import asyncio
import hashlib
import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

from config import DB_PATH, RETENTION_DAYS, STORE_MESSAGE_TEXT, SUPABASE_KEY, SUPABASE_URL

logger = logging.getLogger(__name__)

supabase_client = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        from supabase import create_client

        supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
        logger.info("Supabase cloud client initialized.")
    except Exception as e:
        logger.error("Failed to initialize Supabase client: %s", e)

_init_lock = threading.Lock()
_initialized = False
CLOUD_IP_LABEL = "Telegram Cloud Gateway IP"


# --- SQLite ------------------------------------------------------------------
def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables once per process."""
    global _initialized
    if _initialized:
        return
    with _init_lock:
        if _initialized:
            return
        try:
            conn = _connect()
            conn.execute(
                """
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
                """
            )
            for col in ("user_name", "ip_address"):
                try:
                    conn.execute(f"ALTER TABLE scan_logs ADD COLUMN {col} TEXT DEFAULT ''")
                except sqlite3.OperationalError:
                    pass  # column already exists
            conn.commit()
            conn.close()
            _initialized = True
        except Exception as e:
            logger.warning("Could not initialize local SQLite database: %s", e)


# --- privacy -----------------------------------------------------------------
def make_summary(scan_type: str, text: str, threat_details: Dict[str, Any]) -> str:
    """Return what gets stored for the input. By default message text is NOT
    stored, only a short hash, its length and any link hostnames."""
    text = text or ""
    if scan_type == "FILE" or STORE_MESSAGE_TEXT:
        return text[:200]
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    hosts = []
    for u in (threat_details or {}).get("urls_found", [])[:3]:
        try:
            hosts.append(urlparse(u).hostname or "")
        except ValueError:
            continue
    suffix = f" links: {', '.join(h for h in hosts if h)}" if hosts else ""
    return f"[msg {digest}] {len(text)} chars{suffix}"


# --- write -------------------------------------------------------------------
def log_scan_event(
    chat_id,
    chat_type: str,
    sender_id,
    scan_type: str,
    input_summary: str,
    risk_level: str,
    risk_score: int,
    threat_details: Dict[str, Any],
    virustotal_details: Dict[str, Any] = None,
    user_name: str = "",
    ip_address: str = "",
) -> None:
    threat_details = threat_details or {}
    virustotal_details = virustotal_details or {}
    row = {
        "chat_id": str(chat_id),
        "chat_type": chat_type,
        "sender_id": str(sender_id or "web_user"),
        "user_name": user_name or "",
        "ip_address": ip_address or "",
        "scan_type": scan_type,
        "input_summary": make_summary(scan_type, input_summary, threat_details),
        "risk_level": risk_level,
        "risk_score": int(risk_score),
    }

    if supabase_client:
        try:
            supabase_client.table("scan_logs").insert(
                {**row, "threat_details": threat_details, "virustotal_details": virustotal_details}
            ).execute()
            return
        except Exception as e:
            logger.error("Supabase logging error, falling back to SQLite: %s", e)

    try:
        init_db()
        conn = _connect()
        conn.execute(
            """
            INSERT INTO scan_logs
            (chat_id, chat_type, sender_id, user_name, ip_address, scan_type,
             input_summary, risk_level, risk_score, threat_details, virustotal_details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["chat_id"], row["chat_type"], row["sender_id"], row["user_name"],
                row["ip_address"], row["scan_type"], row["input_summary"], row["risk_level"],
                row["risk_score"],
                json.dumps(threat_details, ensure_ascii=False),
                json.dumps(virustotal_details, ensure_ascii=False),
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("SQLite log_scan_event error: %s", e)


def purge_old_scans(days: int = RETENTION_DAYS) -> None:
    """Delete logs older than the retention period (0 = keep forever)."""
    if days <= 0:
        return
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    if supabase_client:
        try:
            supabase_client.table("scan_logs").delete().lt("created_at", cutoff.isoformat()).execute()
        except Exception as e:
            logger.error("Supabase purge error: %s", e)
    try:
        init_db()
        conn = _connect()
        conn.execute(
            "DELETE FROM scan_logs WHERE timestamp < ?", (cutoff.strftime("%Y-%m-%d %H:%M:%S"),)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning("SQLite purge error: %s", e)


# --- read --------------------------------------------------------------------
def _json_field(value) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        try:
            return json.loads(value)
        except ValueError:
            return {}
    return {}


def _normalize(r: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": r.get("id"),
        "timestamp": r.get("created_at") or r.get("timestamp", ""),
        "chat_id": r.get("chat_id"),
        "chat_type": r.get("chat_type"),
        "sender_id": r.get("sender_id") or "web_user",
        "user_name": r.get("user_name") or "",
        "ip_address": r.get("ip_address") or CLOUD_IP_LABEL,
        "scan_type": r.get("scan_type"),
        "input_summary": r.get("input_summary"),
        "risk_level": r.get("risk_level"),
        "risk_score": r.get("risk_score"),
        "threat_details": _json_field(r.get("threat_details")),
        "virustotal_details": _json_field(r.get("virustotal_details")),
    }


def get_recent_scans(limit: int = 50) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    if supabase_client:
        try:
            resp = supabase_client.table("scan_logs").select("*").order("id", desc=True).limit(limit).execute()
            return [_normalize(r) for r in (resp.data or [])]
        except Exception as e:
            logger.error("Supabase get_recent_scans error: %s", e)
    try:
        init_db()
        conn = _connect()
        rows = conn.execute("SELECT * FROM scan_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [_normalize(dict(r)) for r in rows]
    except Exception as e:
        logger.error("SQLite get_recent_scans error: %s", e)
        return []


def get_user_analytics() -> Dict[str, Any]:
    """Unique senders with scan counts (from the 1000 most recent scans)."""
    users: Dict[str, Dict[str, Any]] = {}
    for r in get_recent_scans(1000):
        sid = str(r["sender_id"])
        u = users.setdefault(
            sid,
            {
                "sender_id": sid,
                "ip_address": r["ip_address"],
                "chat_type": r["chat_type"] or "private",
                "scan_count": 0,
                "last_active": r["timestamp"],
            },
        )
        u["scan_count"] += 1
    user_list = list(users.values())
    return {"total_users": len(user_list), "users": user_list}


def get_soc_stats() -> Dict[str, Any]:
    scans = get_recent_scans(1000)
    count = lambda key, val: sum(1 for s in scans if s.get(key) == val)  # noqa: E731
    return {
        "total_scans": len(scans),
        "dangerous_count": count("risk_level", "DANGEROUS"),
        "suspicious_count": count("risk_level", "SUSPICIOUS"),
        "safe_count": count("risk_level", "SAFE"),
        "unknown_count": sum(1 for s in scans if s.get("risk_level") in ("UNKNOWN", "ANALYZING")),
        "file_scans": count("scan_type", "FILE"),
        "url_scans": count("scan_type", "URL"),
        "total_users": len({str(s["sender_id"]) for s in scans}),
        "protected_groups": len({s["chat_id"] for s in scans if s.get("chat_type") in ("group", "supergroup")}),
    }


# --- async wrappers (do not block the event loop) -------------------------------
async def alog_scan_event(*args, **kwargs) -> None:
    await asyncio.to_thread(log_scan_event, *args, **kwargs)


async def aget_soc_stats() -> Dict[str, Any]:
    return await asyncio.to_thread(get_soc_stats)


async def aget_recent_scans(limit: int = 50) -> List[Dict[str, Any]]:
    return await asyncio.to_thread(get_recent_scans, limit)


async def aget_user_analytics() -> Dict[str, Any]:
    return await asyncio.to_thread(get_user_analytics)


async def apurge_old_scans(days: int = RETENTION_DAYS) -> None:
    await asyncio.to_thread(purge_old_scans, days)


try:
    init_db()
except Exception:
    pass
