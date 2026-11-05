import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


if os.getenv("VERCEL") or os.getenv("VERCEL_ENV") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
    DB_PATH = "/tmp/soc_scan.db"
else:
    try:
        if not os.access(str(BASE_DIR), os.W_OK):
            DB_PATH = "/tmp/soc_scan.db"
        else:
            DB_PATH = os.getenv("DB_PATH", str(BASE_DIR / "soc_scan.db"))
    except Exception:
        DB_PATH = "/tmp/soc_scan.db"

# --- Credentials -----------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Supabase: use the SERVICE ROLE key on the server (never the anon key) and
# enable row-level security on scan_logs so the anon key cannot read it.
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_KEY", "")

# --- Web / API security ----------------------------------------------------
# Required to use the dashboard API. If empty, protected endpoints are disabled.
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
# Random string you also pass to Telegram setWebhook(secret_token=...)
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
# Public base URL of the deployment (used by /api/set_webhook)
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

HOST = os.getenv("HOST", "0.0.0.0")
PORT = _int_env("PORT", 8000)

# --- Limits ----------------------------------------------------------------
MAX_UPLOAD_BYTES = _int_env("MAX_UPLOAD_BYTES", 20 * 1024 * 1024)   # Telegram bot download limit
MAX_URLS_PER_MESSAGE = _int_env("MAX_URLS_PER_MESSAGE", 5)
USER_RATE_LIMIT_PER_MIN = _int_env("USER_RATE_LIMIT_PER_MIN", 6)
VT_REQUESTS_PER_MIN = _int_env("VT_REQUESTS_PER_MIN", 4)            # VT free tier
VT_TIMEOUT_SECONDS = _int_env("VT_TIMEOUT_SECONDS", 15)
VT_POLL_SECONDS = _int_env("VT_POLL_SECONDS", 30)                   # max wait for a fresh analysis
CACHE_TTL_SECONDS = _int_env("CACHE_TTL_SECONDS", 3600)
CACHE_MAX_ITEMS = _int_env("CACHE_MAX_ITEMS", 2000)

# --- Privacy ---------------------------------------------------------------
# "full" stores the message (first 200 chars); "hash" stores only a SHA-256 + length.
STORE_MESSAGE_TEXT = os.getenv("STORE_MESSAGE_TEXT", "hash").lower() == "full"
RETENTION_DAYS = _int_env("RETENTION_DAYS", 30)
# Comma-separated Telegram user IDs allowed to run /status. Empty = everyone.
ADMIN_TELEGRAM_IDS = {
    int(x) for x in os.getenv("ADMIN_TELEGRAM_IDS", "").split(",") if x.strip().isdigit()
}


# Dangerous extension list commonly targeted by Telegram malware campaigns
DANGEROUS_EXTENSIONS = {
    ".apk": "Android Application Package (High Malware Risk on Telegram)",
    ".exe": "Windows Executable File",
    ".zip": "Compressed Zip Archive (May contain hidden malware)",
    ".7z": "7-Zip Compressed Archive (May hide malicious binaries)",
    ".z": "Unix Z Compressed Archive",
    ".rar": "WinRAR Compressed Archive",
    ".tar": "Tape Archive File",
    ".gz": "Gzip Compressed Archive",
    ".iso": "Disk Image File (Commonly used to bypass Windows Mark-of-the-Web)",
    ".img": "Disk Image File",
    ".pdf": "PDF Document (May contain malicious embedded links/scripts)",
    ".msi": "Windows Installer Package",
    ".dll": "Dynamic Link Library Binary",
    ".bat": "Batch Script File",
    ".cmd": "Command Script File",
    ".ps1": "PowerShell Script File",
    ".scr": "Screen Saver Executable (Common Ransomware)",
    ".vbs": "Visual Basic Script File",
    ".js": "JavaScript File",
    ".jar": "Java Executable Archive",
    ".docm": "Word Macro-Enabled Document",
    ".xlsm": "Excel Macro-Enabled Document",
}

# Extensions that are executable/installable: shown as "risky type" when unverified.
HIGH_RISK_EXTENSIONS = {".apk", ".exe", ".msi", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".dll", ".jar"}
