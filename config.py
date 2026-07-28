import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

if os.getenv("VERCEL"):
    DB_PATH = "/tmp/soc_scan.db"
else:
    DB_PATH = os.getenv("DB_PATH", str(BASE_DIR / "soc_scan.db"))


TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Supabase Credentials (For Vercel / Cloud Database Deployment)
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))


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
    ".xlsm": "Excel Macro-Enabled Document"
}


# Known Scam Keywords in Khmer and English for pattern matching fallback
SCAM_KEYWORDS_KHMER = [
    "ផ្ទេរប្រាក់", "គំរាម", "បិទគណនី", "ធនាគារ ABA", "ធនាគារ អេស៊ីលីដា", "វីង", "សូម្បីតែ", 
    "ឈ្នះរង្វាន់", "បញ្ចូលលុយ", "ផ្ទៀងផ្ទាត់លេខកូដ", "OTP", "ប្រញាប់", "បន្ទាន់", "បាត់បង់ប្រាក់",
    "ពិន័យ", "តុលាការ", "ប៉ូលីស", "ដកប្រាក់", "វិនិយោគ", "ចំណេញច្រើន"
]

SCAM_KEYWORDS_ENGLISH = [
    "urgent", "bank", "account suspended", "verify account", "aba bank", "acleda", "wing bank",
    "lottery winner", "claim reward", "transfer money", "otp code", "security breach",
    "police", "court penalty", "crypto investment", "guaranteed profit", "telegram support"
]
