"""NSSF Security Scan - Telegram bot (handlers shared by polling and webhook modes)."""
import html
import logging
import os
import re
from typing import List

from telegram import BotCommand, Message, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from ai_analyzer import AIThreatAnalyzer
from config import (
    ADMIN_TELEGRAM_IDS,
    DANGEROUS_EXTENSIONS,
    MAX_UPLOAD_BYTES,
    RETENTION_DAYS,
    STORE_MESSAGE_TEXT,
    TELEGRAM_BOT_TOKEN,
    USER_RATE_LIMIT_PER_MIN,
)
from database import alog_scan_event, aget_soc_stats, apurge_old_scans
from scan_service import (
    FOOTER,
    HASH_HELP,
    SCORES,
    UserRateLimiter,
    format_file_report,
    format_text_report,
    scan_text,
)
from vt_scanner import VirusTotalScanner

logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

ai_analyzer = AIThreatAnalyzer()
vt_scanner = VirusTotalScanner()
rate_limiter = UserRateLimiter(USER_RATE_LIMIT_PER_MIN)

HTML = ParseMode.HTML
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GROUP_TYPES = ("group", "supergroup")

WELCOME = (
    "🛡️ <b>NSSF Security Scan</b>\n\n"
    "ជួយការពារអ្នកពីការបោកប្រាស់តាមប្រព័ន្ធអ៊ីនធឺណិត។ គ្រាន់តែផ្ញើតំណភ្ជាប់ (Link) សារ ឬឯកសារដែលអ្នកសង្ស័យមកកាន់ Bot "
    "នោះវានឹងវិភាគរកហានិភ័យរួចផ្តល់ការណែនាំភ្លាមៗ។\n\n"
    "✨ <b>លក្ខណៈពិសេស៖</b>\n"
    "1️⃣ <b>វិភាគខ្លឹមសារសារ៖</b> ស្គាល់ភាសាគំរាមកំហែង ការក្លែងបន្លំធនាគារ និងការបង្ខំឱ្យផ្ទេរប្រាក់\n"
    "2️⃣ <b>ស្កេនតំណភ្ជាប់ &amp; ឯកសារ៖</b> តាមរយៈ VirusTotal (.apk, .exe, .zip, .7z, .pdf …)\n"
    "3️⃣ <b>ការពារ Group Chat៖</b> ទាញ Bot ចូល Group ដើម្បីព្រមានសមាជិកពេលមានសារ ឬឯកសារគ្រោះថ្នាក់\n\n"
    "🔍 <b>ពាក្យបញ្ជា៖</b>\n"
    "/scan &lt;អត្ថបទ ឬ តំណភ្ជាប់&gt; - ស្កេនដោយផ្ទាល់\n"
    "/report &lt;ពណ៌នា&gt; - រាយការណ៍លទ្ធផលខុស\n"
    "/privacy - ឯកជនភាព\n"
    "/help - មគ្គុទ្ទេសក៍\n\n"
    f"---\n{FOOTER}"
)

HELP = (
    "❓ <b>មគ្គុទ្ទេសក៍ប្រើប្រាស់</b>\n\n"
    "• <b>ផ្ញើសារ ឬតំណភ្ជាប់សង្ស័យ៖</b> Forward ឬចម្លងមកកាន់ Bot ដោយផ្ទាល់។\n"
    "• <b>ផ្ញើឯកសារ៖</b> ឯកសារទំហំក្រោម 20MB នឹងត្រូវស្កេនតាម VirusTotal។ "
    "ឯកសារធំជាង 20MB មិនអាចស្កេនផ្ទាល់បានទេ ប៉ុន្តែអាចផ្ញើ <code>/hash</code> (SHA-256 របស់ឯកសារ) ដើម្បីពិនិត្យ។\n"
    "• <b>Group Chat៖</b> Bot ព្រមានតែពេលរកឃើញសារ ឬឯកសារដែលគួរឱ្យសង្ស័យប៉ុណ្ណោះ។\n"
    "• <b>ចំណាំ៖</b> លទ្ធផល «មិនឃើញសញ្ញាគ្រោះថ្នាក់» មិនមែនជាការធានាថាសុវត្ថិភាព ១០០% ទេ។\n"
    "• <b>លទ្ធផលខុស?</b> ប្រើ /report ដើម្បីជូនដំណឹង។\n\n"
    f"---\n{FOOTER}"
)


def _privacy_text() -> str:
    stored = "អត្ថបទសារ (រហូតដល់ ២០០ តួអក្សរ)" if STORE_MESSAGE_TEXT else "តែ hash និងប្រវែងសារ (មិនរក្សាអត្ថបទសារ)"
    retention = f"{RETENTION_DAYS} ថ្ងៃ" if RETENTION_DAYS > 0 else "គ្មានកំណត់"
    return (
        "🔒 <b>ឯកជនភាព</b>\n\n"
        f"• Bot រក្សាទុក៖ ID អ្នកប្រើ ប្រភេទការស្កេន លទ្ធផល និង {stored}។\n"
        f"• ទិន្នន័យត្រូវលុបស្វ័យប្រវត្តិបន្ទាប់ពី {retention}។\n"
        "• តំណភ្ជាប់ និងឯកសារត្រូវបានបញ្ជូនទៅ VirusTotal ដើម្បីស្កេន។\n"
        "• មិនត្រូវផ្ញើពាក្យសម្ងាត់ ឬលេខកូដ OTP មកកាន់ Bot ឡើយ។"
    )


# --- helpers -------------------------------------------------------------------
def _user_name(msg: Message) -> str:
    u = msg.from_user
    if not u:
        return ""
    name = f"{u.first_name or ''} {u.last_name or ''}".strip()
    return f"{name} (@{u.username})".strip() if u.username else name


def _message_urls(msg: Message) -> List[str]:
    """URLs hidden in text-link entities or listed as url entities (text or caption)."""
    urls: List[str] = []
    entities = list(msg.entities or ()) + list(msg.caption_entities or ())
    for ent in entities:
        if ent.type == "text_link" and ent.url:
            urls.append(ent.url)
    return urls


def _strip_command(text: str) -> str:
    return re.sub(r"^/scan(@\w+)?\s*", "", text, flags=re.IGNORECASE).strip()


async def _too_fast(update: Update) -> bool:
    user_id = update.effective_user.id if update.effective_user else 0
    if rate_limiter.allow(user_id):
        return False
    if update.effective_chat and update.effective_chat.type == "private":
        await update.message.reply_text("⏳ សូមរង់ចាំបន្តិច រួចសាកល្បងម្តងទៀត (ស្កេនញឹកញាប់ពេក)។")
    return True


# --- commands ------------------------------------------------------------------
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    for name in ("welcome_banner.jpg", "profile_photo.jpg"):
        path = os.path.join(BASE_DIR, "static", "images", name)
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    await update.message.reply_photo(photo=f)
            except Exception as e:
                logger.warning("Could not send banner: %s", e)
            break
    await update.message.reply_text(WELCOME, parse_mode=HTML)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(HELP, parse_mode=HTML)


async def privacy_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(_privacy_text(), parse_mode=HTML)


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id if update.effective_user else 0
    if ADMIN_TELEGRAM_IDS and user_id not in ADMIN_TELEGRAM_IDS:
        await update.message.reply_text("⛔ ពាក្យបញ្ជានេះសម្រាប់អ្នកគ្រប់គ្រងប៉ុណ្ណោះ។")
        return
    s = await aget_soc_stats()
    await update.message.reply_text(
        "📊 <b>របាយការណ៍សុវត្ថិភាពប្រព័ន្ធ</b>\n\n"
        f"• ចំនួនស្កេនសរុប៖ {s['total_scans']}\n"
        f"• 🔴 គ្រោះថ្នាក់៖ {s['dangerous_count']}\n"
        f"• 🟡 សង្ស័យ៖ {s['suspicious_count']}\n"
        f"• 🟢 មិនឃើញហានិភ័យ៖ {s['safe_count']}\n"
        f"• ⚪ មិនអាចផ្ទៀងផ្ទាត់៖ {s['unknown_count']}\n"
        f"• 📁 ឯកសារ៖ {s['file_scans']}  🔗 តំណភ្ជាប់៖ {s['url_scans']}",
        parse_mode=HTML,
    )


async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/report <note> - user flags a wrong result (false positive / false negative)."""
    msg = update.message
    note = " ".join(context.args or []).strip()
    if not note and msg.reply_to_message:
        note = (msg.reply_to_message.text or msg.reply_to_message.caption or "")[:200]
    if not note:
        await msg.reply_text("សូមសរសេរ /report តាមដោយពណ៌នាបញ្ហា ឬ Reply លើសារដែលស្កេនខុស។")
        return
    await alog_scan_event(
        chat_id=msg.chat_id, chat_type=msg.chat.type, sender_id=msg.from_user.id if msg.from_user else 0,
        scan_type="FEEDBACK", input_summary=note, risk_level="FEEDBACK", risk_score=0,
        threat_details={}, user_name=_user_name(msg),
    )
    await msg.reply_text("🙏 អរគុណ! យើងបានទទួលរបាយការណ៍របស់អ្នកហើយ។")


# --- scanning handlers -----------------------------------------------------------
HASH_RE = re.compile(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}")


async def _hash_lookup(update: Update, digest: str):
    """Look a file hash up on VirusTotal (works for files of any size)."""
    msg = update.message
    if await _too_fast(update):
        return
    result = await vt_scanner.lookup_hash(digest)
    status = result.get("status", "UNKNOWN")
    await alog_scan_event(
        chat_id=msg.chat_id, chat_type=msg.chat.type, sender_id=msg.from_user.id if msg.from_user else 0,
        scan_type="FILE", input_summary=f"Hash: {digest.lower()}", risk_level=status,
        risk_score=SCORES.get(status, 0), threat_details={"hash": digest.lower()},
        virustotal_details=result, user_name=_user_name(msg),
    )
    await msg.reply_text(format_file_report(result.get("filename", digest), result),
                         parse_mode=HTML, disable_web_page_preview=True)


async def hash_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    arg = (context.args[0] if context.args else "").strip()
    if not HASH_RE.fullmatch(arg):
        await update.message.reply_text(
            "សូមសរសេរ <code>/hash</code> តាមដោយលេខ hash (SHA-256 / SHA-1 / MD5) របស់ឯកសារ។\n\n" + HASH_HELP,
            parse_mode=HTML,
        )
        return
    await _hash_lookup(update, arg)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Text, captions and /scan."""
    msg = update.message
    if not msg:
        return
    raw = msg.text or msg.caption or ""
    is_command = raw.lower().startswith("/scan")
    text = _strip_command(raw) if is_command else raw
    chat_type = msg.chat.type
    in_group = chat_type in GROUP_TYPES

    if HASH_RE.fullmatch(text.strip()):
        await _hash_lookup(update, text.strip())
        return

    if is_command and not text and not _message_urls(msg):
        await msg.reply_text(
            "🔍 <b>របៀបស្កេន៖</b> សរសេរ <code>/scan</code> តាមដោយសារ ឬតំណភ្ជាប់ "
            "ឬ Forward សារចូលក្នុង Chat។",
            parse_mode=HTML,
        )
        return
    if not text and not _message_urls(msg):
        return
    if await _too_fast(update):
        return

    ai_report, vt_reports, level = await scan_text(ai_analyzer, vt_scanner, text, _message_urls(msg))

    sender_id = msg.from_user.id if msg.from_user else 0
    await alog_scan_event(
        chat_id=msg.chat_id, chat_type=chat_type, sender_id=sender_id,
        scan_type="URL" if ai_report.get("urls_found") else "TEXT",
        input_summary=text, risk_level=level, risk_score=ai_report["risk_score"],
        threat_details=ai_report, virustotal_details=vt_reports[0] if vt_reports else {},
        user_name=_user_name(msg),
    )

    # Groups: stay quiet unless something is wrong (or someone used /scan).
    if in_group and not is_command and level not in ("DANGEROUS", "SUSPICIOUS"):
        return
    await msg.reply_text(format_text_report(ai_report, vt_reports), parse_mode=HTML,
                         disable_web_page_preview=True)


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    if not msg or not msg.document:
        return
    if await _too_fast(update):
        return

    doc = msg.document
    filename = doc.file_name or "unknown_file"
    size = doc.file_size or 0
    ext = os.path.splitext(filename)[1].lower()
    chat_type = msg.chat.type
    in_group = chat_type in GROUP_TYPES
    size_mb = round(size / (1024 * 1024), 2)

    progress = None
    if not in_group:
        progress = await msg.reply_text(
            f"🔍 កំពុងស្កេនឯកសារ៖ <code>{html.escape(filename)}</code> ({size_mb} MB)…", parse_mode=HTML
        )

    try:
        if size > MAX_UPLOAD_BYTES:
            result = vt_scanner.file_too_large_result(filename, size)
        else:
            tg_file = await context.bot.get_file(doc.file_id)
            data = bytes(await tg_file.download_as_bytearray())
            result = await vt_scanner.scan_file_hash(data, filename)
    except Exception as e:
        logger.error("Error scanning file %s: %s", filename, e)
        result = VirusTotalScanner._unknown(
            "Scan failed because of an internal error. The file was NOT scanned.",
            filename=filename, **VirusTotalScanner._type_hint(ext),
        )

    status = result.get("status", "UNKNOWN")
    await alog_scan_event(
        chat_id=msg.chat_id, chat_type=chat_type, sender_id=msg.from_user.id if msg.from_user else 0,
        scan_type="FILE", input_summary=f"File: {filename} ({ext}, {size_mb}MB)",
        risk_level=status, risk_score=SCORES.get(status, 0),
        threat_details={"filename": filename, "extension": ext, "file_size": size,
                        "description": DANGEROUS_EXTENSIONS.get(ext, "File")},
        virustotal_details=result, user_name=_user_name(msg),
    )

    # In groups only speak up for bad/unverified risky files.
    if in_group and status == "SAFE":
        return
    if in_group and status in ("UNKNOWN", "ANALYZING") and not result.get("high_risk_file_type"):
        return
    report = format_file_report(filename, result)
    if progress:
        await progress.edit_text(report, parse_mode=HTML, disable_web_page_preview=True)
    else:
        await msg.reply_text(report, parse_mode=HTML, disable_web_page_preview=True)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Unhandled error while processing update: %s", context.error, exc_info=context.error)


# --- application -----------------------------------------------------------------
async def _daily_purge(context: ContextTypes.DEFAULT_TYPE):
    await apurge_old_scans()


async def post_init(app: Application):
    try:
        await app.bot.set_my_description(
            "🛡️ NSSF Security Scan\nផ្ញើតំណភ្ជាប់ សារ ឬឯកសារសង្ស័យមកកាន់ Bot ដើម្បីពិនិត្យការបោកប្រាស់ និងមេរោគ។ ចុច START ដើម្បីចាប់ផ្តើម។"
        )
        await app.bot.set_my_short_description("🔒 ស្កេន និងការពារសារ តំណភ្ជាប់ ឯកសារបោកប្រាស់")
        await app.bot.set_my_commands([
            BotCommand("scan", "🔍 ស្កេនសារ ឬតំណភ្ជាប់សង្ស័យ"),
            BotCommand("hash", "🔑 ពិនិត្យឯកសារធំតាម hash"),
            BotCommand("report", "📝 រាយការណ៍លទ្ធផលខុស"),
            BotCommand("privacy", "🔒 ឯកជនភាព"),
            BotCommand("help", "❓ មគ្គុទ្ទេសក៍"),
            BotCommand("start", "🚀 ចាប់ផ្តើម"),
        ])
    except Exception as e:
        logger.error("Error setting bot profile: %s", e)
    await apurge_old_scans()


def register_handlers(app: Application) -> Application:
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("privacy", privacy_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("report", report_command))
    app.add_handler(CommandHandler("scan", handle_message))
    app.add_handler(CommandHandler("hash", hash_command))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler((filters.TEXT | filters.CAPTION) & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)
    return app


def build_application(with_post_init: bool = True) -> Application:
    builder = Application.builder().token(TELEGRAM_BOT_TOKEN)
    if with_post_init:
        builder = builder.post_init(post_init)
    app = builder.build()
    if app.job_queue is not None:
        app.job_queue.run_repeating(_daily_purge, interval=24 * 3600, first=3600)
    return register_handlers(app)


def main():
    if not TELEGRAM_BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN is not configured. Bot disabled.")
        return
    logger.info("Telegram Security Bot is starting (polling)...")
    build_application().run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
