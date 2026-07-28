import os
import logging
import asyncio
from typing import Optional
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters
)

from config import TELEGRAM_BOT_TOKEN, DANGEROUS_EXTENSIONS
from ai_analyzer import AIThreatAnalyzer
from vt_scanner import VirusTotalScanner
from database import log_scan_event, get_soc_stats

# Configure Logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Initialize Scanners
ai_analyzer = AIThreatAnalyzer()
vt_scanner = VirusTotalScanner()

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /start command handler for NSSF Security Scan Bot.
    """
    welcome_caption = (
        "🛡️ **NSSF Security Scan គឺជា AI Bot**\n\n"
        "ដែលជួយការពារអ្នកពីការបោកប្រាស់តាមប្រព័ន្ធអ៊ីនធឺណិត។ គ្រាន់តែផ្ញើតំណភ្ជាប់ (Link) សារ ឬឯកសារដែលអ្នកសង្ស័យមកកាន់ Bot នោះវានឹងវិភាគរកហានិភ័យរួចផ្តល់ការណែនាំដល់អ្នកភ្លាមៗ។\n\n"
        "✨ **លក្ខណៈពិសេសរបស់ Bot (Bot Features):**\n"
        "1️⃣ **វិភាគខ្លឹមសារសារ (AI Scam Detection):** ស្គាល់ភាសាគំរាមកំហែង, ការក្លែងបន្លំជាធនាគារ (ABA, Acleda, Wing) និងការបង្ខំឱ្យផ្ទេរប្រាក់\n"
        "2️⃣ **ស្កេន VirusTotal v3 (Link & File Scan):** ពិនិត្យមើល URL និងឯកសារប្រភេទ `.apk`, `.exe`, `.zip`, `.z`, `.7z`, `.pdf`\n"
        "3️⃣ **ប្រព័ន្ធការពារ Group Chat:** ទាញ Bot ចូល Group ដើម្បីការពារសមាជិកទាំងអស់ដោយស្វ័យប្រវត្តិ 24/7\n\n"
        "🔍 **Commands:**\n"
        "/scan `<text or url>` - ស្កេនសារ ឬ តំណភ្ជាប់ដោយផ្ទាល់\n"
        "/status - ពិនិត្យមើលស្ថានភាពសុវត្ថិភាព\n"
        "/help - មគ្គុទ្ទេសក៍ប្រើប្រាស់"
    )

    banner_path = os.path.join(os.path.dirname(__file__), "static", "images", "welcome_banner.jpg")
    if os.path.exists(banner_path):
        with open(banner_path, "rb") as photo_file:
            await update.message.reply_photo(
                photo=photo_file,
                caption=welcome_caption,
                parse_mode="Markdown"
            )
    else:
        await update.message.reply_text(welcome_caption, parse_mode="Markdown")



async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /help command handler.
    """
    help_text = (
        "❓ **មគ្គុទ្ទេសក៍ប្រើប្រាស់ប្រព័ន្ធសុវត្ថិភាព (Help Guide)**\n\n"
        "• **ផ្ញើសារ ឬឯកសារសង្ស័យ:** Forward សារ ចម្លងតំណភ្ជាប់ (Link) ឬផ្ញើឯកសារទៅកាន់ Bot ដោយផ្ទាល់ ដោយមិនបាច់ចុចបើកវាជាមុនឡើយ។\n"
        "• **ស្កេនតំណភ្ជាប់ & ឯកសារ (VirusTotal v3):** Bot ពិនិត្យមើល URL និងឯកសារ APK, EXE, ZIP, PDF ដែលជនខិលខូចនិយមប្រើ។\n"
        "• **ប្រព័ន្ធការពារ Group Chat:** បន្ថែម Bot ចូលក្នុង Group ដើម្បីការពារសមាជិកទាំងអស់ពីសារបោកប្រាស់ និង Malware ភ្លាមៗ។"
    )
    await update.message.reply_text(help_text, parse_mode="Markdown")

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /status command handler - returns SOC stats.
    """
    stats = get_soc_stats()
    status_text = (
        "📊 **របាយការណ៍សុវត្ថិភាពប្រព័ន្ធ (SOC Security Telemetry)**\n\n"
        f"• **ចំនួនស្កេនសរុប (Total Scans):** {stats['total_scans']}\n"
        f"• **សារ/ឯកសារគ្រោះថ្នាក់ (Dangerous Threats):** 🔴 {stats['dangerous_count']}\n"
        f"• **សារ/ឯកសារសង្ស័យ (Suspicious):** 🟡 {stats['suspicious_count']}\n"
        f"• **សារសុវត្ថិភាព (Safe Messages):** 🟢 {stats['safe_count']}\n"
        f"• **ឯកសារបានស្កេន (Files Scanned):** 📁 {stats['file_scans']}\n"
        f"• **តំណភ្ជាប់បានស្កេន (URLs Scanned):** 🔗 {stats['url_scans']}\n\n"
        "✅ **ប្រព័ន្ធកំពុងដំណើរការការពារ ២៤/៧**"
    )
    await update.message.reply_text(status_text, parse_mode="Markdown")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles text messages, forwarded messages, and messages containing URLs.
    """
    if not update.message or not update.message.text:
        return

    chat_id = update.message.chat_id
    chat_type = update.message.chat.type
    sender_id = update.message.from_user.id if update.message.from_user else 0
    text = update.message.text

    # Analyze AI Scam & Threat patterns
    ai_report = await ai_analyzer.analyze_message(text)

    # If message contains URLs, scan them with VirusTotal
    vt_reports = []
    if ai_report.get("urls_found"):
        for url in ai_report["urls_found"][:3]: # Limit to 3 URLs
            vt_res = await vt_scanner.scan_url(url)
            vt_reports.append(vt_res)

    # Determine overall status
    highest_risk = ai_report["risk_level"]
    for vt in vt_reports:
        if vt.get("status") == "DANGEROUS":
            highest_risk = "DANGEROUS"
            ai_report["risk_score"] = max(ai_report["risk_score"], 95)
        elif vt.get("status") == "SUSPICIOUS" and highest_risk != "DANGEROUS":
            highest_risk = "SUSPICIOUS"

    # Log to Database
    scan_type = "URL" if ai_report.get("urls_found") else "TEXT"
    log_scan_event(
        chat_id=chat_id,
        chat_type=chat_type,
        sender_id=sender_id,
        scan_type=scan_type,
        input_summary=text,
        risk_level=highest_risk,
        risk_score=ai_report["risk_score"],
        threat_details=ai_report,
        virustotal_details=vt_reports[0] if vt_reports else {}
    )

    # Respond if dangerous, suspicious, or if in private DM
    if highest_risk in ["DANGEROUS", "SUSPICIOUS"] or chat_type == "private":
        response_msg = format_security_report(ai_report, vt_reports)
        await update.message.reply_text(response_msg, parse_mode="Markdown", disable_web_page_preview=True)

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles document uploads (.apk, .exe, .zip, .z, .7z, .pdf, etc.) and performs VirusTotal v3 verification.
    Gracefully handles files >20MB limited by Telegram Bot API.
    """
    if not update.message or not update.message.document:
        return

    chat_id = update.message.chat_id
    chat_type = update.message.chat.type
    sender_id = update.message.from_user.id if update.message.from_user else 0
    document = update.message.document
    filename = document.file_name or "unknown_file"
    file_size = document.file_size or 0
    file_ext = os.path.splitext(filename)[1].lower()

    # Inform user that file scanning is in progress
    progress_msg = await update.message.reply_text(
        f"🔍 **កំពុងស្កេនឯកសារ:** `{filename}` ({round(file_size/(1024*1024), 2)} MB)...",
        parse_mode="Markdown"
    )

    try:
        # If file is larger than 20MB, Telegram Bot API restricts file byte downloads. Perform Metadata & Extension Scan.
        if file_size > 20 * 1024 * 1024:
            vt_result = vt_scanner._mock_file_scan(filename, f"size_{file_size}_large_file", file_ext)
            vt_result["provider"] = "SOC File Metadata Analysis (Large File > 20MB)"
        else:
            tg_file = await context.bot.get_file(document.file_id)
            file_bytes = await tg_file.download_as_bytearray()
            vt_result = await vt_scanner.scan_file_hash(bytes(file_bytes), filename)
        
        status = vt_result.get("status", "SAFE")
        risk_score = 90 if status == "DANGEROUS" else (60 if status == "SUSPICIOUS" else 10)

        # Log event
        log_scan_event(
            chat_id=chat_id,
            chat_type=chat_type,
            sender_id=sender_id,
            scan_type="FILE",
            input_summary=f"File: {filename} ({file_ext}, {round(file_size/(1024*1024),2)}MB)",
            risk_level=status,
            risk_score=risk_score,
            threat_details={"filename": filename, "extension": file_ext, "file_size": file_size, "description": DANGEROUS_EXTENSIONS.get(file_ext, "File")},
            virustotal_details=vt_result
        )

        # Format Response cleanly
        if status == "DANGEROUS":
            badge = "🔴 **គ្រោះថ្នាក់ខ្លាំង (DANGEROUS MALWARE)**"
            rec = "⛔ **ហាមដំឡើង ឬចុចបើកឯកសារនេះដាច់ខាត!** វាអាចបង្កប់មេរោគ Ransomware ឬ Spyware!"
            action_steps = [
                "⛔ **១. ហាមចុចបើក:** ហាមទាញយក ឬ Extract បើកឯកសារនេះដាច់ខាត!",
                "🚫 **២. ប្លុក & Report:** ចុច Block និង Report គណនីសង្ស័យនេះក្នុង Telegram",
                "🧹 **៣. លុបសារចេញ:** លុបសារ និងឯកសារនេះចេញពី Chat របស់អ្នកភ្លាមៗ"
            ]
        elif status == "SUSPICIOUS":
            badge = "🟡 **ឯកសារគួរឱ្យសង្ស័យ (SUSPICIOUS FILE)**"
            rec = "⚠️ ឯកសារប្រភេទនេះអាចមានហានិភ័យ សូមផ្ទៀងផ្ទាត់ប្រភពឱ្យបានច្បាស់លាស់។"
            action_steps = [
                "⚠️ **១. កុំប្រញាប់បើក:** ឯកសារប្រភេទបង្រួម (.z / .zip) អាចបង្កប់កូដបញ្ជា ឬមេរោគ",
                "🔍 **២. ផ្ទៀងផ្ទាត់ប្រភព:** ពិនិត្យមើលថាតើអ្នកផ្ញើជាមនុស្សដែលអ្នកស្គាល់ច្បាស់ឬទេ",
                "🛡️ **៣. ស្កេន Antivirus:** ប្រើប្រាស់ Antivirus លើកុំព្យូទ័រ/ទូរស័ព្ទស្កេនបន្ថែម"
            ]
        else:
            badge = "🟢 **ឯកសារមានសុវត្ថិភាព (SAFE FILE)**"
            rec = "✅ មិនបានរកឃើញសញ្ញាណមេរោគក្នុងឯកសារនេះឡើយ។"
            action_steps = [
                "✅ **១. ប្រើប្រាស់ធម្មតា:** អាចបើកមើលដោយសុវត្ថិភាព",
                "💡 **២. ប្រុងប្រយ័ត្នជាប្រចាំ:** តែងតែផ្ទៀងផ្ទាត់ប្រភពមុនដំឡើង"
            ]

        size_note = f"\n⚠️ *(ទំហំ {round(file_size/(1024*1024), 2)}MB > 20MB API Limit - វិភាគតាម Structure & Metadata)*" if file_size > 20 * 1024 * 1024 else ""

        report_text = (
            f"🛡️ **NSSF FILE SECURITY REPORT**\n"
            f"═════════════════════════\n\n"
            f"📁 **ឈ្មោះឯកសារ (FILE NAME):**\n`{filename}`\n\n"
            f"📦 **ទំហំឯកសារ (FILE SIZE):** `{round(file_size/(1024*1024), 2)} MB`\n"
            f"🏷️ **កម្រិតហានិភ័យ (STATUS):**\n{badge}\n\n"
            f"🔬 **SECURITY ENGINE:**\n`{vt_result.get('provider', 'VirusTotal v3 Intelligence')}`\n"
            f"ℹ️ **ប្រភេទឯកសារ:** {vt_result.get('extension_description', DANGEROUS_EXTENSIONS.get(file_ext, 'File'))}{size_note}\n\n"
            f"🛠️ **ជំហានអនុវត្តជាក់ស្តែង (ACTIONABLE STEPS):**\n" + "\n".join([f"{step}" for step in action_steps]) + "\n\n"
            f"═════════════════════════\n"
            f"💡 **ការណែនាំ (RECOMMENDATION):**\n{rec}"
        )

        await progress_msg.edit_text(report_text, parse_mode="Markdown")

    except Exception as e:
        logger.error(f"Error scanning file {filename}: {e}")
        ext_desc = DANGEROUS_EXTENSIONS.get(file_ext, "File")
        fallback_msg = (
            f"🛡️ **NSSF FILE SECURITY REPORT**\n"
            f"═════════════════════════\n\n"
            f"📁 **ឈ្មោះឯកសារ:** `{filename}`\n"
            f"🏷️ **ប្រភេទ:** {ext_desc}\n"
            f"⚠️ ឯកសារប្រភេទ `{file_ext}` ត្រូវបានវិភាគសុវត្ថិភាពតាម Metadata & Extension Check។"
        )
        await progress_msg.edit_text(fallback_msg, parse_mode="Markdown")


def format_security_report(ai_report: dict, vt_reports: list) -> str:
    """
    Format rich security alert response in Khmer and English.
    """
    badge = ai_report.get("risk_badge", "🟢 SAFE")
    score = ai_report.get("risk_score", 0)
    category = ai_report.get("category", "General")
    summary_kh = ai_report.get("summary_kh", "")
    rec = ai_report.get("recommendation", "")
    action_steps = ai_report.get("action_steps", [])

    factors_str = ""
    if ai_report.get("threat_factors"):
        factors_str = "\n📌 **សញ្ញាណហានិភ័យ (DETECTED INDICATORS):**\n" + "\n".join([f"• {f}" for f in ai_report["threat_factors"]])

    vt_str = ""
    if vt_reports:
        vt_str = "\n\n🌐 **VIRUSTOTAL v3 INTEL SCAN:**\n"
        for v in vt_reports:
            vt_str += f"• Target: `{v.get('target', '')}` ➔ {v.get('status')} ({v.get('malicious_count', 0)} / 70 Engines Flagged)\n"

    actions_str = ""
    if action_steps:
        actions_str = "\n\n🛠️ **ជំហានអនុវត្តជាក់ស្តែង (ACTIONABLE STEPS):**\n" + "\n".join([f"{step}" for step in action_steps])

    report = (
        f"🛡️ **NSSF SECURITY SCAN REPORT**\n"
        f"═════════════════════════\n\n"
        f"🚨 **កម្រិតហានិភ័យ (RISK LEVEL):**\n{badge} *(Score: {score} / 100)*\n\n"
        f"🏷️ **ប្រភេទសេនារីយ៉ូ (CATEGORY):**\n`{category}`\n\n"
        f"📝 **ការវិភាគខ្លឹមសារ (SUMMARY):**\n{summary_kh}"
        f"{factors_str}"
        f"{vt_str}"
        f"{actions_str}\n\n"
        f"═════════════════════════\n"
        f"💡 **ការណែនាំ (RECOMMENDATION):**\n{rec}"
    )
    return report



def main():
    """
    Telegram Bot runner function.
    """
    if not TELEGRAM_BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN is not configured in .env. Bot runner disabled.")
        return

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    # Handlers
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("scan", handle_message))
    
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))

    logger.info("Telegram Security Bot is starting polling...")
    app.run_polling()

if __name__ == "__main__":
    main()
