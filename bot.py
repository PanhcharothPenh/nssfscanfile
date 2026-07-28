import os
import logging
import asyncio
from typing import Optional
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)

def get_main_menu_keyboard():
    """
    Generate rich interactive inline menu buttons in Khmer.
    """
    keyboard = [
        [
            InlineKeyboardButton("🔍 របៀបស្កេនសារ/Link", callback_data="btn_scan_guide"),
            InlineKeyboardButton("📁 ស្កេនឯកសារ (File Scan)", callback_data="btn_file_guide")
        ],
        [
            InlineKeyboardButton("📊 ស្ថានភាពប្រព័ន្ធ (SOC Status)", callback_data="btn_status"),
            InlineKeyboardButton("❓ មគ្គុទ្ទេសក៍ (Help)", callback_data="btn_help")
        ],
        [
            InlineKeyboardButton("👥 បន្ថែម Bot ចូល Group (Add to Group)", url="https://t.me/nssf_scan_file_bot?startgroup=true")
        ]
    ]
    return InlineKeyboardMarkup(keyboard)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /start command handler for NSSF Security Scan Bot.
    """
    welcome_caption = (
        "🛡️ **NSSF Security Scan គឺជា AI Bot**\n\n"
        "ដែលជួយការពារអ្នកពីការបោកប្រាស់តាមប្រព័ន្ធអ៊ីនធឺណិត។ គ្រាន់តែផ្ញើតំណភ្ជាប់ (Link) សារ ឬឯកសារដែលអ្នកសង្ស័យមកកាន់ Bot នោះវានឹងវិភាគរកហានិភ័យរួចផ្តល់ការណែនាំដល់អ្នកភ្លាមៗ។\n\n"
        "✨ **លក្ខណៈពិសេសរបស់ Bot (Bot Features):**\n"
        "1️⃣ **វិភាគខ្លឹមសារសារ (AI Scam Detection):** ស្គាល់ភាសាគំរាមកំហែង, ការក្លែងបន្លំធនាគារ និងការបង្ខំឱ្យផ្ទេរប្រាក់\n"
        "2️⃣ **ស្កេន VirusTotal v3 (Link & File Scan):** ពិនិត្យមើល URL និងឯកសារប្រភេទ `.apk`, `.exe`, `.zip`, `.z`, `.7z`, `.pdf`\n"
        "3️⃣ **ប្រព័ន្ធការពារ Group Chat:** ទាញ Bot ចូល Group ដើម្បីការពារសមាជិកទាំងអស់ដោយស្វ័យប្រវត្តិ 24/7\n\n"
        "🔍 **Commands:**\n"
        "/menu - 🎛️ ម៉ឺនុយប្រព័ន្ធសុវត្ថិភាព\n"
        "/scan `<text or url>` - ស្កេនសារ ឬ តំណភ្ជាប់\n"
        "/status - ពិនិត្យមើលស្ថានភាពសុវត្ថិភាព\n"
        "/help - មគ្គុទ្ទេសក៍ និងរបៀបប្រើប្រាស់\n\n"
        "--- \n"
        "រៀបចំដោយ៖ ការិយាល័យសុវត្ថិភាពបច្ចេកវិទ្យាព័ត៍មាន"
    )

    banner_jpg = os.path.join(os.path.dirname(__file__), "static", "images", "welcome_banner.jpg")
    profile_jpg = os.path.join(os.path.dirname(__file__), "static", "images", "profile_photo.jpg")
    banner_path = banner_jpg if os.path.exists(banner_jpg) else (profile_jpg if os.path.exists(profile_jpg) else None)

    if banner_path:
        with open(banner_path, "rb") as photo_file:
            await update.message.reply_photo(
                photo=photo_file,
                caption=welcome_caption,
                reply_markup=get_main_menu_keyboard(),
                parse_mode="Markdown"
            )
    else:
        await update.message.reply_text(welcome_caption, reply_markup=get_main_menu_keyboard(), parse_mode="Markdown")



async def menu_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /menu command handler.
    """
    menu_text = (
        "🎛️ **ម៉ឺនុយប្រព័ន្ធសុវត្ថិភាព NSSF Security Scan**\n\n"
        "សូមជ្រើសរើសមុខងារ ឬព័ត៌មានដែលអ្នកចង់ពិនិត្យមើលខាងក្រោម៖\n\n"
        "--- \n"
        "រៀបចំដោយ៖ ការិយាល័យសុវត្ថិភាពបច្ចេកវិទ្យាព័ត៍មាន"
    )
    await update.message.reply_text(menu_text, reply_markup=get_main_menu_keyboard(), parse_mode="Markdown")


async def handle_callback_query(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles button clicks from the inline menu.
    """
    query = update.callback_query
    await query.answer()

    data = query.data
    if data == "btn_scan_guide":
        scan_msg = (
            "🔍 **របៀបស្កេនសារ ឬ តំណភ្ជាប់ (Link):**\n\n"
            "1️⃣ គ្រាន់តែ Forward សារសង្ស័យចូលមកកាន់ Bot\n"
            "2️⃣ ឬ Copy-Paste Link/សារ រួចផ្ញើមកកាន់ Bot\n"
            "3️⃣ ឬប្រើប្រាស់ Command `/scan <សារ ឬ Link>`\n\n"
            "🤖 AI Bot នឹងស្កេនរកល្បិចបោកប្រាស់ និង VirusTotal Link Scan ភ្លាមៗ!\n\n"
            "--- \n"
            "រៀបចំដោយ៖ ការិយាល័យសុវត្ថិភាពបច្ចេកវិទ្យាព័ត៍មាន"
        )
        await query.message.reply_text(scan_msg, parse_mode="Markdown", reply_markup=get_main_menu_keyboard())

    elif data == "btn_file_guide":
        file_msg = (
            "📁 **របៀបស្កេនឯកសារ (File Scanning Guide):**\n\n"
            "1️⃣ ផ្ញើ ឬ Forward ឯកសារប្រភេទ `.apk`, `.exe`, `.zip`, `.z`, `.7z`, `.pdf`, `.rar`, `.msi` មកកាន់ Bot\n"
            "2️⃣ Bot នឹងធ្វើការស្កេន Hash Check & Structure Security Evaluation រកមើលមេរោគ (Malware/Trojan)\n\n"
            "⚠️ *ចំណាំ៖ ឯកសារទំហំលើសពី 20MB នឹងត្រូវស្កេនតាម Extension Check ដោយសុវត្ថិភាព។*\n\n"
            "--- \n"
            "រៀបចំដោយ៖ ការិយាល័យសុវត្ថិភាពបច្ចេកវិទ្យាព័ត៍មាន"
        )
        await query.message.reply_text(file_msg, parse_mode="Markdown", reply_markup=get_main_menu_keyboard())

    elif data == "btn_status":
        stats = get_soc_stats()
        status_text = (
            "📊 **របាយការណ៍សុវត្ថិភាពប្រព័ន្ធ (SOC Security Telemetry)**\n\n"
            f"• **ចំនួនស្កេនសរុប (Total Scans):** {stats['total_scans']}\n"
            f"• **សារ/ឯកសារគ្រោះថ្នាក់ (Dangerous Threats):** 🔴 {stats['dangerous_count']}\n"
            f"• **សារ/ឯកសារសង្ស័យ (Suspicious):** 🟡 {stats['suspicious_count']}\n"
            f"• **សារសុវត្ថិភាព (Safe Messages):** 🟢 {stats['safe_count']}\n"
            f"• **ឯកសារបានស្កេន (Files Scanned):** 📁 {stats['file_scans']}\n"
            f"• **តំណភ្ជាប់បានស្កេន (URLs Scanned):** 🔗 {stats['url_scans']}\n\n"
            "✅ **ប្រព័ន្ធកំពុងដំណើរការការពារ ២៤/៧**\n\n"
            "--- \n"
            "រៀបចំដោយ៖ ការិយាល័យសុវត្ថិភាពបច្ចេកវិទ្យាព័ត៍មាន"
        )
        await query.message.reply_text(status_text, parse_mode="Markdown", reply_markup=get_main_menu_keyboard())

    elif data == "btn_help":
        help_text = (
            "❓ **មគ្គុទ្ទេសក៍ប្រើប្រាស់ប្រព័ន្ធសុវត្ថិភាព (Help Guide)**\n\n"
            "• **ផ្ញើសារ ឬឯកសារសង្ស័យ:** Forward សារ ចម្លងតំណភ្ជាប់ (Link) ឬផ្ញើឯកសារទៅកាន់ Bot ដោយផ្ទាល់ ដោយមិនបាច់ចុចបើកវាជាមុនឡើយ។\n"
            "• **ស្កេនតំណភ្ជាប់ & ឯកសារ (VirusTotal v3):** Bot ពិនិត្យមើល URL និងឯកសារ APK, EXE, ZIP, Z, 7Z, PDF ដែលជនខិលខូចនិយមប្រើ។\n"
            "• **ប្រព័ន្ធការពារ Group Chat:** បន្ថែម Bot ចូលក្នុង Group ដើម្បីការពារសមាជិកទាំងអស់ពីសារបោកប្រាស់ និង Malware ភ្លាមៗ។\n\n"
            "--- \n"
            "រៀបចំដោយ៖ ការិយាល័យសុវត្ថិភាពបច្ចេកវិទ្យាព័ត៍មាន"
        )
        await query.message.reply_text(help_text, parse_mode="Markdown", reply_markup=get_main_menu_keyboard())


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
        "1️⃣ **វិភាគខ្លឹមសារសារ (AI Scam Detection):** ស្គាល់ភាសាគំរាមកំហែង, ការក្លែងបន្លំធនាគារ និងការបង្ខំឱ្យផ្ទេរប្រាក់\n"
        "2️⃣ **ស្កេន VirusTotal v3 (Link & File Scan):** ពិនិត្យមើល URL និងឯកសារប្រភេទ `.apk`, `.exe`, `.zip`, `.z`, `.7z`, `.pdf`\n"
        "3️⃣ **ប្រព័ន្ធការពារ Group Chat:** ទាញ Bot ចូល Group ដើម្បីការពារសមាជិកទាំងអស់ដោយស្វ័យប្រវត្តិ 24/7\n\n"
        "🔍 **Commands:**\n"
        "/scan `<text or url>` - ស្កេនសារ ឬ តំណភ្ជាប់ដោយផ្ទាល់\n"
        "/status - ពិនិត្យមើលស្ថានភាពសុវត្ថិភាព\n"
        "/help - មគ្គុទ្ទេសក៍ និងរបៀបប្រើប្រាស់\n\n"
        "--- \n"
        "រៀបចំដោយ៖ ការិយាល័យសុវត្ថិភាពបច្ចេកវិទ្យាព័ត៍មាន"
    )

    banner_png = os.path.join(os.path.dirname(__file__), "static", "images", "welcome_banner.png")
    banner_jpg = os.path.join(os.path.dirname(__file__), "static", "images", "welcome_banner.jpg")
    banner_path = banner_png if os.path.exists(banner_png) else (banner_jpg if os.path.exists(banner_jpg) else None)

    if banner_path:
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
        "• **ស្កេនតំណភ្ជាប់ & ឯកសារ (VirusTotal v3):** Bot ពិនិត្យមើល URL និងឯកសារ APK, EXE, ZIP, Z, 7Z, PDF ដែលជនខិលខូចនិយមប្រើ។\n"
        "• **ប្រព័ន្ធការពារ Group Chat:** បន្ថែម Bot ចូលក្នុង Group ដើម្បីការពារសមាជិកទាំងអស់ពីសារបោកប្រាស់ និង Malware ភ្លាមៗ។\n\n"
        "--- \n"
        "រៀបចំដោយ៖ ការិយាល័យសុវត្ថិភាពបច្ចេកវិទ្យាព័ត៍មាន"
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
    Matches the exact Khmer security report design requested by user.
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
        f"🔍 **កំពុងស្កេនឯកសារ៖** `{filename}` ({round(file_size/(1024*1024), 2)} MB)...",
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

        # Format Response matching user's exact Khmer template
        if status == "DANGEROUS":
            badge = "🔴 **គ្រោះថ្នាក់ខ្លាំង (Malware)**"
            rec = "កុំទាញយក ឬចែករំលែកឯកសារនេះ ព្រោះវាអាចបង្កគ្រោះថ្នាក់ដល់កុំព្យូទ័រ និងទិន្នន័យរបស់អ្នក។"
            action_steps = [
                "⛔ កុំចុចបើក ឬដំណើរការឯកសារនេះ។",
                "🚫 Block និង Report គណនីដែលបានផ្ញើ។",
                "🗑️ លុបសារ និងឯកសារនេះចេញភ្លាមៗ។"
            ]
        elif status == "SUSPICIOUS":
            badge = "🟡 **គួរឱ្យសង្ស័យ (Suspicious File)**"
            rec = "សូមផ្ទៀងផ្ទាត់ប្រភពឱ្យបានច្បាស់លាស់មុននឹងធ្វើការទាញយក ឬបើកឯកសារនេះ។"
            action_steps = [
                "⚠️ កុំប្រញាប់បើក ឬដំណើរការឯកសារនេះ។",
                "🔍 ផ្ទៀងផ្ទាត់ប្រភពអ្នកផ្ញើឱ្យបានច្បាស់លាស់។",
                "🛡️ ប្រើប្រាស់ Antivirus ស្កេនបន្ថែមមុននឹងបើក។"
            ]
        else:
            badge = "🟢 **សុវត្ថិភាព (Safe File)**"
            rec = "ឯកសារនេះហាក់ដូចជាមានសុវត្ថិភាព មិនបានរកឃើញសញ្ញាណមេរោគឡើយ។"
            action_steps = [
                "✅ អាចបើកមើល ឬទាញយកដោយសុវត្ថិភាព។",
                "💡 តែងតែរក្សាការប្រុងប្រយ័ត្នជាប្រចាំ។"
            ]

        size_note = f"\n*(ទំហំ {round(file_size/(1024*1024), 2)}MB > 20MB API Limit - វិភាគតាម Extension Check)*" if file_size > 20 * 1024 * 1024 else ""

        report_text = (
            f"🛡️ **លទ្ធផលត្រួតពិនិត្យឯកសារ**\n\n"
            f"📁 **ឈ្មោះឯកសារ៖** `{filename}`{size_note}\n"
            f"🏷️ **ស្ថានភាព៖** {badge}\n\n"
            f"⚠️ **សូមអនុវត្ត៖**\n" + "\n".join(action_steps) + "\n\n"
            f"💡 **ការណែនាំ៖** {rec}\n\n"
            f"---\n"
            f"រៀបចំដោយ៖ ការិយាល័យសុវត្ថិភាពបច្ចេកវិទ្យាព័ត៍មាន"
        )

        await progress_msg.edit_text(report_text, parse_mode="Markdown")

    except Exception as e:
        logger.error(f"Error scanning file {filename}: {e}")
        ext_desc = DANGEROUS_EXTENSIONS.get(file_ext, "File")
        fallback_msg = (
            f"🛡️ **លទ្ធផលត្រួតពិនិត្យឯកសារ**\n\n"
            f"📁 **ឈ្មោះឯកសារ៖** `{filename}`\n"
            f"🏷️ **ស្ថានភាព៖** 🟡 **គួរឱ្យសង្ស័យ ({ext_desc})**\n\n"
            f"⚠️ **សូមអនុវត្ត៖**\n"
            f"⚠️ កុំប្រញាប់បើក ឬដំណើរការឯកសារនេះ។\n"
            f"🔍 ផ្ទៀងផ្ទាត់ប្រភពអ្នកផ្ញើឱ្យបានច្បាស់លាស់។\n\n"
            f"💡 **ការណែនាំ៖** សូមផ្ទៀងផ្ទាត់ប្រភពឱ្យបានច្បាស់លាស់មុននឹងបើកឯកសារនេះ。\n\n"
            f"---\n"
            f"រៀបចំដោយ៖ ការិយាល័យសុវត្ថិភាពបច្ចេកវិទ្យាព័ត៍មាន"
        )
        await progress_msg.edit_text(fallback_msg, parse_mode="Markdown")



def format_security_report(ai_report: dict, vt_reports: list) -> str:
    """
    Format rich security alert response in Khmer matching user template.
    """
    badge = ai_report.get("risk_badge", "🟢 SAFE")
    summary_kh = ai_report.get("summary_kh", "")
    rec = ai_report.get("recommendation", "")
    action_steps = ai_report.get("action_steps", [])

    factors_str = ""
    if ai_report.get("threat_factors"):
        factors_str = "\n\n📌 **សញ្ញាណហានិភ័យ៖**\n" + "\n".join([f"• {f}" for f in ai_report["threat_factors"]])

    vt_str = ""
    if vt_reports:
        vt_str = "\n\n🌐 **លទ្ធផលស្កេន VirusTotal v3 Link:**\n"
        for v in vt_reports:
            vt_str += f"• `{v.get('target', '')}` ➔ {v.get('status')} ({v.get('malicious_count', 0)}/70 engines flagged)\n"

    actions_str = ""
    if action_steps:
        actions_str = "\n\n⚠️ **សូមអនុវត្ត៖**\n" + "\n".join([f"{step}" for step in action_steps])

    report = (
        f"🛡️ **លទ្ធផលត្រួតពិនិត្យសារ & តំណភ្ជាប់**\n\n"
        f"🏷️ **ស្ថានភាព៖** {badge}\n"
        f"📝 **ខ្លឹមសារសារ៖** {summary_kh}"
        f"{factors_str}"
        f"{vt_str}"
        f"{actions_str}\n\n"
        f"💡 **ការណែនាំ៖** {rec}\n\n"
        f"---\n"
        f"រៀបចំដោយ៖ ការិយាល័យសុវត្ថិភាពបច្ចេកវិទ្យាព័ត៍មាន"
    )
    return report





async def post_init(app: Application):
    """
    Set pre-start description popup card, media photo banner, short description, and menu commands.
    Displays instructions and wallpaper photo on screen BEFORE user clicks START.
    """
    pre_start_guideline = (
        "🛡️ NSSF Security Scan - AI Security Bot\n\n"
        "មគ្គុទ្ទេសក៍ និងរបៀបប្រើប្រាស់៖\n"
        "Bot នេះជួយការពារអ្នកពីការបោកប្រាស់ Phishing, ការក្លែងបន្លំធនាគារ, សារគំរាមកំហែង និងមេរោគ (Malware)!\n\n"
        "✨ របៀបប្រើប្រាស់ (How to Use):\n"
        "1️⃣ Forward សារ ឬចម្លងតំណភ្ជាប់ (Link) សង្ស័យមកកាន់ Bot\n"
        "2️⃣ ផ្ញើឯកសារ (.apk, .exe, .zip, .z, .7z, .pdf) ដើម្បីស្កេនមេរោគ\n"
        "3️⃣ ទាញ Bot ចូល Group Chat ដើម្បីការពារសមាជិកទាំងអស់ ២៤/៧\n\n"
        "👉 ចុចប៊ូតុង START ខាងក្រោមដើម្បីចាប់ផ្តើមប្រើប្រាស់!"
    )

    short_desc = "NSSF Security Scan - AI Bot ស្កេន និងការពារសារ, Link និង ឯកសារសង្ស័យ"

    try:
        import httpx, json
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/setMyDescription"
        photo_path = os.path.join(os.path.dirname(__file__), "static", "images", "profile_photo.jpg")
        
        if os.path.exists(photo_path):
            photo_obj = json.dumps({"type": "static", "photo": "attach://photo_file"})
            with open(photo_path, "rb") as pf:
                files = {"photo_file": ("wallpaper.jpg", pf, "image/jpeg")}
                data = {"description": pre_start_guideline, "photo": photo_obj}
                async with httpx.AsyncClient() as client:
                    await client.post(url, data=data, files=files)
        else:
            await app.bot.set_my_description(description=pre_start_guideline)

        await app.bot.set_my_short_description(short_description=short_desc)
        from telegram import BotCommand
        await app.bot.set_my_commands([
            BotCommand("menu", "🎛️ ម៉ឺនុយប្រព័ន្ធសុវត្ថិភាព NSSF Security"),
            BotCommand("scan", "🔍 ស្កេនសារ ឬ តំណភ្ជាប់សង្ស័យ"),
            BotCommand("status", "📊 ពិនិត្យមើលស្ថានភាពប្រព័ន្ធសុវត្ថិភាព"),
            BotCommand("help", "❓ មគ្គុទ្ទេសក៍ និងរបៀបប្រើប្រាស់"),
            BotCommand("start", "🚀 ចាប់ផ្តើមប្រើប្រាស់ NSSF Security Bot")
        ])
        logger.info("Bot pre-start description popup guidelines, media photo banner, and menu commands updated successfully.")
    except Exception as e:
        logger.error(f"Error setting bot descriptions: {e}")


def main():
    """
    Telegram Bot runner function.
    """
    if not TELEGRAM_BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN is not configured in .env. Bot runner disabled.")
        return

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).post_init(post_init).build()

    # Handlers
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("menu", menu_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("scan", handle_message))
    
    app.add_handler(CallbackQueryHandler(handle_callback_query))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))

    logger.info("Telegram Security Bot is starting polling...")
    app.run_polling()

if __name__ == "__main__":
    main()







def main():
    """
    Telegram Bot runner function.
    """
    if not TELEGRAM_BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN is not configured in .env. Bot runner disabled.")
        return

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).post_init(post_init).build()

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

