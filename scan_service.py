"""Logic shared by the Telegram bot and the web API: combining analyzer + VirusTotal
results, per-user rate limiting, and Telegram-safe (HTML) report formatting."""
import asyncio
import html
import time
from collections import defaultdict, deque
from typing import Any, Dict, Iterable, List, Optional, Tuple

from config import MAX_URLS_PER_MESSAGE

FOOTER = "រៀបចំដោយ៖ ការិយាល័យសុវត្ថិភាពបច្ចេកវិទ្យាព័ត៌មាន"

BADGES = {
    "DANGEROUS": "🔴 <b>គ្រោះថ្នាក់ខ្លាំង</b>",
    "SUSPICIOUS": "🟡 <b>គួរឱ្យសង្ស័យ</b>",
    "SAFE": "🟢 <b>មិនឃើញសញ្ញាគ្រោះថ្នាក់</b>",
    "UNKNOWN": "⚪ <b>មិនអាចផ្ទៀងផ្ទាត់បាន (មិនទាន់បានស្កេន)</b>",
    "ANALYZING": "⏳ <b>កំពុងវិភាគ សូមសាកល្បងម្តងទៀតក្រោយមួយនាទី</b>",
}
SCORES = {"DANGEROUS": 90, "SUSPICIOUS": 60, "SAFE": 10, "UNKNOWN": 0, "ANALYZING": 0}
TELEGRAM_LIMIT = 4000

BIG_FILE_HELP = (
    "✅ <b>វិធីពិនិត្យឯកសារនេះ (ងាយស្រួល)៖</b>\n"
    "1️⃣ បើក <b>virustotal.com</b> → ចុច <i>Choose file</i> → ជ្រើសឯកសារ (រហូតដល់ 650MB)។ "
    "ចម្លង Link លទ្ធផល ហើយផ្ញើមកកាន់ Bot ឬមើលលទ្ធផលនៅទីនោះ។\n"
    "2️⃣ ឬផ្ញើលេខ <b>SHA-256</b> របស់ឯកសារមកកាន់ Bot (/hash ជួយបង្ហាញរបៀប)។"
)

HASH_HELP = (
    "💡 <b>ពិនិត្យឯកសារធំបានយ៉ាងងាយ៖</b>\n"
    "1️⃣ នៅលើ Windows បើក PowerShell ក្នុងថតឯកសារ ហើយវាយ៖\n"
    "<code>certutil -hashfile ឈ្មោះឯកសារ SHA256</code>\n"
    "(Mac/Linux៖ <code>shasum -a 256 ឈ្មោះឯកសារ</code>)\n"
    "2️⃣ ចម្លងលេខវែង ៦៤ តួអក្សរ ហើយផ្ញើមកកាន់ Bot ត្រង់ៗ ឬប្រើ <code>/hash លេខនោះ</code>\n"
    "⚠️ វិធីនេះឆ្លើយបានតែឯកសារដែល VirusTotal ធ្លាប់ឃើញ។"
)


class UserRateLimiter:
    """Allow at most ``limit`` actions per user per 60 seconds."""

    def __init__(self, limit: int):
        self.limit = limit
        self._hits: Dict[Any, "deque[float]"] = defaultdict(deque)

    def allow(self, key) -> bool:
        now = time.monotonic()
        q = self._hits[key]
        while q and now - q[0] >= 60:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        # keep memory bounded
        if len(self._hits) > 5000:
            for k in [k for k, v in self._hits.items() if not v][:1000]:
                self._hits.pop(k, None)
        return True


def combine_risk(ai_level: str, vt_reports: Iterable[Dict[str, Any]]) -> str:
    level = ai_level
    for vt in vt_reports:
        st = vt.get("status")
        if st == "DANGEROUS":
            return "DANGEROUS"
        if st == "SUSPICIOUS" and level == "SAFE":
            level = "SUSPICIOUS"
    return level


async def scan_text(
    analyzer, vt_scanner, text: str, extra_urls: Optional[Iterable[str]] = None
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], str]:
    """Run the analyzer and scan up to MAX_URLS_PER_MESSAGE links in parallel."""
    ai_report = await analyzer.analyze_message(text, extra_urls=extra_urls)
    urls = ai_report.get("urls_found", [])[:MAX_URLS_PER_MESSAGE]
    vt_reports = list(await asyncio.gather(*[vt_scanner.scan_url(u) for u in urls])) if urls else []
    level = combine_risk(ai_report["risk_level"], vt_reports)
    if any(v.get("status") == "DANGEROUS" for v in vt_reports):
        ai_report["risk_score"] = max(ai_report["risk_score"], 90)
    ai_report["risk_level"] = level
    return ai_report, vt_reports, level


def _e(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=False)


def _clip(text: str) -> str:
    return text if len(text) <= TELEGRAM_LIMIT else text[: TELEGRAM_LIMIT - 20] + "\n…(truncated)"


def _vt_line(v: Dict[str, Any]) -> str:
    target = _e(v.get("target", ""))
    if v.get("scanned"):
        return (
            f"• <code>{target}</code> ➔ {_e(v.get('status'))} "
            f"({v.get('malicious_count', 0)} malicious, {v.get('suspicious_count', 0)} suspicious "
            f"of {v.get('total_engines', 0)} engines)"
        )
    label = "កំពុងវិភាគ" if v.get("status") == "ANALYZING" else "មិនទាន់ផ្ទៀងផ្ទាត់"
    return f"• <code>{target}</code> ➔ {label} — {_e(v.get('message', ''))}"


def format_text_report(ai_report: Dict[str, Any], vt_reports: List[Dict[str, Any]]) -> str:
    level = ai_report.get("risk_level", "SAFE")
    parts = [
        "🛡️ <b>លទ្ធផលត្រួតពិនិត្យសារ &amp; តំណភ្ជាប់</b>",
        f"🏷️ <b>ស្ថានភាព៖</b> {BADGES.get(level, level)}",
        f"📝 <b>ខ្លឹមសារសារ៖</b> {_e(ai_report.get('summary_kh', ''))}",
    ]
    if ai_report.get("threat_factors"):
        parts.append("📌 <b>សញ្ញាណហានិភ័យ៖</b>\n" + "\n".join(f"• {_e(f)}" for f in ai_report["threat_factors"]))
    if vt_reports:
        parts.append("🌐 <b>លទ្ធផលស្កេនតំណភ្ជាប់ (VirusTotal)៖</b>\n" + "\n".join(_vt_line(v) for v in vt_reports))
    steps = ai_report.get("action_steps") or []
    if steps:
        parts.append("⚠️ <b>សូមអនុវត្ត៖</b>\n" + "\n".join(_e(s.replace("**", "")) for s in steps))
    parts.append(f"💡 <b>ការណែនាំ៖</b> {_e(ai_report.get('recommendation', '').replace('**', ''))}")
    parts.append(f"---\n{FOOTER}")
    return _clip("\n\n".join(parts))


FILE_STEPS = {
    "DANGEROUS": [
        "⛔ កុំចុចបើក ឬដំណើរការឯកសារនេះ។",
        "🚫 Block និង Report គណនីដែលបានផ្ញើ។",
        "🗑️ លុបសារ និងឯកសារនេះចេញភ្លាមៗ។",
    ],
    "SUSPICIOUS": [
        "⚠️ កុំប្រញាប់បើក ឬដំណើរការឯកសារនេះ។",
        "🔍 ផ្ទៀងផ្ទាត់ប្រភពអ្នកផ្ញើឱ្យបានច្បាស់លាស់។",
        "🛡️ ប្រើ Antivirus ស្កេនបន្ថែមមុននឹងបើក។",
    ],
    "SAFE": [
        "✅ ម៉ាស៊ីនស្កេនទាំងអស់មិនរកឃើញមេរោគ។",
        "💡 នេះមិនមែនជាការធានា ១០០% ទេ។ សូមប្រុងប្រយ័ត្នជាប្រចាំ។",
    ],
    "UNKNOWN": [
        "❗ ឯកសារនេះ <b>មិនទាន់ត្រូវបានស្កេន</b>។ កុំសន្មត់ថាវាសុវត្ថិភាព។",
        "🔍 ផ្ទៀងផ្ទាត់ប្រភពអ្នកផ្ញើ មុនពេលបើក។",
    ],
    "ANALYZING": [
        "⏳ ឯកសារត្រូវបានបញ្ជូនទៅ VirusTotal ហើយ។ សូមផ្ញើម្តងទៀតក្រោយមួយនាទី។",
    ],
}


def format_file_report(filename: str, vt_result: Dict[str, Any]) -> str:
    status = vt_result.get("status", "UNKNOWN")
    parts = [
        "🛡️ <b>លទ្ធផលត្រួតពិនិត្យឯកសារ</b>",
        f"📁 <b>ឈ្មោះឯកសារ៖</b> <code>{_e(filename)}</code>",
        f"🏷️ <b>ស្ថានភាព៖</b> {BADGES.get(status, status)}",
    ]
    if vt_result.get("scanned"):
        parts.append(
            f"🔬 {vt_result.get('malicious_count', 0)} malicious · {vt_result.get('suspicious_count', 0)} suspicious"
            f" (of {vt_result.get('total_engines', 0)} engines)"
        )
        if vt_result.get("permalink"):
            parts.append(f"🔗 {_e(vt_result['permalink'])}")
    else:
        if vt_result.get("too_large"):
            parts.append("ℹ️ ឯកសារធំជាង 20MB Telegram មិនអនុញ្ញាតឱ្យ Bot ទាញយកបានទេ ដូច្នេះ <b>មិនទាន់បានស្កេន</b>។")
            if vt_result.get("risky_file_type"):
                parts.append(
                    f"⚠️ <b>ការព្រមានតាមប្រភេទឯកសារ (មិនមែនជាលទ្ធផលស្កេនទេ)៖</b> "
                    f"{_e(vt_result.get('type_description', ''))} "
                    "ជាប្រភេទដែលជនខិលខូចប្រើញឹកញាប់។ កុំបើកវា លុះត្រាតែអ្នកទុកចិត្តអ្នកផ្ញើ។"
                )
            parts.append(BIG_FILE_HELP)
        elif vt_result.get("not_found"):
            parts.append(
                "ℹ️ VirusTotal មិនធ្លាប់ឃើញឯកសារនេះទេ។ នេះ <b>មិនមែន</b>មានន័យថាវាសុវត្ថិភាពទេ "
                "(អាចជាឯកសារថ្មី ឬត្រូវបានកែប្រែ)។"
            )
        elif vt_result.get("message"):
            parts.append(f"ℹ️ {_e(vt_result['message'])}")
        if vt_result.get("high_risk_file_type"):
            parts.append(
                f"⚠️ ប្រភេទឯកសារនេះ ({_e(vt_result.get('type_description', ''))}) ជាប្រភេទដែលជនខិលខូចប្រើញឹកញាប់។"
                " នេះជាការព្រមានអំពីប្រភេទឯកសារ មិនមែនជាលទ្ធផលស្កេនមេរោគទេ។"
            )
    parts.append("⚠️ <b>សូមអនុវត្ត៖</b>\n" + "\n".join(FILE_STEPS.get(status, FILE_STEPS["UNKNOWN"])))
    parts.append(f"---\n{FOOTER}")
    return _clip("\n\n".join(parts))
