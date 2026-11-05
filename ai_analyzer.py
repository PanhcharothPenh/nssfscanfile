"""Scam / phishing analyzer for Khmer and English messages.

Fast rule-based pass first. If an OpenAI or Gemini key is configured, messages
whose score is borderline get a second opinion from an LLM (optional).

Improvements over plain substring matching:
  * Unicode normalisation + removal of zero-width characters (used to dodge filters)
  * word-boundary matching for English terms ("aba" no longer matches "database")
  * link analysis: look-alike bank domains, URL shorteners, IP hosts, punycode,
    suspicious TLDs
  * a bank mention or a link alone is not enough to flag a message
"""
import logging
import os
import re
import unicodedata
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

import httpx

from config import GEMINI_API_KEY, OPENAI_API_KEY

logger = logging.getLogger(__name__)

# --- text helpers ------------------------------------------------------------
_INVISIBLE = re.compile("[​‌‍⁠﻿­]")


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = _INVISIBLE.sub("", text)
    return text.lower()


def _has_khmer(term: str) -> bool:
    return any("ក" <= ch <= "៿" for ch in term)


def find_terms(text: str, terms: Iterable[str]) -> List[str]:
    """Khmer has no spaces between words -> substring match.
    Latin terms are matched on word boundaries."""
    found = []
    for term in terms:
        if _has_khmer(term):
            if term in text:
                found.append(term)
        elif re.search(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])", text):
            found.append(term)
    return found


# --- vocabularies --------------------------------------------------------------
BANK_TERMS = ["aba", "acleda", "wing", "canadia", "sathapana", "អេស៊ីលីដា", "វីង", "ធនាគារ", "bank"]
URGENCY_TERMS = [
    "urgent", "immediately", "suspended", "blocked", "legal action", "police", "penalty",
    "within 24 hours", "last warning", "account will be closed",
    "បន្ទាន់", "បិទគណនី", "គំរាម", "តុលាការ", "ប៉ូលីស", "ពិន័យ", "ប្រញាប់",
]
OTP_TERMS = [
    "otp", "verification code", "confirm code", "pin code", "your pin", "password",
    "send me the code", "លេខកូដ", "ពាក្យសម្ងាត់", "ផ្ទៀងផ្ទាត់លេខកូដ",
]
TRANSFER_TERMS = [
    "transfer", "send money", "deposit", "pay fee", "processing fee",
    "ផ្ទេរប្រាក់", "ផ្ញើលុយ", "បញ្ចូលលុយ", "បង់ថ្លៃ",
]
SCAM_TRICK_TERMS = [
    "winner", "you won", "claim reward", "claim your", "free money", "guaranteed profit",
    "easy income", "work from home", "invest", "crypto", "double your",
    "ឈ្នះរង្វាន់", "ចំណេញច្រើន", "ការងារ", "វិនិយោគ", "ឈ្នះ",
]
# Phrases that show a message is *warning about* scams, not committing one.
AWARENESS_TERMS = [
    "do not share", "don't share", "never share", "never ask", "beware", "be careful",
    "កុំចែករំលែក", "កុំផ្តល់", "ប្រយ័ត្ន", "ប្រុងប្រយ័ត្ន",
]

OFFICIAL_DOMAINS = {
    "aba": ["ababank.com"],
    "acleda": ["acledabank.com.kh"],
    "wing": ["wingmoney.com", "wingbank.com.kh"],
    "canadia": ["canadiabank.com.kh", "canadiabank.com"],
    "sathapana": ["sathapana.com.kh"],
}
# Brands short enough to appear inside normal words: match as a whole label token only.
TOKEN_ONLY_BRANDS = {"aba", "wing"}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at",
    "ow.ly", "goo.gl", "s.id", "tiny.cc", "rebrand.ly",
}
SUSPICIOUS_TLDS = {"xyz", "top", "vip", "click", "icu", "cc", "buzz", "work", "rest", "cfd", "sbs"}

_BARE_TLDS = "com|net|org|info|kh|xyz|top|vip|club|online|site|link|cc|ly|me|io|app|shop|live|icu|click|co"
URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'​]+"
    r"|(?<![\w@.-])(?:[a-z0-9-]+\.)+(?:" + _BARE_TLDS + r")(?:/[^\s<>\"']*)?(?![\w.-])",
    re.IGNORECASE,
)


def _clean_url(raw: str) -> str:
    url = raw.rstrip(".,;:!?)]}\"'")
    if not re.match(r"https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url


def extract_urls(text: str, extra: Optional[Iterable[str]] = None) -> List[str]:
    seen, urls = set(), []
    for raw in list(URL_RE.findall(text or "")) + list(extra or []):
        url = _clean_url(raw)
        key = url.lower()
        if key not in seen:
            seen.add(key)
            urls.append(url)
    return urls


def analyze_url_structure(url: str) -> List[Dict[str, Any]]:
    """Return offline risk signals for one URL: [{'score': int, 'reason': str}]."""
    signals: List[Dict[str, Any]] = []
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return [{"score": 15, "reason": "Malformed URL"}]
    if not host:
        return signals

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        signals.append({"score": 20, "reason": f"Link uses a raw IP address ({host})"})
    if "xn--" in host:
        signals.append({"score": 25, "reason": f"Link uses punycode / look-alike characters ({host})"})
    if host in SHORTENERS:
        signals.append({"score": 15, "reason": f"Shortened link hides destination ({host})"})
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        signals.append({"score": 10, "reason": f"Suspicious domain ending (.{host.rsplit('.', 1)[-1]})"})
    if "@" in urlparse(url).netloc:
        signals.append({"score": 20, "reason": "Link contains '@' to disguise the real host"})

    tokens = set(re.split(r"[^a-z0-9]+", host))
    for brand, official in OFFICIAL_DOMAINS.items():
        mentions = brand in tokens if brand in TOKEN_ONLY_BRANDS else brand in host
        is_official = any(host == d or host.endswith("." + d) for d in official)
        if mentions and not is_official:
            signals.append({"score": 35, "reason": f"Look-alike of {brand.upper()} bank domain ({host})"})
            break
    return signals


# --- analyzer --------------------------------------------------------------------
class AIThreatAnalyzer:
    def __init__(self):
        self.openai_key = OPENAI_API_KEY
        self.gemini_key = GEMINI_API_KEY
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
        self.openai_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    async def analyze_message(self, text: str, extra_urls: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        urls = extract_urls(text or "", extra_urls)
        if not (text or "").strip() and not urls:
            return {
                "risk_score": 0,
                "risk_level": "SAFE",
                "risk_badge": "🟢 សុវត្ថិភាព (SAFE)",
                "category": "Normal Message",
                "summary_kh": "មិនមានអត្ថបទសង្ស័យឡើយ។",
                "summary_en": "No suspicious text detected.",
                "threat_factors": [],
                "recommendation": "សារនេះហាក់ដូចជាមានសុវត្ថិភាព។",
                "action_steps": [],
                "urls_found": [],
            }

        result = self._rule_based_scan(text or "", urls)

        if (self.gemini_key or self.openai_key) and 20 <= result["risk_score"] < 65:
            opinion = await self._llm_opinion(text)
            if opinion:
                result = self._apply_opinion(result, opinion)
        return result

    # -- rules ---------------------------------------------------------------
    def _rule_based_scan(self, raw_text: str, urls: List[str]) -> Dict[str, Any]:
        text = normalize_text(raw_text)
        factors: List[str] = []
        score = 0

        banks = find_terms(text, BANK_TERMS)
        if banks:
            score += 10
            factors.append("ការលើកឡើងអំពីធនាគារ (Bank mention)")

        if find_terms(text, URGENCY_TERMS):
            score += 20
            factors.append("ភាសាបង្កការភ័យខ្លាច/ប្រញាប់បន្ទាន់ (Urgent / threat language)")

        otp = find_terms(text, OTP_TERMS)
        if otp:
            pts = 40
            if find_terms(text, AWARENESS_TERMS):
                pts = 10  # e.g. "never share your OTP" is a warning, not a request
            score += pts
            factors.append("ការសុំលេខកូដ OTP / ពាក្យសម្ងាត់ (OTP / password request)")

        if find_terms(text, TRANSFER_TERMS):
            score += 20
            factors.append("ការបង្ខំឱ្យផ្ទេរប្រាក់ (Money transfer request)")

        if find_terms(text, SCAM_TRICK_TERMS):
            score += 20
            factors.append("ល្បិចបោកប្រាស់ទូទៅ (Common scam pattern)")

        if urls:
            score += 5
            factors.append(f"មានតំណភ្ជាប់ (Links found): {len(urls)}")
            for url in urls:
                for sig in analyze_url_structure(url):
                    score += sig["score"]
                    factors.append(f"🔗 {sig['reason']}")

        return self._build_result(min(score, 100), factors, urls)

    def _build_result(self, score: int, factors: List[str], urls: List[str]) -> Dict[str, Any]:
        if score >= 65:
            level = "DANGEROUS"
            badge = "🔴 **គ្រោះថ្នាក់ខ្លាំង (Likely scam)**"
            category = "Bank Impersonation / Forced Transfer Scam"
            summary_kh = "សារនេះមានទម្រង់ជាការបោកប្រាស់ ក្លែងបន្លំធនាគារ ឬបង្ខំឱ្យផ្ទេរប្រាក់ប្រកបដោយគ្រោះថ្នាក់!"
            summary_en = "This message exhibits high indicators of financial scam or coercion!"
            recommendation = "កុំចុចតំណភ្ជាប់ កុំផ្តល់លេខកូដ ឬផ្ទេរប្រាក់ ហើយកុំចែករំលែកសារនេះ។"
            steps = [
                "⛔ កុំចុចបើក ឬដំណើរការតំណភ្ជាប់/ឯកសារនេះ។",
                "🚫 Block និង Report គណនីដែលបានផ្ញើ។",
                "🗑️ លុបសារនេះចេញភ្លាមៗ។",
            ]
        elif score >= 35:
            level = "SUSPICIOUS"
            badge = "🟡 សង្ស័យ (SUSPICIOUS)"
            category = "Potential Phishing / Suspicious Offer"
            summary_kh = "សារនេះមានចំណុចសង្ស័យ សូមប្រុងប្រយ័ត្នមុននឹងធ្វើសកម្មភាព។"
            summary_en = "This message contains suspicious language or elements. Proceed with caution."
            recommendation = "⚠️ ផ្ទៀងផ្ទាត់ប្រភពសារជាមុនសិន មុននឹងបន្តធ្វើសកម្មភាព។"
            steps = [
                "🔍 **១. ផ្ទៀងផ្ទាត់ Domain:** ពិនិត្យមើលអាសយដ្ឋាន URL ឬឈ្មោះអ្នកផ្ញើឱ្យបានច្បាស់",
                "📞 **២. ទាក់ទងផ្ទាល់:** ទូរស័ព្ទទៅស្ថាប័នពាក់ព័ន្ធតាមលេខផ្លូវការ",
                "✋ **៣. បង្អាក់ការផ្ទេរ:** ផ្អាកការផ្ទេរប្រាក់រហូតដល់បានផ្ទៀងផ្ទាត់ច្បាស់",
            ]
        else:
            level = "SAFE"
            badge = "🟢 មិនឃើញសញ្ញាគ្រោះថ្នាក់ (No risk detected)"
            category = "Legitimate Content"
            summary_kh = "មិនបានរកឃើញសញ្ញាណបោកប្រាស់ ឬការគំរាមកំហែងនៅក្នុងសារនេះឡើយ។"
            summary_en = "No immediate threat or scam pattern detected in this message."
            recommendation = "✅ មិនឃើញសញ្ញាគ្រោះថ្នាក់ តែនេះមិនមែនជាការធានាទេ។ ត្រូវប្រុងប្រយ័ត្នជាប្រចាំ។"
            steps = [
                "💡 កុំចែករំលែកលេខកូដ OTP ឬពាក្យសម្ងាត់ជាមួយនរណាម្នាក់។",
            ]

        return {
            "risk_score": score,
            "risk_level": level,
            "risk_badge": badge,
            "category": category,
            "summary_kh": summary_kh,
            "summary_en": summary_en,
            "threat_factors": factors,
            "recommendation": recommendation,
            "action_steps": steps,
            "urls_found": urls,
        }

    # -- optional LLM second opinion ---------------------------------------------
    def _apply_opinion(self, result: Dict[str, Any], opinion: str) -> Dict[str, Any]:
        score = result["risk_score"]
        if opinion == "DANGEROUS":
            score = max(score, 65)
        elif opinion == "SUSPICIOUS":
            score = max(score, 35)
        elif opinion == "SAFE":
            has_lookalike = any("Look-alike" in f for f in result["threat_factors"])
            if not has_lookalike:
                score = min(score, 34)
        if score == result["risk_score"]:
            return result
        factors = result["threat_factors"] + [f"🤖 AI second opinion: {opinion}"]
        return self._build_result(score, factors, result["urls_found"])

    async def _llm_opinion(self, text: str) -> Optional[str]:
        """Return SAFE / SUSPICIOUS / DANGEROUS, or None on any failure.
        NOTE: this sends the message text to the configured provider."""
        prompt = (
            "You are a scam-detection assistant for Cambodian Telegram users. "
            "Classify the message below (Khmer or English) as exactly one word: "
            "SAFE, SUSPICIOUS or DANGEROUS. DANGEROUS = clear phishing, bank "
            "impersonation, OTP theft, forced transfer or fake prize/job/investment. "
            "Reply with the single word only.\n\nMESSAGE:\n" + text[:1500]
        )
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                if self.gemini_key:
                    r = await client.post(
                        f"https://generativelanguage.googleapis.com/v1beta/models/{self.gemini_model}:generateContent",
                        headers={"x-goog-api-key": self.gemini_key},
                        json={
                            "contents": [{"parts": [{"text": prompt}]}],
                            "generationConfig": {"temperature": 0, "maxOutputTokens": 5},
                        },
                    )
                    r.raise_for_status()
                    answer = r.json()["candidates"][0]["content"]["parts"][0]["text"]
                else:
                    r = await client.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers={"Authorization": f"Bearer {self.openai_key}"},
                        json={
                            "model": self.openai_model,
                            "temperature": 0,
                            "max_tokens": 5,
                            "messages": [{"role": "user", "content": prompt}],
                        },
                    )
                    r.raise_for_status()
                    answer = r.json()["choices"][0]["message"]["content"]
        except Exception as e:  # network, quota, parse: rules result stands
            logger.warning("LLM second opinion failed: %s", e)
            return None
        answer = answer.strip().upper()
        for label in ("DANGEROUS", "SUSPICIOUS", "SAFE"):
            if answer.startswith(label):
                return label
        return None
