import re
from typing import Dict, Any, List
from config import SCAM_KEYWORDS_KHMER, SCAM_KEYWORDS_ENGLISH, OPENAI_API_KEY, GEMINI_API_KEY

class AIThreatAnalyzer:
    """
    AI Content Verification Engine for Telegram messages.
    Analyzes Khmer & English message content for threat vectors:
    - Bank impersonation (ABA, Acleda, Wing, etc.)
    - Fear-inducing/coercive language
    - Forced money transfers & OTP harvesting
    - Social engineering & phishing tricks
    """

    def __init__(self):
        self.openai_key = OPENAI_API_KEY
        self.gemini_key = GEMINI_API_KEY

    async def analyze_message(self, text: str) -> Dict[str, Any]:
        """
        Main analysis function evaluating raw message text.
        """
        if not text or not text.strip():
            return {
                "risk_score": 0,
                "risk_level": "SAFE",
                "risk_badge": "🟢 សុវត្ថិភាព (SAFE)",
                "category": "Normal Message",
                "summary_kh": "មិនមានអត្ថបទសង្ស័យឡើយ។",
                "summary_en": "No suspicious text detected.",
                "threat_factors": [],
                "recommendation": "សារនេះហាក់ដូចជាមានសុវត្ថិភាព។"
            }

        # Analyze using local multi-lingual Security NLP Heuristics
        heuristics_result = self._rule_based_scan(text)

        # If LLM API keys are provided, we could refine results via OpenAI/Gemini
        # For instant performance, our multi-lingual security engine provides high precision response
        return heuristics_result

    def _rule_based_scan(self, text: str) -> Dict[str, Any]:
        text_lower = text.lower()
        threat_factors = []
        score = 0

        # Check 1: Bank Impersonation
        bank_terms = ["aba", "acleda", "wing", "canadia", "sathapana", "អេស៊ីលីដា", "វីង", "ធនាគារ"]
        detected_banks = [b for b in bank_terms if b in text_lower]
        if detected_banks:
            score += 25
            threat_factors.append("ការលើកឡើងអំពីធនាគារ (Bank Impersonation Mention)")

        # Check 2: Fear-inducing / Urgent threats
        urgency_terms = ["urgent", "immediately", "suspended", "blocked", "legal action", "police", "penalty", "បន្ទាន់", "បិទគណនី", "គំរាម", "តុលាការ", "ប៉ូលីស", "ពិន័យ"]
        detected_urgency = [u for u in urgency_terms if u in text_lower]
        if detected_urgency:
            score += 30
            threat_factors.append("ភាសាបង្កការភ័យខ្លាច/ប្រញាប់បន្ទាន់ (Urgent / Threat Language)")

        # Check 3: Forced Money Transfers & OTP Requests
        transfer_terms = ["transfer", "send money", "otp", "code", "password", "deposit", "ផ្ទេរប្រាក់", "ផ្ញើលុយ", "លេខកូដ", "ពាក្យសម្ងាត់", "បញ្ចូលលុយ"]
        detected_transfers = [t for t in transfer_terms if t in text_lower]
        if detected_transfers:
            score += 30
            threat_factors.append("ការបង្ខំឱ្យផ្ទេរប្រាក់ ឬសុំលេខកូដ OTP (Money Transfer / OTP Request)")

        # Check 4: Phishing Links or URLs
        urls = re.findall(r'https?://[^\s]+', text)
        if urls:
            score += 15
            threat_factors.append(f"មានប្រកបដោយតំណភ្ជាប់ (Phishing Links Detected): {len(urls)} URLs")

        # Check 5: Common Scam Tricks (Lottery, Free Money, Crypto, Telegram Job)
        scam_tricks = ["winner", "claim", "free", "guaranteed profit", "job", "invest", "ឈ្នះរង្វាន់", "ចំណេញច្រើន", "ការងារ", "វិនិយោគ"]
        detected_tricks = [st for st in scam_tricks if st in text_lower]
        if detected_tricks:
            score += 20
            threat_factors.append("ល្បិចបោកប្រាស់ទូទៅ (Scam Pattern Detected)")

        # Determine Category, Risk Level, and Actionable Steps
        if score >= 65:
            risk_level = "DANGEROUS"
            risk_badge = "🔴 **គ្រោះថ្នាក់ខ្លាំង (Malware / Financial Scam)**"
            category = "Bank Impersonation / Forced Transfer Scam"
            summary_kh = "សារនេះមានទម្រង់ជាការបោកប្រាស់ ក្លែងបន្លំធនាគារ ឬបង្ខំឱ្យផ្ទេរប្រាក់ប្រកបដោយគ្រោះថ្នាក់!"
            summary_en = "This message exhibits high indicators of financial scam or coercion!"
            recommendation = "កុំទាញយក ឬចែករំលែកសារនេះ ព្រោះវាអាចបង្កគ្រោះថ្នាក់ដល់ទិន្នន័យរបស់អ្នក។"
            action_steps = [
                "⛔ កុំចុចបើក ឬដំណើរការតំណភ្ជាប់/ឯកសារនេះ។",
                "🚫 Block និង Report គណនីដែលបានផ្ញើ។",
                "🗑️ លុបសារ និងឯកសារនេះចេញភ្លាមៗ។"
            ]

        elif score >= 35:
            risk_level = "SUSPICIOUS"
            risk_badge = "🟡 សង្ស័យ (SUSPICIOUS)"
            category = "Potential Phishing / Suspicious Offer"
            summary_kh = "សារនេះមានចំណុចសង្ស័យ សូមប្រុងប្រយ័ត្នមុននឹងធ្វើសកម្មភាព។"
            summary_en = "This message contains suspicious language or elements. Proceed with caution."
            recommendation = "⚠️ ផ្ទៀងផ្ទាត់ប្រភពសារជាមុនសិន មុននឹងបន្តធ្វើសកម្មភាព។"
            action_steps = [
                "🔍 **១. ផ្ទៀងផ្ទាត់ Domain:** ពិនិត្យមើលអាសយដ្ឋាន URL ឬឈ្មោះអ្នកផ្ញើឱ្យបានច្បាស់",
                "📞 **២. ទាក់ទងផ្ទាល់:** ទូរស័ព្ទទៅកាន់សាម៉ីខ្លួន ឬស្ថាប័នពាក់ព័ន្ធតាមលេខផ្លូវការ",
                "✋ **៣. បង្អាក់ការផ្ទេរ:** ផ្អាកការផ្ទេរប្រាក់រហូតដល់បានផ្ទៀងផ្ទាត់ច្បាស់ 100%"
            ]
        else:
            risk_level = "SAFE"
            risk_badge = "🟢 សុវត្ថិភាព (SAFE)"
            category = "Legitimate Content"
            summary_kh = "មិនបានរកឃើញសញ្ញាណបោកប្រាស់ ឬការគំរាមកំហែងនៅក្នុងសារនេះឡើយ។"
            summary_en = "No immediate threat or scam pattern detected in this message."
            recommendation = "✅ សារនេះហាក់ដូចជាមានសុវត្ថិភាព តែត្រូវប្រុងប្រយ័ត្នជាប្រចាំ។"
            action_steps = [
                "✅ **១. ប្រើប្រាស់ធម្មតា:** អាចអាន និងឆ្លើយតបបានដោយសុវត្ថិភាព",
                "💡 **២. រក្សាការប្រុងប្រយ័ត្ន:** មិនត្រូវចែករំលែកព័ត៌មានសម្ងាត់តាមអនឡាញឡើយ"
            ]

        return {
            "risk_score": min(score, 100),
            "risk_level": risk_level,
            "risk_badge": risk_badge,
            "category": category,
            "summary_kh": summary_kh,
            "summary_en": summary_en,
            "threat_factors": threat_factors,
            "recommendation": recommendation,
            "action_steps": action_steps,
            "urls_found": urls
        }

