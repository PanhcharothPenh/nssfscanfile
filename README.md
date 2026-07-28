# 🛡️ Security SOC Scan - Telegram AI Security & VirusTotal Scanner Bot

**Security SOC Scan** គឺជាប្រព័ន្ធការពារ និងផ្ទៀងផ្ទាត់សុវត្ថិភាពសារ Telegram ស្វ័យប្រវត្តិ ដោយប្រើប្រាស់ **AI Threat Content Verification Engine** និង **VirusTotal v3 REST API**។

---

## 🌟 លក្ខណៈពិសេសចម្បង (Key Features)

1. **វិភាគផ្ទៀងផ្ទាត់ខ្លឹមសារសារដោយ AI (AI Message Verification):**
   - ស្គាល់យ៉ាងឆ្លាតវៃនូវ **ភាសាគំរាមកំហែងបង្កភ័យ**, **ការក្លែងបន្លំជាធនាគារ (ABA, ACLEDA, Wing, etc.)**, **ការបង្ខំឱ្យផ្ទេរប្រាក់**, **សុំលេខកូដ OTP** និង **ល្បិចបោកប្រាស់ទូទៅ** ទាំងភាសាខ្មែរនិងភាសាអង់គ្លេស។

2. **ស្កេនតំណភ្ជាប់ & ឯកសារគ្រោះថ្នាក់ (VirusTotal v3 API):**
   - ពិនិត្យមើល URL និង ឯកសារប្រភេទ `.APK`, `.EXE`, `.ZIP`, `.PDF` ដែលជនខិលខូចនិយមប្រើដើម្បីបោកប្រាស់ ឬបង្កប់មេរោគ (Malware / Ransomware) លើ Telegram។

3. **ប្រព័ន្ធការពារសម្រាប់ក្រុមពិភាក្សា (Group Chat Protection):**
   - គ្រាន់តែទាញ Bot ចូលទៅក្នុង Group Chat សមាជិកទាំងអស់នឹងមានកន្លែងសុវត្ថិភាពមួយសម្រាប់ផ្ទៀងផ្ទាត់រាល់មាតិកាសង្ស័យ មុននឹងសម្រេចចិត្តចុចបើក។

4. **Web Security SOC Dashboard:**
   - ផ្ទាំងគ្រប់គ្រង SOC Dashboard ទំនើប (Dark Mode, Glassmorphism design) បង្ហាញពីប្រវត្តិនៃការស្កេន ទិន្នន័យ Telemetry និង ឧបករណ៍ធ្វើតេស្តស្កេន (AI Threat Simulator)។

---

## 🚀 របៀបដំឡើង និងដំណើរការ (Quick Start & Installation)

### ១. ទាញយក និងដំឡើង Dependencies
```bash
# ដំឡើង Python dependencies
pip install -r requirements.txt
```

### ២. កំណត់ទិន្នន័យ `.env` (Configuration)
ចម្លងរចនាសម្ព័ន្ធពី `.env.example` ទៅ `.env`៖
```env
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_from_botfather
VIRUSTOTAL_API_KEY=your_virustotal_v3_api_key
OPENAI_API_KEY=optional_openai_key
PORT=8000
HOST=0.0.0.0
```

> **ចំណាំ៖** ប្រសិនបើពុំទាន់មាន VirusTotal API Key ឬ OpenAI Key ប្រព័ន្ធ SOC Scan នឹងប្រើប្រាស់ **SOC Heuristic Security Engine** ដោយស្វ័យប្រវត្តិដើម្បីស្កេននិងធ្វើតេស្ត។

### ៣. ដំណើរការ Web SOC Dashboard & API
```bash
python server.py
```
- បើក Browser ទៅកាន់៖ `http://localhost:8000`

### ៤. ដំណើរការ Telegram Security Bot
```bash
python bot.py
```

---

## 📁 រចនាសម្ព័ន្ធគម្រោង (Project Architecture)

```
Security_SOC_SCAN/
├── bot.py             # Telegram Security Bot (DM & Group Protection)
├── server.py          # FastAPI Server & Web SOC Dashboard API
├── ai_analyzer.py     # AI Threat & Scam Engine (Khmer & English)
├── vt_scanner.py      # VirusTotal v3 REST API Scanner (URL & File SHA-256)
├── database.py        # SQLite Database (Scan logs & Telemetry)
├── config.py          # Global Config & Constants
├── requirements.txt   # Python Dependencies
├── static/            # Web SOC Dashboard UI
│   ├── index.html
│   ├── css/styles.css
│   └── js/app.js
└── README.md          # Project Documentation
```

---

## 🔒 Telegram Group Chat Setup

1. បើក Telegram ហើយស្វែងរក Bot របស់អ្នក។
2. បន្ថែម Bot ចូលទៅក្នុង **Group Chat**។
3. ផ្តល់សិទ្ធិជា **Admin (Optional)** ឬទុកជាសមាជិកធម្មតា។
4. Bot នឹងពិនិត្យនិងស្កេនរាល់សារ, តំណភ្ជាប់ (Links), និង ឯកសារ (`.apk`, `.exe`, `.pdf`) ដែលបានផ្ញើក្នុង Group ដោយស្វ័យប្រវត្តិ!
