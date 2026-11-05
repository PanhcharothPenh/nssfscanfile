import asyncio

import pytest

from ai_analyzer import AIThreatAnalyzer, analyze_url_structure, extract_urls, normalize_text


def analyze(text, **kw):
    return asyncio.run(AIThreatAnalyzer().analyze_message(text, **kw))


SCAMS = [
    "URGENT: your ABA account is suspended. Send your OTP now at https://aba-bank-verify.com/login",
    "⚠️ ជូនដំណឹងបន្ទាន់ពីធនាគារ ABA! គណនីរបស់អ្នកត្រូវបានបិទគណនី សូមផ្ញើលេខកូដ OTP និងផ្ទេរប្រាក់ https://aba-bank-verify.com",
    "Police court penalty: transfer money $500 within 24 hours or you will be arrested",
]

SAFE = [
    "Hey, are you free for coffee at 3pm?",
    "I updated the database schema and pushed the code to the repo.",   # 'aba' in 'database', 'code'
    "The job interview is on Monday, free parking is available.",
    "ជំរាបសួរមិត្តភក្តិ! តើថ្ងៃនេះទំនេរទេ? ពួកយើងអាចជួបគ្នាញ៉ាំកាហ្វេបានទេ?",
]


@pytest.mark.parametrize("text", SCAMS)
def test_scams_are_flagged(text):
    r = analyze(text)
    assert r["risk_level"] in ("SUSPICIOUS", "DANGEROUS"), r
    assert r["risk_level"] == "DANGEROUS" or r["risk_score"] >= 35


def test_obvious_scams_are_dangerous():
    assert analyze(SCAMS[0])["risk_level"] == "DANGEROUS"
    assert analyze(SCAMS[1])["risk_level"] == "DANGEROUS"


@pytest.mark.parametrize("text", SAFE)
def test_normal_messages_not_flagged(text):
    r = analyze(text)
    assert r["risk_level"] == "SAFE", r


def test_zero_width_characters_do_not_evade_detection():
    sneaky = "Send your O​T​P and tran​sfer money, urgent, ABA bank https://aba-verify.xyz"
    assert analyze(sneaky)["risk_level"] in ("SUSPICIOUS", "DANGEROUS")
    assert normalize_text("O​TP") == "otp"


def test_warning_about_otp_is_not_a_request():
    r = analyze("ABA Bank reminder: never share your OTP with anyone.")
    assert r["risk_level"] == "SAFE", r


def test_lookalike_domain_detected_but_official_is_not():
    assert any("Look-alike" in s["reason"] for s in analyze_url_structure("https://aba-login-kh.com"))
    assert not analyze_url_structure("https://www.ababank.com/personal")
    assert not any("Look-alike" in s["reason"] for s in analyze_url_structure("https://database.com"))


def test_url_signals():
    assert analyze_url_structure("http://192.168.1.5/login")
    assert analyze_url_structure("https://bit.ly/abc")
    assert analyze_url_structure("https://xn--abbank-9ua.com")


def test_extract_urls_normalises_and_dedupes():
    urls = extract_urls("see www.example.com, https://example.org/x. and bit.ly/abc", ["https://hidden.example/x"])
    assert "https://www.example.com" in urls
    assert "https://example.org/x" in urls
    assert "https://bit.ly/abc" in urls
    assert "https://hidden.example/x" in urls
    assert len(urls) == len(set(u.lower() for u in urls))


def test_empty_message_is_safe():
    assert analyze("   ")["risk_level"] == "SAFE"


def test_llm_opinion_can_escalate_borderline(monkeypatch):
    a = AIThreatAnalyzer()
    a.openai_key = "x"

    async def fake(text):
        return "DANGEROUS"

    monkeypatch.setattr(a, "_llm_opinion", fake)
    # bank + urgency + invest = borderline by rules
    text = "ABA bank urgent invest now"
    base = asyncio.run(AIThreatAnalyzer().analyze_message(text))
    assert base["risk_level"] != "DANGEROUS"
    assert asyncio.run(a.analyze_message(text))["risk_level"] == "DANGEROUS"
