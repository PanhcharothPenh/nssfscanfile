from scan_service import UserRateLimiter, combine_risk, format_file_report, format_text_report


def test_file_report_unknown_never_says_safe():
    msg = format_file_report("evil.apk", {
        "status": "UNKNOWN", "scanned": False, "message": "File is larger than 20MB",
        "high_risk_file_type": True, "type_description": "APK"})
    assert "មិនទាន់ត្រូវបានស្កេន" in msg
    assert "🟢" not in msg


def test_reports_escape_html():
    msg = format_file_report("<b>x</b>.zip", {"status": "SAFE", "scanned": True, "total_engines": 70})
    assert "&lt;b&gt;" in msg and "<b>x</b>.zip" not in msg
    text = format_text_report(
        {"risk_level": "SAFE", "summary_kh": "a<b", "threat_factors": ["<script>"], "action_steps": [],
         "recommendation": "r"}, [])
    assert "<script>" not in text


def test_reports_fit_telegram_limit():
    ai = {"risk_level": "DANGEROUS", "summary_kh": "x" * 6000, "threat_factors": [], "action_steps": [],
          "recommendation": ""}
    assert len(format_text_report(ai, [])) <= 4000


def test_combine_risk():
    assert combine_risk("SAFE", [{"status": "DANGEROUS"}]) == "DANGEROUS"
    assert combine_risk("SAFE", [{"status": "SUSPICIOUS"}]) == "SUSPICIOUS"
    assert combine_risk("SAFE", [{"status": "UNKNOWN"}]) == "SAFE"
    assert combine_risk("DANGEROUS", [{"status": "SAFE"}]) == "DANGEROUS"


def test_user_rate_limiter():
    rl = UserRateLimiter(2)
    assert [rl.allow(1), rl.allow(1), rl.allow(1), rl.allow(2)] == [True, True, False, True]


def test_large_file_report_explains_hash_workflow():
    from vt_scanner import VirusTotalScanner
    msg = format_file_report("big.rar", VirusTotalScanner(api_key="k").file_too_large_result("big.rar", 30_000_000))
    assert "certutil" in msg and "/hash" in msg and "🟢" not in msg


def test_hash_not_found_says_not_safe():
    msg = format_file_report("x", {"status": "UNKNOWN", "scanned": False, "not_found": True})
    assert "មិនមែន" in msg and "🟢" not in msg
