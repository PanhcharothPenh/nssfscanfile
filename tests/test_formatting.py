from scan_service import UserRateLimiter, combine_risk, format_file_report, format_text_report


def test_file_report_unknown_never_says_safe():
    msg = format_file_report("evil.apk", {
        "status": "UNKNOWN", "scanned": False, "message": "File is larger than 20MB",
        "high_risk_file_type": True, "type_description": "APK"})
    assert "ព្រមាន" in msg
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
    assert "virustotal.com" in msg and "SHA-256" in msg and "🟢" not in msg


def test_hash_not_found_says_not_safe():
    msg = format_file_report("x", {"status": "UNKNOWN", "scanned": False, "not_found": True})
    assert "មិនមែន" in msg and "🟢" not in msg


def test_large_archive_gets_type_warning_but_never_safe():
    from vt_scanner import VirusTotalScanner
    msg = format_file_report("a.rar", VirusTotalScanner(api_key="k").file_too_large_result("a.rar", 30_000_000))
    assert "ហេតុផលនៃការព្រមាន" in msg and "🟢" not in msg


def test_disguised_archive_gets_warning_not_a_verdict():
    from scan_service import filename_warnings
    from vt_scanner import VirusTotalScanner
    name = "លិខិតអញ្ជើញ_.pdf.rar"
    w = filename_warnings(name)
    assert w["high"] and len(w["reasons"]) >= 2
    msg = format_file_report(name, VirusTotalScanner(api_key="k").file_too_large_result(name, 30_000_000))
    assert "🟠" in msg and "ព្រមាន" in msg and "មិនទាន់" not in msg and "🟢" not in msg and "🔴" not in msg


def test_plain_files_get_no_name_warning():
    from scan_service import filename_warnings
    assert filename_warnings("holiday.mp4") == {"high": False, "reasons": []}
    assert filename_warnings("report.pdf")["high"] is False
    assert filename_warnings("setup.exe")["high"] is True
