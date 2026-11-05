import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_TOKEN", "admin-secret")
    monkeypatch.setenv("WEBHOOK_SECRET", "hook-secret")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setenv("SUPABASE_URL", "")
    import config, database, scan_service, vt_scanner, ai_analyzer  # noqa: F401
    for m in (config, database, scan_service, vt_scanner, ai_analyzer):
        importlib.reload(m)
    import server
    importlib.reload(server)
    return TestClient(server.app)


AUTH = {"Authorization": "Bearer admin-secret"}


def test_api_requires_token(client):
    for path in ("/api/stats", "/api/scans", "/api/users"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.get(path, headers=AUTH).status_code == 200
    assert client.post("/api/scan/text", json={"text": "hi"}).status_code == 401
    assert client.post("/api/set_webhook").status_code == 401


def test_webhook_needs_telegram_secret(client):
    assert client.post("/api/webhook", json={}).status_code == 403
    assert client.post("/api/webhook", json={}, headers={"X-Telegram-Bot-Api-Secret-Token": "bad"}).status_code == 403
    ok = client.post("/api/webhook", json={}, headers={"X-Telegram-Bot-Api-Secret-Token": "hook-secret"})
    assert ok.status_code == 200


def test_scan_text_and_stats_roundtrip(client):
    r = client.post("/api/scan/text", headers=AUTH, json={
        "text": "URGENT ABA account suspended, send OTP https://aba-verify.xyz"})
    assert r.status_code == 200
    body = r.json()
    assert body["highest_risk"] in ("SUSPICIOUS", "DANGEROUS")
    # VirusTotal not configured -> honest UNKNOWN, not a fake verdict
    assert all(v["status"] == "UNKNOWN" for v in body["vt_reports"])
    stats = client.get("/api/stats", headers=AUTH).json()
    assert stats["total_scans"] == 1


def test_message_text_not_stored_by_default(client):
    secret = "my private message about lunch"
    client.post("/api/scan/text", headers=AUTH, json={"text": secret})
    logs = client.get("/api/scans", headers=AUTH).json()
    assert secret not in logs[0]["input_summary"]
    assert logs[0]["input_summary"].startswith("[msg ")


def test_upload_size_limit(client, monkeypatch):
    import server
    monkeypatch.setattr(server, "MAX_UPLOAD_BYTES", 1024)
    r = client.post("/api/scan/file", headers=AUTH, files={"file": ("a.zip", b"x" * 2048)})
    assert r.status_code == 413
    r = client.post("/api/scan/file", headers=AUTH, files={"file": ("a.zip", b"x" * 10)})
    assert r.status_code == 200 and r.json()["risk_level"] == "UNKNOWN"


def test_rate_limit(client, monkeypatch):
    import server
    from scan_service import UserRateLimiter
    monkeypatch.setattr(server, "web_rate_limiter", UserRateLimiter(2))
    codes = [client.post("/api/scan/text", headers=AUTH, json={"text": "hello"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_no_admin_token_configured_disables_api(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_TOKEN", "")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "t.db"))
    import config, server
    importlib.reload(config)
    importlib.reload(server)
    assert TestClient(server.app).get("/api/stats").status_code == 503
