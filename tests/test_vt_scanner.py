import asyncio
import base64

import httpx

from vt_scanner import RateLimiter, TTLCache, VirusTotalScanner


def make_scanner(handler, **kw):
    return VirusTotalScanner(
        api_key="test-key",
        transport=httpx.MockTransport(handler),
        poll_seconds=kw.pop("poll_seconds", 0.05),
        poll_interval=0.01,
        rate_limiter=RateLimiter(1000),
        **kw,
    )


def stats_body(malicious=0, suspicious=0, harmless=60, undetected=10):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected},
        "meaningful_name": "x", "type_description": "Win32 EXE"}}}


def run(coro):
    return asyncio.run(coro)


def test_no_api_key_is_unknown_never_safe():
    s = VirusTotalScanner(api_key="")
    r = run(s.scan_file_hash(b"abc", "setup.exe"))
    assert r["status"] == "UNKNOWN" and r["scanned"] is False
    assert r["high_risk_file_type"] is True
    assert r["total_engines"] == 0  # no invented engine counts
    assert run(s.scan_url("https://example.com"))["status"] == "UNKNOWN"


def test_known_file_verdicts():
    for mal, sus, expected in [(0, 0, "SAFE"), (1, 0, "SUSPICIOUS"), (0, 2, "SUSPICIOUS"), (5, 0, "DANGEROUS")]:
        s = make_scanner(lambda req, m=mal, su=sus: httpx.Response(200, json=stats_body(m, su)))
        r = run(s.scan_file_hash(b"abc", "a.zip"))
        assert r["status"] == expected, (mal, sus, r)
        assert r["scanned"] is True and r["total_engines"] >= 70


def test_http_errors_are_unknown_and_not_cached():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(429)

    s = make_scanner(handler)
    assert run(s.scan_file_hash(b"abc", "a.pdf"))["status"] == "UNKNOWN"
    assert run(s.scan_file_hash(b"abc", "a.pdf"))["status"] == "UNKNOWN"
    assert calls["n"] == 2  # failure was not cached


def test_network_error_is_unknown():
    def handler(req):
        raise httpx.ConnectError("boom")

    r = run(make_scanner(handler).scan_url("https://example.com"))
    assert r["status"] == "UNKNOWN"


def test_unknown_file_is_uploaded_and_polled():
    seen = []

    def handler(req):
        seen.append((req.method, req.url.path))
        if req.method == "GET" and req.url.path.startswith("/api/v3/files/"):
            return httpx.Response(404)
        if req.method == "POST" and req.url.path == "/api/v3/files":
            return httpx.Response(200, json={"data": {"id": "an1"}})
        if req.url.path == "/api/v3/analyses/an1":
            return httpx.Response(200, json={"data": {"attributes": {
                "status": "completed", "stats": {"malicious": 7, "harmless": 50, "undetected": 5}}}})
        return httpx.Response(500)

    r = run(make_scanner(handler).scan_file_hash(b"new malware", "evil.apk"))
    assert r["status"] == "DANGEROUS" and r["malicious_count"] == 7
    assert ("POST", "/api/v3/files") in seen


def test_analysis_timeout_reports_analyzing():
    def handler(req):
        if req.method == "GET" and "/files/" in req.url.path:
            return httpx.Response(404)
        if req.method == "POST":
            return httpx.Response(200, json={"data": {"id": "an1"}})
        return httpx.Response(200, json={"data": {"attributes": {"status": "queued"}}})

    r = run(make_scanner(handler).scan_file_hash(b"x", "a.exe"))
    assert r["status"] == "ANALYZING"


def test_unknown_url_submitted_then_result():
    def handler(req):
        if req.method == "GET" and "/urls/" in req.url.path:
            return httpx.Response(404)
        if req.method == "POST" and req.url.path == "/api/v3/urls":
            return httpx.Response(200, json={"data": {"id": "u1"}})
        return httpx.Response(200, json={"data": {"attributes": {
            "status": "completed", "stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5}}}})

    r = run(make_scanner(handler).scan_url("https://fresh.example"))
    assert r["status"] == "SAFE" and r["scanned"]
    assert base64.urlsafe_b64encode(b"https://fresh.example").decode().strip("=") in r["permalink"]


def test_success_is_cached():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(200, json=stats_body())

    s = make_scanner(handler)
    run(s.scan_file_hash(b"abc", "a.zip"))
    run(s.scan_file_hash(b"abc", "b.zip"))
    assert calls["n"] == 1


def test_large_file_not_claimed_scanned():
    r = VirusTotalScanner(api_key="k").file_too_large_result("big.apk", 50_000_000)
    assert r["status"] == "UNKNOWN" and r["scanned"] is False and "NOT scanned" in r["message"]


def test_ttl_cache_expiry_and_size():
    c = TTLCache(ttl=0, max_items=2)
    c.set("a", {"x": 1})
    assert c.get("a") is None
    c = TTLCache(ttl=100, max_items=2)
    for k in "abc":
        c.set(k, {})
    assert len(c) == 2 and c.get("a") is None


def test_rate_limiter_blocks_over_limit():
    async def go():
        rl = RateLimiter(2)
        return [await rl.acquire(max_wait=0) for _ in range(3)]

    assert run(go()) == [True, True, False]


def test_hash_lookup_known_unknown_and_unconfigured():
    h = "a" * 64
    known = make_scanner(lambda req: httpx.Response(200, json=stats_body(6, 0)))
    r = run(known.lookup_hash(h.upper()))
    assert r["status"] == "DANGEROUS" and r["scanned"] and r["hash_lookup"]

    missing = make_scanner(lambda req: httpx.Response(404))
    r = run(missing.lookup_hash(h))
    assert r["status"] == "UNKNOWN" and r["not_found"] is True  # never "SAFE"

    assert run(VirusTotalScanner(api_key="").lookup_hash(h))["status"] == "UNKNOWN"
