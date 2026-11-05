"""VirusTotal v3 scanner.

Design rules (important for a security tool):
  * Never invent a verdict. If VirusTotal cannot be reached, is rate limited,
    or has no answer yet, the status is UNKNOWN / ANALYZING and the result says
    so. Only real engine counts are ever reported.
  * Unknown files/URLs are submitted to VirusTotal and the analysis is polled
    for a limited time, instead of falling back to a guess.
  * Failures are never cached; successful verdicts are cached with a TTL.
"""
import asyncio
import base64
import hashlib
import logging
import os
import time
from collections import OrderedDict, deque
from typing import Any, Dict, Optional

import httpx

from config import (
    CACHE_MAX_ITEMS,
    CACHE_TTL_SECONDS,
    DANGEROUS_EXTENSIONS,
    HIGH_RISK_EXTENSIONS,
    VIRUSTOTAL_API_KEY,
    VT_POLL_SECONDS,
    VT_REQUESTS_PER_MIN,
    VT_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024  # VT /files accepts up to 32MB

# Malicious detections needed for a DANGEROUS verdict. 1-2 detections are often
# false positives, so they are reported as SUSPICIOUS.
DANGEROUS_THRESHOLD = 3


class TTLCache:
    """Small LRU cache with per-item expiry."""

    def __init__(self, ttl: int = CACHE_TTL_SECONDS, max_items: int = CACHE_MAX_ITEMS):
        self.ttl = ttl
        self.max_items = max_items
        self._data: "OrderedDict[str, tuple]" = OrderedDict()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        item = self._data.get(key)
        if not item:
            return None
        expires, value = item
        if expires < time.monotonic():
            self._data.pop(key, None)
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key: str, value: Dict[str, Any]) -> None:
        self._data[key] = (time.monotonic() + self.ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self.max_items:
            self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)


class RateLimiter:
    """Sliding-window limiter: at most per_minute acquisitions per 60 seconds."""

    def __init__(self, per_minute: int):
        self.per_minute = max(1, per_minute)
        self._stamps: "deque[float]" = deque()
        self._lock: Optional[asyncio.Lock] = None

    async def acquire(self, max_wait: float = 20.0) -> bool:
        if self._lock is None:
            self._lock = asyncio.Lock()
        deadline = time.monotonic() + max_wait
        while True:
            async with self._lock:
                now = time.monotonic()
                while self._stamps and now - self._stamps[0] >= 60:
                    self._stamps.popleft()
                if len(self._stamps) < self.per_minute:
                    self._stamps.append(now)
                    return True
                wait = 60 - (now - self._stamps[0])
            if time.monotonic() + wait > deadline:
                return False
            await asyncio.sleep(min(wait, 1.0))


def _verdict(malicious: int, suspicious: int) -> str:
    if malicious >= DANGEROUS_THRESHOLD:
        return "DANGEROUS"
    if malicious > 0 or suspicious > 0:
        return "SUSPICIOUS"
    return "SAFE"


def _counts(stats: Dict[str, int]) -> Dict[str, int]:
    return {
        "malicious_count": stats.get("malicious", 0),
        "suspicious_count": stats.get("suspicious", 0),
        "harmless_count": stats.get("harmless", 0),
        "total_engines": sum(
            stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")
        ),
    }


class VirusTotalScanner:
    def __init__(
        self,
        api_key: Optional[str] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        poll_seconds: float = VT_POLL_SECONDS,
        poll_interval: float = 4.0,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self.api_key = VIRUSTOTAL_API_KEY if api_key is None else api_key
        self.headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        self.cache = TTLCache()
        self.poll_seconds = poll_seconds
        self.poll_interval = poll_interval
        self.limiter = rate_limiter or RateLimiter(VT_REQUESTS_PER_MIN)
        self._transport = transport
        self._client: Optional[httpx.AsyncClient] = None

    # -- plumbing ----------------------------------------------------------
    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=VT_TIMEOUT_SECONDS,
                transport=self._transport,
                limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _request(self, method: str, path: str, **kwargs) -> Optional[httpx.Response]:
        """Rate-limited request. Returns None if the limiter or network fails."""
        if not await self.limiter.acquire():
            logger.warning("VirusTotal local rate limit reached")
            return None
        try:
            return await self._get_client().request(
                method, f"{VT_BASE_URL}{path}", headers=self.headers, **kwargs
            )
        except httpx.HTTPError as e:
            logger.warning("VirusTotal request failed: %s", e)
            return None

    @staticmethod
    def _unknown(reason: str, **extra) -> Dict[str, Any]:
        res = {
            "scanned": False,
            "provider": "VirusTotal v3 API",
            "status": "UNKNOWN",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "total_engines": 0,
            "message": reason,
        }
        res.update(extra)
        return res

    async def _poll_analysis(self, analysis_id: str) -> Optional[Dict[str, int]]:
        """Wait (bounded) for an analysis to complete. Returns stats or None."""
        waited = 0.0
        while waited <= self.poll_seconds:
            resp = await self._request("GET", f"/analyses/{analysis_id}")
            if resp is not None and resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                if attrs.get("status") == "completed":
                    return attrs.get("stats", {})
            await asyncio.sleep(self.poll_interval)
            waited += max(self.poll_interval, 0.001)
        return None

    @staticmethod
    def _http_reason(resp: Optional[httpx.Response]) -> str:
        if resp is None:
            return "Could not reach VirusTotal (network error or local rate limit)."
        if resp.status_code == 429:
            return "VirusTotal rate limit reached. Please try again in a minute."
        if resp.status_code in (401, 403):
            return "VirusTotal rejected the API key."
        return f"VirusTotal returned HTTP {resp.status_code}."

    @staticmethod
    def _type_hint(ext: str) -> Dict[str, Any]:
        """Honest file-type information. This is NOT a malware verdict."""
        return {
            "type_description": DANGEROUS_EXTENSIONS.get(ext, "File"),
            "risky_file_type": ext in DANGEROUS_EXTENSIONS,
            "high_risk_file_type": ext in HIGH_RISK_EXTENSIONS,
        }

    # -- URLs --------------------------------------------------------------
    async def scan_url(self, url: str) -> Dict[str, Any]:
        cache_key = f"url:{url}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        if not self.api_key:
            return self._unknown("VirusTotal is not configured.", target=url)

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        permalink = f"https://www.virustotal.com/gui/url/{url_id}"

        resp = await self._request("GET", f"/urls/{url_id}")
        attrs: Dict[str, Any] = {}

        if resp is not None and resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
        elif resp is not None and resp.status_code == 404:
            # Never seen before: submit and wait a bounded time for the result.
            sub = await self._request("POST", "/urls", data={"url": url})
            if sub is None or sub.status_code != 200:
                return self._unknown(self._http_reason(sub), target=url)
            analysis_id = sub.json().get("data", {}).get("id", "")
            stats = await self._poll_analysis(analysis_id) if analysis_id else None
            if stats is None:
                return {
                    **self._unknown(
                        "URL submitted to VirusTotal; analysis not finished yet. Try again in a minute.",
                        target=url,
                    ),
                    "status": "ANALYZING",
                    "permalink": permalink,
                }
        else:
            return self._unknown(self._http_reason(resp), target=url)

        res = {
            "scanned": True,
            "provider": "VirusTotal v3 API",
            "target": url,
            "status": _verdict(stats.get("malicious", 0), stats.get("suspicious", 0)),
            "categories": attrs.get("categories", {}),
            "reputation": attrs.get("reputation", 0),
            "permalink": permalink,
            **_counts(stats),
        }
        self.cache.set(cache_key, res)
        return res

    # -- Files -------------------------------------------------------------
    async def scan_file_hash(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """Look up by SHA-256; upload the file if VirusTotal has never seen it."""
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        ext = os.path.splitext(filename)[1].lower()
        cache_key = f"file:{sha256}"
        cached = self.cache.get(cache_key)
        if cached:
            return {**cached, "filename": filename}

        base = {"filename": filename, "sha256": sha256}
        permalink = f"https://www.virustotal.com/gui/file/{sha256}"

        if not self.api_key:
            return self._unknown("VirusTotal is not configured.", **base, **self._type_hint(ext))

        resp = await self._request("GET", f"/files/{sha256}")
        attrs: Dict[str, Any] = {}

        if resp is not None and resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
        elif resp is not None and resp.status_code == 404:
            if len(file_bytes) > VT_DIRECT_UPLOAD_LIMIT:
                return self._unknown(
                    "File is too large to upload to VirusTotal and is not in its database.",
                    **base, **self._type_hint(ext),
                )
            up = await self._request("POST", "/files", files={"file": (filename, file_bytes)})
            if up is None or up.status_code != 200:
                return self._unknown(self._http_reason(up), **base, **self._type_hint(ext))
            analysis_id = up.json().get("data", {}).get("id", "")
            stats = await self._poll_analysis(analysis_id) if analysis_id else None
            if stats is None:
                return {
                    **self._unknown(
                        "File uploaded to VirusTotal; analysis not finished yet. Try again in a minute.",
                        **base, **self._type_hint(ext),
                    ),
                    "status": "ANALYZING",
                    "permalink": permalink,
                }
        else:
            return self._unknown(self._http_reason(resp), **base, **self._type_hint(ext))

        res = {
            "scanned": True,
            "provider": "VirusTotal v3 API",
            **base,
            "status": _verdict(stats.get("malicious", 0), stats.get("suspicious", 0)),
            "meaningful_name": attrs.get("meaningful_name", filename),
            "type_description": attrs.get("type_description", "File"),
            "permalink": permalink,
            **_counts(stats),
        }
        self.cache.set(cache_key, res)
        return res

    def file_too_large_result(self, filename: str, size: int) -> Dict[str, Any]:
        """Telegram bots cannot download files >20MB, so nothing can be scanned."""
        ext = os.path.splitext(filename)[1].lower()
        return self._unknown(
            "File is larger than 20MB, so it could not be downloaded and was NOT scanned.",
            filename=filename, file_size=size, **self._type_hint(ext),
        )
