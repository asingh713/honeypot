"""IP geolocation via ip-api.com with SQLite caching and token-bucket rate limiting."""

from __future__ import annotations

import ipaddress
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

import requests

from honeypot.core.database import Database, GeoData
from honeypot.core import logger as _logger

log = _logger.get("geo")

# RFC 1918 + loopback + link-local prefixes that we never look up
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_GEO_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,as,lat,lon,query"


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


class _TokenBucket:
    """Simple token-bucket rate limiter (thread-safe)."""

    def __init__(self, rate_per_minute: int) -> None:
        self._rate = rate_per_minute / 60.0   # tokens per second
        self._tokens = float(rate_per_minute)
        self._max = float(rate_per_minute)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def consume(self) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self._max, self._tokens + elapsed * self._rate)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


class GeoLookup:
    """Geo-locate IPs with caching and rate limiting."""

    def __init__(self, db: Database, cache_ttl_hours: int = 24, rate_per_minute: int = 40) -> None:
        self._db = db
        self._ttl = timedelta(hours=cache_ttl_hours)
        self._bucket = _TokenBucket(rate_per_minute)

    def lookup(self, ip: str) -> GeoData:
        if _is_private(ip):
            return GeoData(ip=ip, country="Private Network", country_code="--")

        # Check cache first
        cached = self._db.get_geo(ip)
        if cached:
            cached_at_str = self._db._local.conn.execute(
                "SELECT cached_at FROM geo_cache WHERE ip = ?", (ip,)
            ).fetchone()
            if cached_at_str:
                try:
                    cached_at = datetime.fromisoformat(cached_at_str[0])
                    if cached_at.tzinfo is None:
                        cached_at = cached_at.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) - cached_at < self._ttl:
                        return cached
                except (ValueError, TypeError):
                    pass

        # Rate limit check
        if not self._bucket.consume():
            log.debug("Geo rate limit hit for %s; returning cached or empty", ip)
            return cached or GeoData(ip=ip)

        # Live fetch
        try:
            resp = requests.get(_GEO_URL.format(ip=ip), timeout=5)
            data = resp.json()
            if data.get("status") != "success":
                log.warning("Geo lookup failed for %s: %s", ip, data.get("message"))
                return cached or GeoData(ip=ip)

            geo = GeoData(
                ip=ip,
                country=data.get("country"),
                country_code=data.get("countryCode"),
                region=data.get("regionName"),
                city=data.get("city"),
                isp=data.get("isp"),
                asn=data.get("as"),
                lat=data.get("lat"),
                lon=data.get("lon"),
            )
            self._db.upsert_geo(geo)
            return geo

        except requests.RequestException as exc:
            log.warning("Geo HTTP error for %s: %s", ip, exc)
            return cached or GeoData(ip=ip)
