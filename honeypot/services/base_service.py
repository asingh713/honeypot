"""Abstract base that all honeypot services inherit from."""

from __future__ import annotations

import collections
import time
import threading
from abc import ABC, abstractmethod
from typing import Dict, Tuple

from honeypot.core.database import Database, EventData
from honeypot.core.geo import GeoLookup
from honeypot.core import logger as _logger


class BaseService(ABC):
    service_name: str = ""

    def __init__(self, db: Database, geo: GeoLookup, max_events_per_ip_per_minute: int = 30) -> None:
        self._db = db
        self._geo = geo
        self._rate_limit = max_events_per_ip_per_minute
        self._log = _logger.get(self.service_name or self.__class__.__name__.lower())
        # {ip: deque of timestamps}
        self._ip_counts: Dict[str, collections.deque] = {}
        self._lock = threading.Lock()

    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    def _is_rate_limited(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if ip not in self._ip_counts:
                self._ip_counts[ip] = collections.deque()
            dq = self._ip_counts[ip]
            # Drop entries older than 60 seconds
            while dq and now - dq[0] > 60:
                dq.popleft()
            if len(dq) >= self._rate_limit:
                return True
            dq.append(now)
            return False

    def record(self, event: EventData) -> None:
        """Write an event to the DB (with geo enrichment) unless rate-limited."""
        if self._is_rate_limited(event.src_ip):
            self._log.debug("Rate-limited event from %s", event.src_ip)
            return

        geo = self._geo.lookup(event.src_ip)
        self._log.info(
            "service=%s ip=%s port=%s user=%s pass=%s cmd=%s path=%s geo=%s/%s",
            event.service, event.src_ip, event.src_port,
            event.username, event.password, event.command,
            event.http_path,
            geo.country_code, geo.city,
        )
        self._db.insert_event(event)
