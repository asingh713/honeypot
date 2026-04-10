"""SQLite database: schema creation, event writes, and query helpers."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional


@dataclass
class EventData:
    service: str          # "ssh" | "http" | "telnet"
    src_ip: str
    src_port: int
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    http_path: Optional[str] = None
    http_method: Optional[str] = None
    http_ua: Optional[str] = None
    session_id: Optional[str] = None


@dataclass
class GeoData:
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None


_CREATE_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    service     TEXT    NOT NULL,
    src_ip      TEXT    NOT NULL,
    src_port    INTEGER,
    username    TEXT,
    password    TEXT,
    command     TEXT,
    http_path   TEXT,
    http_method TEXT,
    http_ua     TEXT,
    session_id  TEXT
);
"""

_CREATE_GEO = """
CREATE TABLE IF NOT EXISTS geo_cache (
    ip           TEXT PRIMARY KEY,
    country      TEXT,
    country_code TEXT,
    region       TEXT,
    city         TEXT,
    isp          TEXT,
    asn          TEXT,
    lat          REAL,
    lon          REAL,
    cached_at    TEXT NOT NULL
);
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_events_src_ip    ON events(src_ip);",
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_events_service   ON events(service);",
    "CREATE INDEX IF NOT EXISTS idx_events_session   ON events(session_id);",
]


class Database:
    """Thread-safe SQLite wrapper for honeypot events."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._local = threading.local()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        # Initialise schema on a dedicated connection
        with self._conn() as conn:
            conn.execute(_CREATE_EVENTS)
            conn.execute(_CREATE_GEO)
            for idx in _CREATE_INDEXES:
                conn.execute(idx)
            conn.commit()

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        yield self._local.conn

    # ------------------------------------------------------------------ writes

    def insert_event(self, event: EventData) -> int:
        sql = """
        INSERT INTO events
            (timestamp, service, src_ip, src_port, username, password,
             command, http_path, http_method, http_ua, session_id)
        VALUES
            (:timestamp, :service, :src_ip, :src_port, :username, :password,
             :command, :http_path, :http_method, :http_ua, :session_id)
        """
        with self._conn() as conn:
            cur = conn.execute(sql, {
                "timestamp":   event.timestamp,
                "service":     event.service,
                "src_ip":      event.src_ip,
                "src_port":    event.src_port,
                "username":    event.username,
                "password":    event.password,
                "command":     event.command,
                "http_path":   event.http_path,
                "http_method": event.http_method,
                "http_ua":     event.http_ua,
                "session_id":  event.session_id,
            })
            conn.commit()
            return cur.lastrowid

    def upsert_geo(self, geo: GeoData) -> None:
        sql = """
        INSERT INTO geo_cache
            (ip, country, country_code, region, city, isp, asn, lat, lon, cached_at)
        VALUES
            (:ip, :country, :country_code, :region, :city, :isp, :asn, :lat, :lon, :cached_at)
        ON CONFLICT(ip) DO UPDATE SET
            country=excluded.country, country_code=excluded.country_code,
            region=excluded.region, city=excluded.city, isp=excluded.isp,
            asn=excluded.asn, lat=excluded.lat, lon=excluded.lon,
            cached_at=excluded.cached_at
        """
        with self._conn() as conn:
            conn.execute(sql, {
                "ip":           geo.ip,
                "country":      geo.country,
                "country_code": geo.country_code,
                "region":       geo.region,
                "city":         geo.city,
                "isp":          geo.isp,
                "asn":          geo.asn,
                "lat":          geo.lat,
                "lon":          geo.lon,
                "cached_at":    datetime.now(timezone.utc).isoformat(),
            })
            conn.commit()

    # ------------------------------------------------------------------ reads

    def get_geo(self, ip: str) -> Optional[GeoData]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM geo_cache WHERE ip = ?", (ip,)
            ).fetchone()
        if not row:
            return None
        return GeoData(
            ip=row["ip"], country=row["country"], country_code=row["country_code"],
            region=row["region"], city=row["city"], isp=row["isp"],
            asn=row["asn"], lat=row["lat"], lon=row["lon"],
        )

    def get_events(
        self,
        service: Optional[str] = None,
        src_ip: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        page: int = 1,
        per_page: int = 50,
    ) -> List[Dict[str, Any]]:
        clauses, params = [], []
        if service:
            clauses.append("service = ?")
            params.append(service)
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        if until:
            clauses.append("timestamp <= ?")
            params.append(until)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        offset = (page - 1) * per_page
        sql = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params += [per_page, offset]

        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count_events(
        self,
        service: Optional[str] = None,
        src_ip: Optional[str] = None,
        since: Optional[str] = None,
    ) -> int:
        clauses, params = [], []
        if service:
            clauses.append("service = ?")
            params.append(service)
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._conn() as conn:
            return conn.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]

    def get_stats(self) -> Dict[str, Any]:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00")
        week_ago = datetime.now(timezone.utc)
        # simple week start
        from datetime import timedelta
        week_start = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()

        with self._conn() as conn:
            total        = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            today_count  = conn.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (today,)).fetchone()[0]
            week_count   = conn.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (week_start,)).fetchone()[0]
            unique_ips   = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events").fetchone()[0]
            by_service   = conn.execute(
                "SELECT service, COUNT(*) as n FROM events GROUP BY service"
            ).fetchall()
            top_ips      = conn.execute(
                "SELECT src_ip, COUNT(*) as n FROM events GROUP BY src_ip ORDER BY n DESC LIMIT 10"
            ).fetchall()
            top_users    = conn.execute(
                "SELECT username, COUNT(*) as n FROM events WHERE username IS NOT NULL "
                "GROUP BY username ORDER BY n DESC LIMIT 10"
            ).fetchall()
            top_passwords = conn.execute(
                "SELECT password, COUNT(*) as n FROM events WHERE password IS NOT NULL "
                "GROUP BY password ORDER BY n DESC LIMIT 10"
            ).fetchall()

        return {
            "total":          total,
            "today":          today_count,
            "last_7_days":    week_count,
            "unique_ips":     unique_ips,
            "by_service":     {r["service"]: r["n"] for r in by_service},
            "top_ips":        [{"ip": r["src_ip"], "count": r["n"]} for r in top_ips],
            "top_usernames":  [{"username": r["username"], "count": r["n"]} for r in top_users],
            "top_passwords":  [{"password": r["password"], "count": r["n"]} for r in top_passwords],
        }

    def get_geo_points(self) -> List[Dict[str, Any]]:
        """Return GeoJSON-ready points for all geo-located IPs that attacked us."""
        sql = """
        SELECT g.lat, g.lon, g.city, g.country, g.isp, e.src_ip,
               COUNT(e.id) as attack_count
        FROM geo_cache g
        JOIN events e ON e.src_ip = g.ip
        WHERE g.lat IS NOT NULL AND g.lon IS NOT NULL
        GROUP BY e.src_ip
        """
        with self._conn() as conn:
            rows = conn.execute(sql).fetchall()
        return [dict(r) for r in rows]
