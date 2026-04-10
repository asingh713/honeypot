"""Load and validate configuration from config.yaml with env var overrides."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml


@dataclass(frozen=True)
class TrapCredential:
    username: str
    password: str


@dataclass(frozen=True)
class SSHConfig:
    enabled: bool
    port: int
    banner: str
    trap_credentials: List[TrapCredential]
    auth_fail_delay: float
    max_session_commands: int
    session_timeout: int


@dataclass(frozen=True)
class HTTPConfig:
    enabled: bool
    port: int
    server_header: str
    x_powered_by: str
    persona: str


@dataclass(frozen=True)
class TelnetConfig:
    enabled: bool
    port: int
    auth_fail_delay: float
    trap_credentials: List[TrapCredential]


@dataclass(frozen=True)
class DashboardConfig:
    enabled: bool
    port: int
    host: str


@dataclass(frozen=True)
class GeoConfig:
    enabled: bool
    cache_ttl_hours: int
    rate_limit_per_minute: int


@dataclass(frozen=True)
class LoggingConfig:
    level: str
    file: str
    max_bytes: int
    backup_count: int


@dataclass(frozen=True)
class RateLimitConfig:
    max_events_per_ip_per_minute: int


@dataclass(frozen=True)
class DatabaseConfig:
    path: str


@dataclass(frozen=True)
class Config:
    ssh: SSHConfig
    http: HTTPConfig
    telnet: TelnetConfig
    dashboard: DashboardConfig
    geo: GeoConfig
    logging: LoggingConfig
    rate_limit: RateLimitConfig
    database: DatabaseConfig


def load(path: Optional[str] = None) -> Config:
    """Load configuration from a YAML file with environment variable overrides."""
    config_path = path or os.environ.get("HONEYPOT_CONFIG_PATH", "config.yaml")
    config_file = Path(config_path)

    if not config_file.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with config_file.open() as f:
        raw = yaml.safe_load(f)

    hp = raw.get("honeypot", {})

    ssh_raw = hp.get("ssh", {})
    http_raw = hp.get("http", {})
    telnet_raw = hp.get("telnet", {})
    dashboard_raw = hp.get("dashboard", {})
    geo_raw = hp.get("geo", {})
    logging_raw = hp.get("logging", {})
    rate_raw = hp.get("rate_limit", {})
    db_raw = hp.get("database", {})

    def parse_creds(raw_list: list) -> List[TrapCredential]:
        return [TrapCredential(username=c["username"], password=c["password"]) for c in raw_list]

    return Config(
        ssh=SSHConfig(
            enabled=ssh_raw.get("enabled", True),
            port=int(os.environ.get("HONEYPOT_SSH_PORT", ssh_raw.get("port", 2222))),
            banner=ssh_raw.get("banner", "SSH-2.0-OpenSSH_7.4"),
            trap_credentials=parse_creds(ssh_raw.get("trap_credentials", [])),
            auth_fail_delay=float(ssh_raw.get("auth_fail_delay", 2.0)),
            max_session_commands=int(ssh_raw.get("max_session_commands", 30)),
            session_timeout=int(ssh_raw.get("session_timeout", 120)),
        ),
        http=HTTPConfig(
            enabled=http_raw.get("enabled", True),
            port=int(os.environ.get("HONEYPOT_HTTP_PORT", http_raw.get("port", 8080))),
            server_header=http_raw.get("server_header", "Apache/2.4.41 (Ubuntu)"),
            x_powered_by=http_raw.get("x_powered_by", "PHP/7.4.3"),
            persona=http_raw.get("persona", "router"),
        ),
        telnet=TelnetConfig(
            enabled=telnet_raw.get("enabled", True),
            port=int(os.environ.get("HONEYPOT_TELNET_PORT", telnet_raw.get("port", 2323))),
            auth_fail_delay=float(telnet_raw.get("auth_fail_delay", 1.5)),
            trap_credentials=parse_creds(telnet_raw.get("trap_credentials", [])),
        ),
        dashboard=DashboardConfig(
            enabled=dashboard_raw.get("enabled", True),
            port=int(os.environ.get("HONEYPOT_DASHBOARD_PORT", dashboard_raw.get("port", 5000))),
            host=dashboard_raw.get("host", "0.0.0.0"),
        ),
        geo=GeoConfig(
            enabled=geo_raw.get("enabled", True),
            cache_ttl_hours=int(geo_raw.get("cache_ttl_hours", 24)),
            rate_limit_per_minute=int(geo_raw.get("rate_limit_per_minute", 40)),
        ),
        logging=LoggingConfig(
            level=logging_raw.get("level", "INFO"),
            file=logging_raw.get("file", "logs/honeypot.log"),
            max_bytes=int(logging_raw.get("max_bytes", 10485760)),
            backup_count=int(logging_raw.get("backup_count", 5)),
        ),
        rate_limit=RateLimitConfig(
            max_events_per_ip_per_minute=int(rate_raw.get("max_events_per_ip_per_minute", 30)),
        ),
        database=DatabaseConfig(
            path=db_raw.get("path", "data/honeypot.db"),
        ),
    )
