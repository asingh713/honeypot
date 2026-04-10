"""Structured logging setup: file rotation + JSON stdout for Docker."""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional


class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line (for `docker logs | jq`)."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts":      self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level":   record.levelname,
            "logger":  record.name,
            "msg":     record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


_configured: bool = False
_log_file: Optional[str] = None
_max_bytes: int = 10 * 1024 * 1024
_backup_count: int = 5
_level: str = "INFO"


def configure(
    level: str = "INFO",
    log_file: str = "logs/honeypot.log",
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
) -> None:
    """Call once at startup to configure root handler chain."""
    global _configured, _log_file, _max_bytes, _backup_count, _level
    _log_file    = log_file
    _max_bytes   = max_bytes
    _backup_count = backup_count
    _level       = level

    root = logging.getLogger("honeypot")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not root.handlers:
        # Rotating file — plain text, human-readable
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count
        )
        fh.setFormatter(logging.Formatter(
            "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        ))
        root.addHandler(fh)

        # Stdout — JSON for Docker/log aggregators
        sh = logging.StreamHandler()
        sh.setFormatter(_JsonFormatter())
        root.addHandler(sh)

    _configured = True


def get(name: str) -> logging.Logger:
    """Return a child logger under the 'honeypot' namespace."""
    if not _configured:
        configure()
    return logging.getLogger(f"honeypot.{name}")
