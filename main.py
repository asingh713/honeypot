#!/usr/bin/env python3
"""Honeypot entrypoint: starts all enabled services and blocks until interrupted."""

from __future__ import annotations

import asyncio
import signal
import sys
from pathlib import Path

# Ensure package is importable when run from repo root
sys.path.insert(0, str(Path(__file__).parent))

import honeypot.core.config as _config_mod
import honeypot.core.logger as _logger_mod
from honeypot.core.database import Database
from honeypot.core.geo import GeoLookup


async def main() -> None:
    cfg = _config_mod.load()
    _logger_mod.configure(
        level=cfg.logging.level,
        log_file=cfg.logging.file,
        max_bytes=cfg.logging.max_bytes,
        backup_count=cfg.logging.backup_count,
    )
    log = _logger_mod.get("main")
    log.info("Starting honeypot services...")

    db  = Database(cfg.database.path)
    geo = GeoLookup(db, cfg.geo.cache_ttl_hours, cfg.geo.rate_limit_per_minute)

    services = []

    if cfg.ssh.enabled:
        from honeypot.services.ssh_honeypot import SSHHoneypot
        services.append(SSHHoneypot(cfg.ssh, db, geo, cfg.rate_limit.max_events_per_ip_per_minute))

    if cfg.telnet.enabled:
        from honeypot.services.telnet_honeypot import TelnetHoneypot
        services.append(TelnetHoneypot(cfg.telnet, db, geo, cfg.rate_limit.max_events_per_ip_per_minute))

    if cfg.http.enabled:
        from honeypot.services.http_honeypot import HTTPHoneypot
        services.append(HTTPHoneypot(cfg.http, db, geo, cfg.rate_limit.max_events_per_ip_per_minute))

    if cfg.dashboard.enabled:
        # Dashboard runs in a thread
        from honeypot.dashboard.app import create_app
        import threading
        dash_app = create_app(db)
        t = threading.Thread(
            target=dash_app.run,
            kwargs={"host": cfg.dashboard.host, "port": cfg.dashboard.port,
                    "use_reloader": False, "threaded": True},
            daemon=True,
        )
        t.start()
        log.info("Dashboard listening on http://%s:%d", cfg.dashboard.host, cfg.dashboard.port)

    # Start all async services
    for svc in services:
        await svc.start()

    log.info("All services running. Press Ctrl+C to stop.")

    # Block until SIGINT/SIGTERM
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _handle_signal():
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal)

    await stop_event.wait()

    log.info("Shutting down...")
    for svc in services:
        await svc.stop()
    log.info("Goodbye.")


if __name__ == "__main__":
    asyncio.run(main())
