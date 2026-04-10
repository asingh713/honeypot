"""HTTP honeypot: Flask-based fake admin panel that logs all probes and credential attempts."""

from __future__ import annotations

import asyncio
import threading
from typing import Optional
from pathlib import Path

from flask import Flask, request, redirect, url_for, render_template, make_response, jsonify

from honeypot.core.config import HTTPConfig
from honeypot.core.database import Database, EventData
from honeypot.core.geo import GeoLookup
from honeypot.services.base_service import BaseService

_TEMPLATE_DIR = Path(__file__).parent.parent / "dashboard" / "templates"


def _create_flask_app(service: "HTTPHoneypot") -> Flask:
    app = Flask(
        __name__,
        template_folder=str(_TEMPLATE_DIR),
    )
    app.secret_key = "honeypot-static-key-not-sensitive"

    cfg = service._cfg

    def _add_fake_headers(response):
        response.headers["Server"] = cfg.server_header
        response.headers["X-Powered-By"] = cfg.x_powered_by
        # Remove Flask's default header
        response.headers.pop("X-Content-Type-Options", None)
        return response

    app.after_request(_add_fake_headers)

    def _log_request(extra: Optional[dict] = None) -> None:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "0.0.0.0"
        ip = ip.split(",")[0].strip()
        event = EventData(
            service="http",
            src_ip=ip,
            src_port=0,
            http_path=request.path,
            http_method=request.method,
            http_ua=request.user_agent.string[:512] if request.user_agent.string else None,
        )
        if extra:
            event.username = extra.get("username")
            event.password = extra.get("password")
        service.record(event)

    # --- Fake admin login ---
    @app.route("/", methods=["GET"])
    def index():
        _log_request()
        return render_template("hp_login.html", persona=cfg.persona, error=None)

    @app.route("/login", methods=["POST"])
    def login():
        username = (request.form.get("username") or "")[:128]
        password = (request.form.get("password") or "")[:128]
        _log_request({"username": username, "password": password})
        # Always fail — but look convincing
        return render_template("hp_login.html", persona=cfg.persona,
                               error="Invalid username or password.")

    # --- Fake admin panel (bait for scanners that check /admin) ---
    @app.route("/admin", methods=["GET"])
    @app.route("/admin/", methods=["GET"])
    def admin():
        _log_request()
        return redirect(url_for("index"))

    # --- Common scanner bait paths ---
    @app.route("/wp-login.php", methods=["GET", "POST"])
    def wp_login():
        username = request.form.get("log", "")[:128]
        password = request.form.get("pwd", "")[:128]
        _log_request({"username": username, "password": password} if username else None)
        return make_response(
            "<html><body>ERROR: The page you're looking for isn't here.</body></html>",
            404
        )

    @app.route("/wp-admin", methods=["GET"])
    @app.route("/wp-admin/", methods=["GET"])
    def wp_admin():
        _log_request()
        return redirect("/wp-login.php")

    @app.route("/phpMyAdmin", methods=["GET"])
    @app.route("/phpmyadmin", methods=["GET"])
    @app.route("/pma", methods=["GET"])
    def phpmyadmin():
        _log_request()
        return make_response("<html><body>Forbidden</body></html>", 403)

    @app.route("/.env", methods=["GET"])
    @app.route("/.git/config", methods=["GET"])
    @app.route("/config.php", methods=["GET"])
    def sensitive_file():
        _log_request()
        return make_response("", 404)

    @app.route("/api/v1/admin", methods=["GET", "POST"])
    @app.route("/api/admin", methods=["GET", "POST"])
    def fake_api():
        _log_request()
        return jsonify({"error": "Unauthorized"}), 401

    # Catch-all: log every other path
    @app.route("/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
    def catch_all(subpath: str):
        _log_request()
        return make_response("", 404)

    return app


class HTTPHoneypot(BaseService):
    service_name = "http"

    def __init__(self, cfg: HTTPConfig, db: Database, geo: GeoLookup,
                 max_events_per_ip_per_minute: int = 30) -> None:
        super().__init__(db, geo, max_events_per_ip_per_minute)
        self._cfg = cfg
        self._thread: Optional[threading.Thread] = None
        self._app: Optional[Flask] = None

    async def start(self) -> None:
        self._app = _create_flask_app(self)
        # Run Flask in a background thread (it's WSGI, not async)
        self._thread = threading.Thread(
            target=self._app.run,
            kwargs={
                "host": "0.0.0.0",
                "port": self._cfg.port,
                "threaded": True,
                "use_reloader": False,
            },
            daemon=True,
        )
        self._thread.start()
        self._log.info("HTTP honeypot listening on port %d", self._cfg.port)

    async def stop(self) -> None:
        # Flask dev server doesn't have a clean shutdown; daemon thread dies with process
        self._log.info("HTTP honeypot stopping")
