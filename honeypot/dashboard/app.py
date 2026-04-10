"""Flask dashboard app factory."""

from __future__ import annotations

from flask import Flask
from pathlib import Path

from honeypot.core.database import Database


def create_app(db: Database) -> Flask:
    template_dir = Path(__file__).parent / "templates"
    app = Flask(__name__, template_folder=str(template_dir))
    app.config["DB"] = db

    from honeypot.dashboard.routes import bp
    app.register_blueprint(bp)

    return app
