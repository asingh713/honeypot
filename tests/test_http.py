"""Tests for the HTTP honeypot Flask app."""

import pytest
from unittest.mock import MagicMock, patch

from honeypot.core.database import Database, EventData
from honeypot.core.geo import GeoLookup
from honeypot.core.config import HTTPConfig
from honeypot.services.http_honeypot import HTTPHoneypot, _create_flask_app


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "test.db"))


@pytest.fixture
def cfg():
    return HTTPConfig(
        enabled=True,
        port=18080,
        server_header="Apache/2.4.41 (Ubuntu)",
        x_powered_by="PHP/7.4.3",
        persona="router",
    )


@pytest.fixture
def service(cfg, db, tmp_path):
    geo = MagicMock(spec=GeoLookup)
    geo.lookup.return_value = MagicMock(country="Test", country_code="XX", city="Testville")
    svc = HTTPHoneypot(cfg, db, geo)
    return svc


@pytest.fixture
def client(service):
    app = _create_flask_app(service)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_login_page_renders(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Sign In" in resp.data or b"Login" in resp.data


def test_fake_server_header(client):
    resp = client.get("/")
    assert resp.headers.get("Server") == "Apache/2.4.41 (Ubuntu)"
    assert resp.headers.get("X-Powered-By") == "PHP/7.4.3"


def test_login_post_logs_credentials(client, db):
    client.post("/login", data={"username": "admin", "password": "secret"})
    events = db.get_events(service="http")
    assert len(events) == 1
    assert events[0]["username"] == "admin"
    assert events[0]["password"] == "secret"


def test_login_always_fails(client):
    resp = client.post("/login", data={"username": "admin", "password": "admin"})
    assert b"Invalid" in resp.data


def test_admin_redirect(client):
    resp = client.get("/admin")
    assert resp.status_code in (301, 302)


def test_sensitive_path_404(client, db):
    resp = client.get("/.env")
    assert resp.status_code == 404
    events = db.get_events(service="http")
    assert any(e["http_path"] == "/.env" for e in events)


def test_catchall_logs_path(client, db):
    client.get("/some/random/scanner/path")
    events = db.get_events(service="http")
    assert any("/some/random/scanner/path" in (e["http_path"] or "") for e in events)
