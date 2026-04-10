"""Unit tests for database schema, inserts, and query helpers."""

import pytest
from honeypot.core.database import Database, EventData, GeoData


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "test.db"))


def test_insert_and_count(db):
    db.insert_event(EventData(service="ssh", src_ip="1.2.3.4", src_port=12345,
                              username="root", password="toor"))
    db.insert_event(EventData(service="http", src_ip="5.6.7.8", src_port=0,
                              http_path="/admin", http_method="GET"))
    assert db.count_events() == 2
    assert db.count_events(service="ssh") == 1
    assert db.count_events(service="http") == 1


def test_get_events_filter(db):
    db.insert_event(EventData(service="ssh",    src_ip="10.0.0.1", src_port=1111, username="admin"))
    db.insert_event(EventData(service="telnet", src_ip="10.0.0.2", src_port=2222, username="root"))
    db.insert_event(EventData(service="ssh",    src_ip="10.0.0.3", src_port=3333, username="pi"))

    ssh_events = db.get_events(service="ssh")
    assert len(ssh_events) == 2
    assert all(e["service"] == "ssh" for e in ssh_events)

    ip_events = db.get_events(src_ip="10.0.0.2")
    assert len(ip_events) == 1
    assert ip_events[0]["username"] == "root"


def test_stats(db):
    db.insert_event(EventData(service="ssh",  src_ip="1.1.1.1", src_port=1, username="root", password="pass"))
    db.insert_event(EventData(service="ssh",  src_ip="2.2.2.2", src_port=2, username="admin", password="admin"))
    db.insert_event(EventData(service="http", src_ip="3.3.3.3", src_port=0, http_path="/login"))

    stats = db.get_stats()
    assert stats["total"] == 3
    assert stats["unique_ips"] == 3
    assert stats["by_service"]["ssh"] == 2
    assert stats["by_service"]["http"] == 1
    assert any(e["username"] == "root" for e in stats["top_usernames"])


def test_geo_upsert_and_retrieve(db):
    geo = GeoData(ip="8.8.8.8", country="United States", country_code="US",
                  city="Mountain View", isp="Google LLC", lat=37.386, lon=-122.083)
    db.upsert_geo(geo)

    result = db.get_geo("8.8.8.8")
    assert result is not None
    assert result.country == "United States"
    assert result.city == "Mountain View"
    assert abs(result.lat - 37.386) < 0.001


def test_geo_upsert_overwrites(db):
    db.upsert_geo(GeoData(ip="1.1.1.1", country="Australia", country_code="AU", city="Sydney"))
    db.upsert_geo(GeoData(ip="1.1.1.1", country="Australia", country_code="AU", city="Melbourne"))
    result = db.get_geo("1.1.1.1")
    assert result.city == "Melbourne"


def test_pagination(db):
    for i in range(10):
        db.insert_event(EventData(service="ssh", src_ip=f"10.0.0.{i}", src_port=i))

    page1 = db.get_events(page=1, per_page=4)
    page2 = db.get_events(page=2, per_page=4)
    page3 = db.get_events(page=3, per_page=4)

    assert len(page1) == 4
    assert len(page2) == 4
    assert len(page3) == 2
