"""Tests for GeoLookup: caching, private IP short-circuit, and rate limiting."""

import pytest
from unittest.mock import patch, MagicMock

from honeypot.core.database import Database
from honeypot.core.geo import GeoLookup


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "test.db"))


@pytest.fixture
def geo(db):
    return GeoLookup(db, cache_ttl_hours=24, rate_per_minute=100)


def _mock_response(data: dict) -> MagicMock:
    m = MagicMock()
    m.json.return_value = data
    return m


def test_private_ip_short_circuits(geo):
    """Private IPs should never make an HTTP call."""
    with patch("honeypot.core.geo.requests.get") as mock_get:
        result = geo.lookup("192.168.1.100")
        mock_get.assert_not_called()
        assert result.country == "Private Network"


def test_loopback_short_circuits(geo):
    with patch("honeypot.core.geo.requests.get") as mock_get:
        result = geo.lookup("127.0.0.1")
        mock_get.assert_not_called()
        assert result.country == "Private Network"


def test_successful_lookup(geo):
    api_resp = {
        "status": "success",
        "country": "Germany",
        "countryCode": "DE",
        "regionName": "Bavaria",
        "city": "Munich",
        "isp": "Deutsche Telekom",
        "as": "AS3320",
        "lat": 48.137,
        "lon": 11.576,
        "query": "5.5.5.5",
    }
    with patch("honeypot.core.geo.requests.get", return_value=_mock_response(api_resp)):
        result = geo.lookup("5.5.5.5")
        assert result.country == "Germany"
        assert result.city == "Munich"
        assert result.asn == "AS3320"


def test_cache_prevents_second_request(geo, db):
    api_resp = {
        "status": "success", "country": "France", "countryCode": "FR",
        "regionName": "Île-de-France", "city": "Paris", "isp": "Orange",
        "as": "AS3215", "lat": 48.8566, "lon": 2.3522, "query": "9.9.9.9",
    }
    with patch("honeypot.core.geo.requests.get", return_value=_mock_response(api_resp)) as mock_get:
        geo.lookup("9.9.9.9")
        geo.lookup("9.9.9.9")  # Should hit cache
        assert mock_get.call_count == 1


def test_failed_api_response(geo):
    with patch("honeypot.core.geo.requests.get", return_value=_mock_response({"status": "fail", "message": "reserved range"})):
        result = geo.lookup("5.5.5.6")
        # Should return empty GeoData, not raise
        assert result.ip == "5.5.5.6"
        assert result.country is None
