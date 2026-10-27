from types import SimpleNamespace

import pytest

from config import Config
from sources import ipinfo


def resp(status=200, payload=None):
    return SimpleNamespace(status_code=status, json=lambda: payload)


@pytest.fixture(autouse=True)
def token(monkeypatch):
    monkeypatch.setattr(Config, "IPINFO_API_KEY", "test-token")


def test_non_ip_not_applicable():
    assert ipinfo.query("example.com", "domain")["status"] == "not_applicable"


def test_missing_token(monkeypatch):
    monkeypatch.setattr(Config, "IPINFO_API_KEY", None)
    assert ipinfo.query("8.8.8.8", "ip")["status"] == "error"


def test_ok_with_geo(monkeypatch):
    lite = resp(200, {"asn": "AS15169", "as_name": "Google LLC",
                      "as_domain": "google.com", "country_code": "US"})
    core = resp(200, {"city": "Mountain View", "region": "California",
                      "country": "US", "loc": "37.4,-122.0",
                      "timezone": "America/Los_Angeles", "postal": "94043"})
    calls = iter([(lite, None), (core, None)])
    monkeypatch.setattr(ipinfo, "safe_request", lambda *a, **k: next(calls))
    r = ipinfo.query("8.8.8.8", "ip")
    assert r["status"] == "ok"
    assert r["asn"] == "AS15169"
    assert r["geo"]["city"] == "Mountain View"


def test_geo_failure_keeps_asn(monkeypatch):
    lite = resp(200, {"asn": "AS15169", "as_name": "Google LLC"})
    calls = iter([(lite, None), (None, {"reason": "timeout"})])
    monkeypatch.setattr(ipinfo, "safe_request", lambda *a, **k: next(calls))
    r = ipinfo.query("8.8.8.8", "ip")
    assert r["status"] == "ok"
    assert r["geo"] == {}


def test_bad_token(monkeypatch):
    monkeypatch.setattr(ipinfo, "safe_request",
                        lambda *a, **k: (resp(401), None))
    assert ipinfo.query("8.8.8.8", "ip")["status"] == "error"


def test_not_found(monkeypatch):
    monkeypatch.setattr(ipinfo, "safe_request",
                        lambda *a, **k: (resp(404), None))
    assert ipinfo.query("8.8.8.8", "ip")["status"] == "not_found"
