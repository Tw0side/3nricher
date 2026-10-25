from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

import freshness

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)


def rdap(date):
    return {"events": [{"eventAction": "registration", "eventDate": date}]}


def fake_response(status=200, payload=None, bad_json=False):
    r = MagicMock()
    r.status_code = status
    if bad_json:
        r.json.side_effect = ValueError("bad json")
    else:
        r.json.return_value = payload if payload is not None else {}
    return r


def patch_request(monkeypatch, resp, err=None):
    monkeypatch.setattr(freshness, "safe_request",
                        lambda *a, **k: (resp, err))


# ---- parsing ----

def test_parse_registration_date():
    dt = freshness.parse_registration_date(rdap("2007-10-09T18:20:50Z"))
    assert dt == datetime(2007, 10, 9, 18, 20, 50, tzinfo=timezone.utc)


def test_parse_ignores_other_events():
    data = {"events": [{"eventAction": "expiration",
                        "eventDate": "2030-01-01T00:00:00Z"}]}
    assert freshness.parse_registration_date(data) is None


def test_parse_handles_missing_events():
    assert freshness.parse_registration_date({}) is None


def test_parse_handles_bad_date():
    assert freshness.parse_registration_date(rdap("not-a-date")) is None


# ---- age and points ----

def test_age_in_days():
    reg = datetime(2026, 10, 20, tzinfo=timezone.utc)
    assert freshness.age_in_days(reg, NOW) == 5


def test_age_never_negative():
    future = datetime(2027, 1, 1, tzinfo=timezone.utc)
    assert freshness.age_in_days(future, NOW) == 0


@pytest.mark.parametrize("days,points", [
    (0, 25), (6, 25), (7, 15), (29, 15), (30, 5), (89, 5), (90, 0), (4000, 0),
])
def test_freshness_points_boundaries(days, points):
    assert freshness.freshness_points(days) == points


# ---- check_domain_age ----

def test_new_domain_scores(monkeypatch):
    patch_request(monkeypatch, fake_response(200, rdap("2026-10-20T00:00:00Z")))
    result = freshness.check_domain_age("new-example.com", now=NOW)
    assert result["status"] == "ok"
    assert result["date"] == "2026-10-20"
    assert result["age_days"] == 5
    assert result["points"] == 25
    assert result["source"] == "rdap"


def test_old_domain_scores_zero(monkeypatch):
    patch_request(monkeypatch, fake_response(200, rdap("2007-10-09T18:20:50Z")))
    result = freshness.check_domain_age("github.com", now=NOW)
    assert result["status"] == "ok"
    assert result["points"] == 0


def test_404_is_not_found(monkeypatch):
    patch_request(monkeypatch, fake_response(404))
    result = freshness.check_domain_age("kjfuwyce.kr")
    assert result["status"] == "not_found"


def test_server_error_is_error_not_not_found(monkeypatch):
    patch_request(monkeypatch, fake_response(503))
    assert freshness.check_domain_age("example.com")["status"] == "error"


def test_rate_limit_is_error(monkeypatch):
    patch_request(monkeypatch, fake_response(429))
    assert freshness.check_domain_age("example.com")["status"] == "error"


def test_network_failure_is_error(monkeypatch):
    patch_request(monkeypatch, None, {"status": "error", "reason": "timed out"})
    result = freshness.check_domain_age("example.com")
    assert result["status"] == "error"
    assert result["reason"] == "timed out"


def test_invalid_json_is_error(monkeypatch):
    patch_request(monkeypatch, fake_response(200, bad_json=True))
    assert freshness.check_domain_age("example.com")["status"] == "error"


def test_no_registration_event_is_not_found(monkeypatch):
    patch_request(monkeypatch, fake_response(200, {"events": []}))
    assert freshness.check_domain_age("example.com")["status"] == "not_found"


# ---- entry point ----

@pytest.mark.parametrize("ioc_type", ["ip", "md5", "sha1", "sha256"])
def test_non_domain_not_applicable(ioc_type):
    result = freshness.check_freshness("anything", ioc_type)
    assert result["status"] == "not_applicable"


def test_domain_routes_to_check_domain_age(monkeypatch):
    patch_request(monkeypatch, fake_response(200, rdap("2007-10-09T00:00:00Z")))
    assert freshness.check_freshness("github.com", "domain")["status"] == "ok"
