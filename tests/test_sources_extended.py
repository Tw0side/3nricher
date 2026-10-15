"""
Tests for extended sources — GreyNoise, ThreatFox, Feodo Tracker.

Uses the `responses` library to mock HTTP calls. No live API requests.
"""
import pytest
import responses

from sources import greynoise, threatfox, feodo


# ---------------------------------------------------------------
# GreyNoise
# ---------------------------------------------------------------
class TestGreyNoise:
    @responses.activate
    def test_success(self):
        """GreyNoise returns classification, noise, riot flags."""
        responses.add(
            responses.GET,
            "https://api.greynoise.io/v3/community/45.155.205.233",
            json={
                "ip": "45.155.205.233",
                "noise": True,
                "riot": False,
                "classification": "malicious",
                "name": "Unknown Scanner",
                "last_seen": "2026-10-14",
                "link": "https://viz.greynoise.io/ip/45.155.205.233",
            },
            status=200,
        )
        result = greynoise.query("45.155.205.233", "ip")
        assert result["status"] == "ok"
        assert result["classification"] == "malicious"
        assert result["noise"] is True
        assert result["riot"] is False

    @responses.activate
    def test_not_found(self):
        """GreyNoise returns 404 for IPs it hasn't seen."""
        responses.add(
            responses.GET,
            "https://api.greynoise.io/v3/community/1.2.3.4",
            status=404,
        )
        result = greynoise.query("1.2.3.4", "ip")
        assert result["status"] == "not_found"

    def test_not_applicable_for_domain(self):
        """GreyNoise only supports IPs."""
        result = greynoise.query("google.com", "domain")
        assert result["status"] == "not_applicable"

    def test_not_applicable_for_hash(self):
        result = greynoise.query("a" * 64, "sha256")
        assert result["status"] == "not_applicable"


# ---------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------
class TestThreatFox:
    @responses.activate
    def test_success(self):
        """ThreatFox returns malware family and threat type."""
        responses.add(
            responses.POST,
            "https://threatfox-api.abuse.ch/api/v1/",
            json={
                "query_status": "ok",
                "data": [{
                    "ioc": "45.155.205.233:443",
                    "malware_printable": "Cobalt Strike",
                    "malware": "win.cobalt_strike",
                    "threat_type": "botnet_cc",
                    "confidence_level": 100,
                    "first_seen": "2026-10-10 12:00:00",
                    "last_seen": "2026-10-14 08:30:00",
                    "reference": "https://twitter.com/...",
                }],
            },
            status=200,
        )
        result = threatfox.query("45.155.205.233", "ip")
        assert result["status"] == "ok"
        assert "Cobalt Strike" in result["malware"]
        assert result["threat_type"] == "botnet_cc"
        assert result["confidence_level"] == 100

    @responses.activate
    def test_no_result(self):
        """ThreatFox returns 'no_result' when IOC isn't tracked."""
        responses.add(
            responses.POST,
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query_status": "no_result"},
            status=200,
        )
        result = threatfox.query("8.8.8.8", "ip")
        assert result["status"] == "not_found"

    @responses.activate
    def test_empty_data(self):
        """Empty data list → not_found."""
        responses.add(
            responses.POST,
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query_status": "ok", "data": []},
            status=200,
        )
        result = threatfox.query("1.2.3.4", "ip")
        assert result["status"] == "not_found"

    def test_not_applicable_for_unknown_type(self):
        result = threatfox.query("something", "unknown")
        assert result["status"] == "not_applicable"


# ---------------------------------------------------------------
# Feodo Tracker
# ---------------------------------------------------------------
class TestFeodo:
    @responses.activate
    def test_success(self):
        """Feodo returns malware family when IP is in the blocklist."""
        responses.add(
            responses.GET,
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            json=[
                {
                    "ip_address": "45.155.205.233",
                    "malware": "Emotet",
                    "status": "online",
                    "first_seen": "2026-10-01",
                    "last_online": "2026-10-14",
                    "port": 443,
                    "as_number": 12345,
                    "country": "RU",
                },
                {
                    "ip_address": "1.2.3.4",
                    "malware": "QakBot",
                    "status": "offline",
                },
            ],
            status=200,
        )
        result = feodo.query("45.155.205.233", "ip")
        assert result["status"] == "ok"
        assert result["malware"] == "Emotet"
        assert result["status_detail"] == "online"
        assert result["port"] == 443

    @responses.activate
    def test_not_found(self):
        """IP not in blocklist → not_found."""
        responses.add(
            responses.GET,
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            json=[
                {"ip_address": "5.6.7.8", "malware": "Emotet"},
            ],
            status=200,
        )
        result = feodo.query("8.8.8.8", "ip")
        assert result["status"] == "not_found"

    @responses.activate
    def test_empty_blocklist(self):
        responses.add(
            responses.GET,
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            json=[],
            status=200,
        )
        result = feodo.query("8.8.8.8", "ip")
        assert result["status"] == "not_found"

    @responses.activate
    def test_malformed_response(self):
        """Non-list response → error."""
        responses.add(
            responses.GET,
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            json={"error": "something went wrong"},
            status=200,
        )
        result = feodo.query("8.8.8.8", "ip")
        assert result["status"] == "error"

    def test_not_applicable_for_domain(self):
        result = feodo.query("google.com", "domain")
        assert result["status"] == "not_applicable"

    def test_not_applicable_for_hash(self):
        result = feodo.query("a" * 64, "sha256")
        assert result["status"] == "not_applicable"
