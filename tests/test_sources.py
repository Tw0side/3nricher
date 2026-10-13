"""
Tests for source modules — mocked HTTP responses.

Uses the `responses` library to intercept HTTP calls and return
fixture data. No live API requests are made.
"""
import pytest
import responses

from sources import virustotal, abuseipdb, malwarebazaar, urlhaus, otx


# ---------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------
class TestVirusTotal:
    @responses.activate
    def test_success(self, load_fixture):
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/185.220.101.1",
            json=load_fixture("vt_response.json"),
            status=200,
        )
        result = virustotal.query("185.220.101.1", "ip")
        assert result["status"] == "ok"
        assert result["malicious"] == 13
        assert result["suspicious"] == 4
        assert result["harmless"] == 45

    @responses.activate
    def test_not_found(self):
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
            status=404,
        )
        result = virustotal.query("1.2.3.4", "ip")
        assert result["status"] == "not_found"

    def test_not_applicable_for_unknown_type(self):
        result = virustotal.query("something", "unknown")
        assert result["status"] == "not_applicable"


# ---------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------
class TestAbuseIPDB:
    @responses.activate
    def test_success(self, load_fixture):
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json=load_fixture("abuse_response.json"),
            status=200,
        )
        result = abuseipdb.query("185.220.101.1", "ip")
        assert result["status"] == "ok"
        assert result["abuse_score"] == 100
        assert result["country"] == "DE"
        assert result["isp"] == "Artikel10 e.V."
        assert result["total_reports"] == 408

    def test_not_applicable_for_domain(self):
        result = abuseipdb.query("google.com", "domain")
        assert result["status"] == "not_applicable"

    def test_not_applicable_for_hash(self):
        result = abuseipdb.query("a" * 64, "sha256")
        assert result["status"] == "not_applicable"


# ---------------------------------------------------------------
# MalwareBazaar
# ---------------------------------------------------------------
class TestMalwareBazaar:
    @responses.activate
    def test_success(self, load_fixture):
        responses.add(
            responses.POST,
            "https://mb-api.abuse.ch/api/v1/",
            json=load_fixture("mb_response.json"),
            status=200,
        )
        result = malwarebazaar.query("84c82835a5d21bbcf75a61706d8ab549", "md5")
        assert result["status"] == "ok"
        assert result["signature"] == "WannaCry"
        assert result["file_type"] == "exe"
        assert result["first_seen"] == "2020-07-15 08:04:18"

    @responses.activate
    def test_not_found(self):
        responses.add(
            responses.POST,
            "https://mb-api.abuse.ch/api/v1/",
            json={"query_status": "hash_not_found"},
            status=200,
        )
        result = malwarebazaar.query("a" * 64, "sha256")
        assert result["status"] == "not_found"

    def test_not_applicable_for_ip(self):
        result = malwarebazaar.query("8.8.8.8", "ip")
        assert result["status"] == "not_applicable"


# ---------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------
class TestUrlhaus:
    @responses.activate
    def test_success(self, load_fixture):
        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/host/",
            json=load_fixture("uh_response.json"),
            status=200,
        )
        result = urlhaus.query("bad.example.com", "domain")
        assert result["status"] == "ok"
        assert result["url_count"] == 3
        assert result["threat"] == "malware_download"

    @responses.activate
    def test_not_found(self):
        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/host/",
            json={"query_status": "no_results"},
            status=200,
        )
        result = urlhaus.query("clean.example.com", "domain")
        assert result["status"] == "not_found"

    def test_not_applicable_for_hash(self):
        result = urlhaus.query("a" * 64, "sha256")
        assert result["status"] == "not_applicable"


# ---------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------
class TestOTX:
    @responses.activate
    def test_success(self, load_fixture):
        responses.add(
            responses.GET,
            "https://otx.alienvault.com/api/v1/indicators/file/84c82835a5d21bbcf75a61706d8ab549/general",
            json=load_fixture("otx_response.json"),
            status=200,
        )
        result = otx.query("84c82835a5d21bbcf75a61706d8ab549", "md5")
        assert result["status"] == "ok"
        assert result["pulse_count"] == 50
        assert "ransomware" in result["tags"]
        assert "wannacry" in result["tags"]

    @responses.activate
    def test_not_found(self):
        responses.add(
            responses.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general",
            status=404,
        )
        result = otx.query("1.2.3.4", "ip")
        assert result["status"] == "not_found"

    def test_not_applicable_for_unknown(self):
        result = otx.query("something", "unknown")
        assert result["status"] == "not_applicable"
