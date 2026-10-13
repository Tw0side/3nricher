"""
Tests for enrichment.py — parallel and sequential orchestration.

Uses mocked HTTP responses so no live API calls are made.
"""
import pytest
import responses

from enrichment import enrich_one, enrich_all, _error_result


class TestErrorResult:
    def test_error_result_shape(self):
        """Error result should be well-formed."""
        r = _error_result("1.2.3.4", "test failure")
        assert r["ioc"] == "1.2.3.4"
        assert r["type"] == "unknown"
        assert r["risk"] == "Unknown"
        assert r["risk_score"] == 0
        assert r["error"] == "test failure"
        assert r["sources"] == {}
        assert "test failure" in r["rationale"][0]


class TestEnrichOne:
    @responses.activate
    def test_enrich_one_produces_full_result(self, load_fixture):
        """enrich_one should produce a dict with rationale and sources."""
        # Mock VirusTotal
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            json=load_fixture("vt_response.json"),
            status=200,
        )
        # Mock AbuseIPDB
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json=load_fixture("abuse_response.json"),
            status=200,
        )
        # Mock URLhaus (applicable for IPs in Iteration 3+)
        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/host/",
            json={"query_status": "no_results"},
            status=200,
        )
        # Mock OTX
        responses.add(
            responses.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general",
            json={"pulse_info": {"count": 0, "pulses": []}},
            status=200,
        )

        result = enrich_one("8.8.8.8")

        # Shape checks
        assert result["ioc"] == "8.8.8.8"
        assert result["type"] == "ip"
        assert "risk" in result
        assert "risk_score" in result
        assert "rationale" in result
        assert isinstance(result["rationale"], list)
        assert len(result["rationale"]) == 6  # 5 sources + total
        assert "sources" in result
        assert set(result["sources"].keys()) == {
            "virustotal", "abuseipdb", "malwarebazaar", "urlhaus", "otx",
        }


class TestEnrichAllDispatcher:
    @responses.activate
    def test_empty_list_returns_empty(self):
        """Empty input → empty output, no API calls."""
        result = enrich_all([], parallel=True, workers=5)
        assert result == []

    @responses.activate
    def test_sequential_mode(self, load_fixture):
        """Sequential mode should produce results in order."""
        # Mock for one IOC
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            json=load_fixture("vt_response.json"),
            status=200,
        )
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json=load_fixture("abuse_response.json"),
            status=200,
        )
        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/host/",
            json={"query_status": "no_results"},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general",
            json={"pulse_info": {"count": 0, "pulses": []}},
            status=200,
        )

        results = enrich_all(["8.8.8.8"], parallel=False)
        assert len(results) == 1
        assert results[0]["ioc"] == "8.8.8.8"

    @responses.activate
    def test_parallel_preserves_order(self, load_fixture):
        """Parallel mode must return results in the same order as input."""
        iocs = ["8.8.8.8", "1.1.1.1"]

        # Mock all endpoints for both IPs
        for ip in iocs:
            responses.add(
                responses.GET,
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                json=load_fixture("vt_response.json"),
                status=200,
            )
            responses.add(
                responses.GET,
                "https://api.abuseipdb.com/api/v2/check",
                json=load_fixture("abuse_response.json"),
                status=200,
            )
            responses.add(
                responses.POST,
                "https://urlhaus-api.abuse.ch/v1/host/",
                json={"query_status": "no_results"},
                status=200,
            )
            responses.add(
                responses.GET,
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                json={"pulse_info": {"count": 0, "pulses": []}},
                status=200,
            )

        results = enrich_all(iocs, parallel=True, workers=5)

        # Order preservation
        assert len(results) == 2
        assert results[0]["ioc"] == "8.8.8.8"
        assert results[1]["ioc"] == "1.1.1.1"
