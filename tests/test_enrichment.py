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
        assert r["attack"] == []
        assert "test failure" in r["rationale"][0]


class TestEnrichOne:
    @responses.activate
    def test_enrich_one_produces_full_result(self, mock_all_sources):
        """enrich_one should produce a dict with rationale, sources, and attack."""
        mock_all_sources("8.8.8.8", "ip")

        result = enrich_one("8.8.8.8")

        # Basic shape
        assert result["ioc"] == "8.8.8.8"
        assert result["type"] == "ip"
        assert "risk" in result
        assert "risk_score" in result
        assert "rationale" in result
        assert isinstance(result["rationale"], list)
        assert "attack" in result
        assert isinstance(result["attack"], list)
        assert "sources" in result

        # All 8 sources present
        assert set(result["sources"].keys()) == {
            "virustotal", "abuseipdb", "malwarebazaar", "urlhaus", "otx",
            "greynoise", "threatfox", "feodo",
        }


class TestEnrichAllDispatcher:
    @responses.activate
    def test_empty_list_returns_empty(self):
        """Empty input → empty output, no API calls."""
        result = enrich_all([], parallel=True, workers=5)
        assert result == []

    @responses.activate
    def test_sequential_mode(self, mock_all_sources):
        """Sequential mode should produce results in order."""
        mock_all_sources("8.8.8.8", "ip")

        results = enrich_all(["8.8.8.8"], parallel=False)
        assert len(results) == 1
        assert results[0]["ioc"] == "8.8.8.8"

    @responses.activate
    def test_parallel_preserves_order(self, mock_all_sources):
        """Parallel mode must return results in the same order as input."""
        iocs = ["8.8.8.8", "1.1.1.1"]
        for ip in iocs:
            mock_all_sources(ip, "ip")

        results = enrich_all(iocs, parallel=True, workers=5)

        assert len(results) == 2
        assert results[0]["ioc"] == "8.8.8.8"
        assert results[1]["ioc"] == "1.1.1.1"
