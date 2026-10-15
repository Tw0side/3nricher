"""
Tests for cli_query.py — single-IOC query mode.

Uses mocked HTTP responses so no live API calls are made.
"""
import responses
import pytest

from cli_query import run_query, _EXIT_CODES, _source_detail


class TestExitCodes:
    def test_low_risk_exits_zero(self):
        assert _EXIT_CODES["Low"] == 0

    def test_medium_risk_exits_zero(self):
        assert _EXIT_CODES["Medium"] == 0

    def test_high_risk_exits_one(self):
        assert _EXIT_CODES["High"] == 1

    def test_critical_risk_exits_one(self):
        assert _EXIT_CODES["Critical"] == 1

    def test_unknown_risk_exits_two(self):
        assert _EXIT_CODES["Unknown"] == 2


class TestSourceDetail:
    def test_virustotal_detail(self):
        """VT detail shows malicious/harmless counts."""
        s = {"status": "ok", "malicious": 10, "harmless": 50}
        detail = _source_detail("virustotal", s)
        assert "10 malicious" in detail
        assert "50 harmless" in detail

    def test_abuseipdb_detail(self):
        """AbuseIPDB detail shows abuse score + geo."""
        s = {"status": "ok", "abuse_score": 100, "country": "DE", "isp": "Test ISP"}
        detail = _source_detail("abuseipdb", s)
        assert "100% abuse" in detail
        assert "DE" in detail
        assert "Test ISP" in detail

    def test_not_applicable_shows_reason(self):
        """not_applicable status includes the reason."""
        s = {"status": "not_applicable", "reason": "Only supports IPs"}
        detail = _source_detail("abuseipdb", s)
        assert "Only supports IPs" in detail

    def test_error_shows_reason(self):
        """error status includes the reason."""
        s = {"status": "error", "reason": "timeout"}
        detail = _source_detail("virustotal", s)
        assert "timeout" in detail

    def test_not_found_returns_empty(self):
        """not_found status returns empty detail."""
        s = {"status": "not_found"}
        detail = _source_detail("urlhaus", s)
        assert detail == ""


class TestRunQuery:
    @responses.activate
    def test_query_clean_ioc_returns_zero(self, mock_all_sources, capsys):
        """Clean IOC → exit 0, output contains IOC and Low."""
        mock_all_sources("8.8.8.8", "ip")

        exit_code = run_query("8.8.8.8", show_history=False)

        captured = capsys.readouterr()
        output = captured.out

        assert exit_code == 0
        assert "IOC:   8.8.8.8" in output
        assert "Type:  ip" in output
        assert "Sources:" in output
        assert "Rationale:" in output

    def test_empty_ioc_returns_two(self, capsys):
        """Empty IOC string → exit 2."""
        exit_code = run_query("", show_history=False)
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "ERROR" in captured.err

    def test_whitespace_only_ioc_returns_two(self, capsys):
        """Whitespace-only IOC → exit 2."""
        exit_code = run_query("   ", show_history=False)
        assert exit_code == 2
