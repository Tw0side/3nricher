"""
Tests for scoring.py — multi-source risk scoring.

These tests lock in the reviewer's feedback from v0.2.1:
- MalwareBazaar hit floors at High
- AbuseIPDB abuse_score=100 floors at High
- Allowlist forces Low regardless of other signals
"""
import pytest

from scoring import calculate_risk


def sources(**kwargs) -> dict:
    """Helper to build a sources dict from keyword arguments."""
    return kwargs


class TestScoring:
    def test_all_clean_returns_low(self):
        """Clean IOC across all sources should score 0 / Low."""
        score, label = calculate_risk(sources(
            virustotal={"status": "ok", "malicious": 0, "suspicious": 0},
            abuseipdb={"status": "ok", "abuse_score": 0},
            malwarebazaar={"status": "not_found"},
            urlhaus={"status": "not_found"},
            otx={"status": "ok", "pulse_count": 0},
        ), ioc="1.2.3.4", ioc_type="ip")
        assert score == 0
        assert label == "Low"

    def test_wannacry_is_critical(self):
        """WannaCry hash should hit Critical (VT + MB + OTX)."""
        score, label = calculate_risk(sources(
            virustotal={"status": "ok", "malicious": 62, "suspicious": 0},
            abuseipdb={"status": "not_applicable"},
            malwarebazaar={"status": "ok", "signature": "WannaCry"},
            urlhaus={"status": "not_applicable"},
            otx={"status": "ok", "pulse_count": 50},
        ), ioc="84c82835a5d21bbcf75a61706d8ab549", ioc_type="md5")
        assert label == "Critical"
        assert score == 100  # VT 50 (capped) + MB 40 + OTX 10 (capped) = 100

    def test_tor_exit_node_is_critical(self):
        """Tor exit node: VT flags + Abuse 100 + OTX pulses."""
        score, label = calculate_risk(sources(
            virustotal={"status": "ok", "malicious": 13, "suspicious": 4},
            abuseipdb={"status": "ok", "abuse_score": 100},
            malwarebazaar={"status": "not_applicable"},
            urlhaus={"status": "not_applicable"},
            otx={"status": "ok", "pulse_count": 50},
        ), ioc="185.220.101.1", ioc_type="ip")
        assert label == "Critical"
        assert score == 95  # VT 50 + Abuse 25 + OTX 20 = 95

    def test_mb_hit_floors_at_high(self):
        """MalwareBazaar hit alone should floor at High (reviewer fix)."""
        score, label = calculate_risk(sources(
            virustotal={"status": "not_found"},
            abuseipdb={"status": "not_applicable"},
            malwarebazaar={"status": "ok", "signature": "SomeMalware"},
            urlhaus={"status": "not_applicable"},
            otx={"status": "not_found"},
        ), ioc="a" * 64, ioc_type="sha256")
        # Without floor: 40 pts -> Medium. With floor -> High.
        assert label == "High"
        assert score >= 45

    def test_abuse_100_floors_at_high(self):
        """AbuseIPDB abuse_score=100 alone should floor at High."""
        score, label = calculate_risk(sources(
            virustotal={"status": "not_found"},
            abuseipdb={"status": "ok", "abuse_score": 100},
            malwarebazaar={"status": "not_applicable"},
            urlhaus={"status": "not_applicable"},
            otx={"status": "not_found"},
        ), ioc="1.2.3.4", ioc_type="ip")
        assert label == "High"

    def test_allowlist_forces_low(self):
        """Allowlisted IOC should be Low even with strong signals."""
        score, label = calculate_risk(sources(
            virustotal={"status": "ok", "malicious": 10, "suspicious": 5},
            abuseipdb={"status": "ok", "abuse_score": 100},
            malwarebazaar={"status": "not_applicable"},
            urlhaus={"status": "not_applicable"},
            otx={"status": "ok", "pulse_count": 50},
        ), ioc="8.8.8.8", ioc_type="ip")
        assert score == 0
        assert label == "Low"

    def test_errors_only_returns_low(self):
        """All errors should score Low."""
        score, label = calculate_risk(sources(
            virustotal={"status": "error", "reason": "timeout"},
            abuseipdb={"status": "error", "reason": "timeout"},
            malwarebazaar={"status": "error", "reason": "timeout"},
            urlhaus={"status": "error", "reason": "timeout"},
            otx={"status": "error", "reason": "timeout"},
        ), ioc="1.2.3.4", ioc_type="ip")
        assert score == 0
        assert label == "Low"

    def test_score_capped_at_100(self):
        """Score must never exceed 100 even with huge signals."""
        score, _ = calculate_risk(sources(
            virustotal={"status": "ok", "malicious": 70, "suspicious": 20},
            abuseipdb={"status": "ok", "abuse_score": 100},
            malwarebazaar={"status": "ok", "signature": "X"},
            urlhaus={"status": "ok", "url_count": 100},
            otx={"status": "ok", "pulse_count": 100},
        ), ioc="1.2.3.4", ioc_type="ip")
        assert score == 100
