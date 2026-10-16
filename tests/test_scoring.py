"""
Tests for scoring.py — multi-source risk scoring.

Covers the reviewer's feedback from v0.2.1 (score floors + allowlist)
and the Iteration 7a changes:
- Unknown verdict for zero-signal IOCs
- VirusTotal uses detection ratio, not raw count
- 8 sources contribute to the score
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
            virustotal={"status": "ok", "malicious": 0, "suspicious": 0,
                       "harmless": 50, "undetected": 10},
            abuseipdb={"status": "ok", "abuse_score": 0},
            malwarebazaar={"status": "not_found"},
            urlhaus={"status": "not_found"},
            otx={"status": "ok", "pulse_count": 0},
            greynoise={"status": "not_applicable"},
            threatfox={"status": "not_found"},
            feodo={"status": "not_applicable"},
        ), ioc="1.2.3.4", ioc_type="ip")
        assert score == 0
        assert label == "Low"

    def test_wannacry_is_critical(self):
        """WannaCry hash should hit Critical (VT + MB + OTX)."""
        score, label = calculate_risk(sources(
            virustotal={"status": "ok", "malicious": 62, "suspicious": 0,
                       "harmless": 0, "undetected": 2},
            abuseipdb={"status": "not_applicable"},
            malwarebazaar={"status": "ok", "signature": "WannaCry"},
            urlhaus={"status": "not_applicable"},
            otx={"status": "ok", "pulse_count": 50},
            greynoise={"status": "not_applicable"},
            threatfox={"status": "not_found"},
            feodo={"status": "not_applicable"},
        ), ioc="84c82835a5d21bbcf75a61706d8ab549", ioc_type="md5")
        assert label == "Critical"
        # VT ratio (62/64 ≈ 97%) + MB 40 + OTX 20 → capped at 100
        assert score == 100

    def test_tor_exit_node_is_high(self):
        """
        Tor exit node: VT flags + Abuse 100 + OTX pulses.

        With detection-ratio scoring, 13/67 VT detections is a weak signal
        (~22%). Combined with abuse=100 and 50 OTX pulses, this lands at
        High, not Critical. That's the honest verdict — Tor exit nodes
        are commonly abused infrastructure, not confirmed malicious.
        """
        score, label = calculate_risk(sources(
            virustotal={"status": "ok", "malicious": 13, "suspicious": 4,
                       "harmless": 40, "undetected": 10},
            abuseipdb={"status": "ok", "abuse_score": 100},
            malwarebazaar={"status": "not_applicable"},
            urlhaus={"status": "not_applicable"},
            otx={"status": "ok", "pulse_count": 50},
            greynoise={"status": "not_applicable"},
            threatfox={"status": "not_found"},
            feodo={"status": "not_applicable"},
        ), ioc="185.220.101.1", ioc_type="ip")
        assert label == "High"
        assert 45 <= score <= 69

    def test_mb_hit_floors_at_high(self):
        """MalwareBazaar hit alone should floor at High (reviewer fix)."""
        score, label = calculate_risk(sources(
            virustotal={"status": "not_found"},
            abuseipdb={"status": "not_applicable"},
            malwarebazaar={"status": "ok", "signature": "SomeMalware"},
            urlhaus={"status": "not_applicable"},
            otx={"status": "not_found"},
            greynoise={"status": "not_applicable"},
            threatfox={"status": "not_found"},
            feodo={"status": "not_applicable"},
        ), ioc="a" * 64, ioc_type="sha256")
        # Without floor: 40 pts → Medium. With floor → High.
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
            greynoise={"status": "not_applicable"},
            threatfox={"status": "not_found"},
            feodo={"status": "not_applicable"},
        ), ioc="1.2.3.4", ioc_type="ip")
        assert label == "High"

    def test_allowlist_forces_low(self):
        """Allowlisted IOC should be Low even with strong signals."""
        score, label = calculate_risk(sources(
            virustotal={"status": "ok", "malicious": 10, "suspicious": 5,
                       "harmless": 30, "undetected": 5},
            abuseipdb={"status": "ok", "abuse_score": 100},
            malwarebazaar={"status": "not_applicable"},
            urlhaus={"status": "not_applicable"},
            otx={"status": "ok", "pulse_count": 50},
            greynoise={"status": "not_applicable"},
            threatfox={"status": "not_found"},
            feodo={"status": "not_applicable"},
        ), ioc="8.8.8.8", ioc_type="ip")
        assert score == 0
        assert label == "Low"

    def test_all_errors_returns_unknown(self):
        """All sources errored → Unknown (no data from any source)."""
        score, label = calculate_risk(sources(
            virustotal={"status": "error", "reason": "timeout"},
            abuseipdb={"status": "error", "reason": "timeout"},
            malwarebazaar={"status": "error", "reason": "timeout"},
            urlhaus={"status": "error", "reason": "timeout"},
            otx={"status": "error", "reason": "timeout"},
            greynoise={"status": "error", "reason": "timeout"},
            threatfox={"status": "error", "reason": "timeout"},
            feodo={"status": "error", "reason": "timeout"},
        ), ioc="1.2.3.4", ioc_type="ip")
        assert score == 0
        assert label == "Unknown"

    def test_score_capped_at_100(self):
        """Score must never exceed 100 even with huge signals."""
        score, _ = calculate_risk(sources(
            virustotal={"status": "ok", "malicious": 70, "suspicious": 20,
                       "harmless": 0, "undetected": 0},
            abuseipdb={"status": "ok", "abuse_score": 100},
            malwarebazaar={"status": "ok", "signature": "X"},
            urlhaus={"status": "ok", "url_count": 100},
            otx={"status": "ok", "pulse_count": 100},
            greynoise={"status": "ok", "classification": "malicious"},
            threatfox={"status": "ok", "malware": "Cobalt Strike"},
            feodo={"status": "ok", "malware": "Emotet"},
        ), ioc="1.2.3.4", ioc_type="ip")
        assert score == 100

    def test_unknown_verdict_for_zero_signal(self):
        """No source returned data → Unknown, not Low."""
        score, label = calculate_risk(sources(
            virustotal={"status": "not_found"},
            abuseipdb={"status": "not_applicable"},
            malwarebazaar={"status": "not_applicable"},
            urlhaus={"status": "not_found"},
            otx={"status": "not_found"},
            greynoise={"status": "not_found"},
            threatfox={"status": "not_found"},
            feodo={"status": "not_applicable"},
        ), ioc="fresh-domain.com", ioc_type="domain")
        assert score == 0
        assert label == "Unknown"

    def test_greynoise_malicious_adds_score(self):
        """GreyNoise 'malicious' classification adds 15 points."""
        score, _ = calculate_risk(sources(
            virustotal={"status": "ok", "malicious": 0, "suspicious": 0,
                       "harmless": 50, "undetected": 10},
            abuseipdb={"status": "not_applicable"},
            malwarebazaar={"status": "not_applicable"},
            urlhaus={"status": "not_applicable"},
            otx={"status": "not_applicable"},
            greynoise={"status": "ok", "classification": "malicious"},
            threatfox={"status": "not_applicable"},
            feodo={"status": "not_applicable"},
        ), ioc="1.2.3.4", ioc_type="ip")
        assert score >= 15

    def test_threatfox_hit_adds_score(self):
        """ThreatFox hit adds 30 points and floors at High."""
        score, label = calculate_risk(sources(
            virustotal={"status": "not_found"},
            abuseipdb={"status": "not_applicable"},
            malwarebazaar={"status": "not_applicable"},
            urlhaus={"status": "not_applicable"},
            otx={"status": "not_found"},
            greynoise={"status": "not_applicable"},
            threatfox={"status": "ok", "malware": "Cobalt Strike",
                      "threat_type": "botnet_cc"},
            feodo={"status": "not_applicable"},
        ), ioc="1.2.3.4", ioc_type="ip")
        assert score >= 30
        assert label == "High"

    def test_feodo_hit_adds_score(self):
        """Feodo hit adds 25 points and floors at High."""
        score, label = calculate_risk(sources(
            virustotal={"status": "not_found"},
            abuseipdb={"status": "not_applicable"},
            malwarebazaar={"status": "not_applicable"},
            urlhaus={"status": "not_applicable"},
            otx={"status": "not_found"},
            greynoise={"status": "not_applicable"},
            threatfox={"status": "not_found"},
            feodo={"status": "ok", "malware": "Emotet", "status_detail": "online"},
        ), ioc="1.2.3.4", ioc_type="ip")
        assert score >= 25
        assert label == "High"
