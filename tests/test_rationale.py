"""
Tests for rationale.py — score explanation builder.

Covers the 8-source rationale format with detection-ratio VT scoring
and the Unknown verdict semantics from Iteration 7a.
"""
import pytest

from rationale import build_rationale


class TestRationaleBuilder:
    def test_returns_9_lines(self):
        """Should produce 8 source lines + 1 total = 9 lines."""
        sources = {
            "virustotal": {"status": "ok", "malicious": 0, "suspicious": 0,
                          "harmless": 50, "undetected": 10},
            "abuseipdb": {"status": "ok", "abuse_score": 0},
            "malwarebazaar": {"status": "not_applicable"},
            "urlhaus": {"status": "not_found"},
            "otx": {"status": "ok", "pulse_count": 0},
            "greynoise": {"status": "not_applicable"},
            "threatfox": {"status": "not_found"},
            "feodo": {"status": "not_applicable"},
        }
        lines = build_rationale(sources, score=0, label="Low")
        assert len(lines) == 9
        assert lines[-1] == "Total: 0 (Low)"

    def test_unknown_verdict_in_total_line(self):
        """Unknown label produces a distinct total line."""
        sources = {
            "virustotal": {"status": "not_found"},
            "abuseipdb": {"status": "not_applicable"},
            "malwarebazaar": {"status": "not_applicable"},
            "urlhaus": {"status": "not_found"},
            "otx": {"status": "not_found"},
            "greynoise": {"status": "not_found"},
            "threatfox": {"status": "not_found"},
            "feodo": {"status": "not_applicable"},
        }
        lines = build_rationale(sources, score=0, label="Unknown")
        assert len(lines) == 9
        assert "Unknown" in lines[-1]
        assert "no source returned data" in lines[-1]

    def test_tor_node_rationale(self):
        """Tor exit node: VT + Abuse + OTX all contribute."""
        sources = {
            "virustotal": {"status": "ok", "malicious": 13, "suspicious": 4,
                          "harmless": 40, "undetected": 10},
            "abuseipdb": {"status": "ok", "abuse_score": 100},
            "malwarebazaar": {"status": "not_applicable"},
            "urlhaus": {"status": "not_applicable"},
            "otx": {"status": "ok", "pulse_count": 50},
            "greynoise": {"status": "not_applicable"},
            "threatfox": {"status": "not_found"},
            "feodo": {"status": "not_applicable"},
        }
        lines = build_rationale(sources, score=89, label="Critical")
        text = "\n".join(lines)

        # VT now shows detection ratio
        assert "VirusTotal:" in text
        assert "malicious" in text
        # Abuse and OTX unchanged
        assert "AbuseIPDB: 100% abuse confidence → +25" in text
        assert "OTX: 50 community pulses → +20 (capped)" in text
        assert "Total: 89 (Critical)" in text

    def test_virustotal_ratio_format(self):
        """VirusTotal line shows detection ratio, not raw count."""
        sources = {
            "virustotal": {"status": "ok", "malicious": 30, "suspicious": 0,
                          "harmless": 30, "undetected": 3},
            "abuseipdb": {"status": "not_applicable"},
            "malwarebazaar": {"status": "not_applicable"},
            "urlhaus": {"status": "not_applicable"},
            "otx": {"status": "not_applicable"},
            "greynoise": {"status": "not_applicable"},
            "threatfox": {"status": "not_applicable"},
            "feodo": {"status": "not_applicable"},
        }
        lines = build_rationale(sources, score=31, label="Medium")
        text = "\n".join(lines)

        # 30/63 = 47.6% → truncated to 47%
        assert "30/63" in text
        assert "47%" in text

    def test_malware_bazaar_hit(self):
        """MB hit shows signature."""
        sources = {
            "virustotal": {"status": "ok", "malicious": 62, "suspicious": 0,
                          "harmless": 0, "undetected": 2},
            "abuseipdb": {"status": "not_applicable"},
            "malwarebazaar": {"status": "ok", "signature": "WannaCry"},
            "urlhaus": {"status": "not_applicable"},
            "otx": {"status": "ok", "pulse_count": 50},
            "greynoise": {"status": "not_applicable"},
            "threatfox": {"status": "not_found"},
            "feodo": {"status": "not_applicable"},
        }
        lines = build_rationale(sources, score=100, label="Critical")
        text = "\n".join(lines)

        assert "confirmed malware (WannaCry) → +40" in text

    def test_errors_shown_with_reason(self):
        """Error sources show their reason."""
        sources = {
            "virustotal": {"status": "error", "reason": "timeout"},
            "abuseipdb": {"status": "error", "reason": "invalid API key"},
            "malwarebazaar": {"status": "not_found"},
            "urlhaus": {"status": "not_applicable"},
            "otx": {"status": "not_found"},
            "greynoise": {"status": "not_found"},
            "threatfox": {"status": "not_found"},
            "feodo": {"status": "not_applicable"},
        }
        lines = build_rationale(sources, score=0, label="Unknown")
        text = "\n".join(lines)

        assert "VirusTotal: error (timeout)" in text
        assert "AbuseIPDB: error (invalid API key)" in text
        assert "MalwareBazaar: not found" in text
        assert "URLhaus: not applicable" in text
        assert "OTX: not found" in text
        assert "GreyNoise: not found" in text
        assert "ThreatFox: not found" in text
        assert "Feodo: not applicable" in text

    def test_not_applicable_sources_included(self):
        """All 8 sources appear in rationale, even if not applicable."""
        sources = {
            "virustotal": {"status": "ok", "malicious": 0, "suspicious": 0,
                          "harmless": 50, "undetected": 10},
            "abuseipdb": {"status": "not_applicable"},
            "malwarebazaar": {"status": "not_applicable"},
            "urlhaus": {"status": "not_applicable"},
            "otx": {"status": "not_applicable"},
            "greynoise": {"status": "not_applicable"},
            "threatfox": {"status": "not_applicable"},
            "feodo": {"status": "not_applicable"},
        }
        lines = build_rationale(sources, score=0, label="Low")
        text = "\n".join(lines)

        # Every source must have a line
        assert "VirusTotal:" in text
        assert "AbuseIPDB:" in text
        assert "MalwareBazaar:" in text
        assert "URLhaus:" in text
        assert "OTX:" in text
        assert "GreyNoise:" in text
        assert "ThreatFox:" in text
        assert "Feodo:" in text

    def test_greynoise_contribution(self):
        """GreyNoise shows classification and score."""
        sources = {
            "virustotal": {"status": "ok", "malicious": 0, "suspicious": 0,
                          "harmless": 50, "undetected": 10},
            "abuseipdb": {"status": "not_applicable"},
            "malwarebazaar": {"status": "not_applicable"},
            "urlhaus": {"status": "not_applicable"},
            "otx": {"status": "not_applicable"},
            "greynoise": {"status": "ok", "classification": "malicious", "name": "Test Scanner"},
            "threatfox": {"status": "not_applicable"},
            "feodo": {"status": "not_applicable"},
        }
        lines = build_rationale(sources, score=15, label="Low")
        text = "\n".join(lines)

        assert "GreyNoise: malicious (Test Scanner) → +15" in text

    def test_threatfox_contribution(self):
        """ThreatFox shows malware and threat type."""
        sources = {
            "virustotal": {"status": "ok", "malicious": 0, "suspicious": 0,
                          "harmless": 50, "undetected": 10},
            "abuseipdb": {"status": "not_applicable"},
            "malwarebazaar": {"status": "not_applicable"},
            "urlhaus": {"status": "not_applicable"},
            "otx": {"status": "not_applicable"},
            "greynoise": {"status": "not_applicable"},
            "threatfox": {"status": "ok", "malware": "Cobalt Strike", "threat_type": "botnet_cc"},
            "feodo": {"status": "not_applicable"},
        }
        lines = build_rationale(sources, score=30, label="Medium")
        text = "\n".join(lines)

        assert "ThreatFox: Cobalt Strike (botnet_cc) → +30" in text
