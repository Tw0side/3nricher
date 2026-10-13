"""
Tests for rationale.py — score explanation builder.
"""
import pytest

from rationale import build_rationale


class TestRationaleBuilder:
    def test_returns_6_lines(self):
        """Should produce 5 source lines + 1 total = 6 lines."""
        sources = {
            "virustotal": {"status": "ok", "malicious": 0, "suspicious": 0},
            "abuseipdb": {"status": "ok", "abuse_score": 0},
            "malwarebazaar": {"status": "not_applicable"},
            "urlhaus": {"status": "not_found"},
            "otx": {"status": "ok", "pulse_count": 0},
        }
        lines = build_rationale(sources, score=0, label="Low")
        assert len(lines) == 6
        assert lines[-1] == "Total: 0 (Low)"

    def test_tor_node_rationale(self):
        """Tor exit node: VT + Abuse + OTX all contribute."""
        sources = {
            "virustotal": {"status": "ok", "malicious": 13, "suspicious": 4},
            "abuseipdb": {"status": "ok", "abuse_score": 100},
            "malwarebazaar": {"status": "not_applicable"},
            "urlhaus": {"status": "not_applicable"},
            "otx": {"status": "ok", "pulse_count": 50},
        }
        lines = build_rationale(sources, score=95, label="Critical")
        text = "\n".join(lines)

        assert "VirusTotal: 13 malicious + 4 suspicious → +50 (capped)" in text
        assert "AbuseIPDB: 100% abuse confidence → +25" in text
        assert "OTX: 50 community pulses → +20 (capped)" in text
        assert "Total: 95 (Critical)" in text

    def test_malware_bazaar_hit(self):
        """MB hit shows signature."""
        sources = {
            "virustotal": {"status": "ok", "malicious": 62, "suspicious": 0},
            "abuseipdb": {"status": "not_applicable"},
            "malwarebazaar": {"status": "ok", "signature": "WannaCry"},
            "urlhaus": {"status": "not_applicable"},
            "otx": {"status": "ok", "pulse_count": 50},
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
        }
        lines = build_rationale(sources, score=0, label="Low")
        text = "\n".join(lines)

        assert "VirusTotal: error (timeout)" in text
        assert "AbuseIPDB: error (invalid API key)" in text
        assert "MalwareBazaar: not found" in text
        assert "URLhaus: not applicable" in text
        assert "OTX: not found" in text

    def test_not_applicable_sources_included(self):
        """All sources appear in rationale, even if not applicable."""
        sources = {
            "virustotal": {"status": "ok", "malicious": 0, "suspicious": 0},
            "abuseipdb": {"status": "not_applicable"},
            "malwarebazaar": {"status": "not_applicable"},
            "urlhaus": {"status": "not_applicable"},
            "otx": {"status": "not_applicable"},
        }
        lines = build_rationale(sources, score=0, label="Low")
        text = "\n".join(lines)

        # Every source must have a line
        assert "VirusTotal:" in text
        assert "AbuseIPDB:" in text
        assert "MalwareBazaar:" in text
        assert "URLhaus:" in text
        assert "OTX:" in text
