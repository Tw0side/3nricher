"""
Tests for attck_loader.py and attck.py — ATT&CK mapping.

Covers:
- Loading YAML mappings from disk
- Name normalization (case, underscores, prefixes)
- Alias resolution
- Version stripping (e.g., "lockbit 3.0" → "lockbit")
- Mapper extraction of candidates from source data
- Deduplication of techniques
- Provenance tracking
"""
import pytest

from attck_loader import (
    lookup_by_name,
    all_malware_names,
    stats,
    _normalize,
)
from attck import map_to_attck, format_techniques, _extract_candidates


class TestNormalize:
    def test_lowercase(self):
        assert _normalize("WannaCry") == "wannacry"

    def test_underscores_to_spaces(self):
        assert _normalize("cobalt_strike") == "cobalt strike"

    def test_hyphens_to_spaces(self):
        assert _normalize("some-malware") == "some malware"

    def test_strip_whitespace(self):
        assert _normalize("  wannacry  ") == "wannacry"

    def test_strip_win_prefix(self):
        assert _normalize("win.cobalt_strike") == "cobalt strike"
        assert _normalize("win32.emotet") == "emotet"

    def test_empty_returns_empty(self):
        assert _normalize("") == ""
        assert _normalize(None) == ""


class TestLoader:
    def test_stats_returns_expected_keys(self):
        s = stats()
        assert "files_loaded" in s
        assert "unique_malware" in s
        assert "aliases" in s
        assert "total_techniques" in s

    def test_stats_loaded_files(self):
        s = stats()
        assert s["files_loaded"] >= 5  # at least our 5 official files
        assert s["unique_malware"] >= 5
        assert s["total_techniques"] >= 20

    def test_all_malware_names_includes_known(self):
        names = all_malware_names()
        assert "wannacry" in names
        assert "lockbit" in names
        assert "emotet" in names
        assert "qakbot" in names
        assert "cobalt strike" in names

    def test_lookup_by_primary_name(self):
        mapping = lookup_by_name("wannacry")
        assert mapping is not None
        assert mapping["malware"] == "wannacry"

    def test_lookup_case_insensitive(self):
        assert lookup_by_name("WannaCry") is not None
        assert lookup_by_name("WANNACRY") is not None

    def test_lookup_by_alias(self):
        # wcry is an alias for wannacry
        mapping = lookup_by_name("wcry")
        assert mapping is not None
        assert mapping["malware"] == "wannacry"

    def test_lookup_normalizes_underscores(self):
        mapping = lookup_by_name("cobalt_strike")
        assert mapping is not None
        assert mapping["malware"] == "cobalt strike"

    def test_lookup_strips_version(self):
        # lockbit 3.0 → lockbit
        mapping = lookup_by_name("lockbit 3.0")
        assert mapping is not None
        assert mapping["malware"] == "lockbit"

    def test_lookup_unknown_returns_none(self):
        assert lookup_by_name("not-a-real-malware") is None

    def test_lookup_empty_returns_none(self):
        assert lookup_by_name("") is None
        assert lookup_by_name(None) is None


class TestExtractCandidates:
    def test_extracts_mb_signature(self):
        sources = {
            "malwarebazaar": {"status": "ok", "signature": "WannaCry"},
        }
        candidates = _extract_candidates(sources)
        assert ("WannaCry", "malwarebazaar") in candidates

    def test_extracts_otx_tags(self):
        sources = {
            "otx": {"status": "ok", "tags": ["ransomware", "wannacry"]},
        }
        candidates = _extract_candidates(sources)
        assert ("ransomware", "otx") in candidates
        assert ("wannacry", "otx") in candidates

    def test_skips_non_ok_status(self):
        sources = {
            "malwarebazaar": {"status": "error", "signature": "WannaCry"},
            "otx": {"status": "not_applicable"},
        }
        candidates = _extract_candidates(sources)
        assert candidates == []

    def test_handles_missing_fields(self):
        sources = {
            "malwarebazaar": {"status": "ok"},  # no signature
            "otx": {"status": "ok"},            # no tags
        }
        candidates = _extract_candidates(sources)
        assert candidates == []

    def test_extracts_threatfox_malware(self):
        sources = {
            "threatfox": {"status": "ok", "malware": "win.cobalt_strike"},
        }
        candidates = _extract_candidates(sources)
        assert ("win.cobalt_strike", "threatfox") in candidates


class TestMapToAttck:
    def test_wannacry_maps_to_techniques(self):
        sources = {
            "virustotal": {"status": "ok", "malicious": 66},
            "malwarebazaar": {"status": "ok", "signature": "WannaCry"},
            "otx": {"status": "ok", "pulse_count": 50, "tags": []},
        }
        techniques = map_to_attck(sources)
        ids = [t["id"] for t in techniques]
        assert "T1486" in ids
        assert "T1529" in ids

    def test_provenance_included(self):
        sources = {
            "malwarebazaar": {"status": "ok", "signature": "WannaCry"},
        }
        techniques = map_to_attck(sources)
        for t in techniques:
            assert "source" in t
            assert "malwarebazaar" in t["source"]
            assert "WannaCry" in t["source"]

    def test_clean_ioc_returns_empty(self):
        sources = {
            "virustotal": {"status": "ok", "malicious": 0},
            "abuseipdb": {"status": "ok", "abuse_score": 0},
            "malwarebazaar": {"status": "not_applicable"},
            "otx": {"status": "ok", "pulse_count": 0, "tags": []},
        }
        assert map_to_attck(sources) == []

    def test_deduplicates_techniques(self):
        """Same technique from two sources should appear once."""
        sources = {
            "malwarebazaar": {"status": "ok", "signature": "WannaCry"},
            "otx": {"status": "ok", "tags": ["wannacry"]},
        }
        techniques = map_to_attck(sources)
        ids = [t["id"] for t in techniques]
        # No duplicates
        assert len(ids) == len(set(ids))

    def test_sorted_by_id(self):
        sources = {
            "malwarebazaar": {"status": "ok", "signature": "WannaCry"},
        }
        techniques = map_to_attck(sources)
        ids = [t["id"] for t in techniques]
        assert ids == sorted(ids)

    def test_empty_sources(self):
        assert map_to_attck({}) == []


class TestFormatTechniques:
    def test_formats_list(self):
        techniques = [
            {"id": "T1486", "name": "Data Encrypted for Impact", "source": "mb:WannaCry"},
        ]
        output = format_techniques(techniques)
        assert "T1486" in output
        assert "Data Encrypted for Impact" in output

    def test_empty_returns_placeholder(self):
        output = format_techniques([])
        assert "(none)" in output
