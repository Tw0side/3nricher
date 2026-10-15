"""
Shared pytest fixtures for 3nricher tests.

Provides:
- Path to fixtures directory
- Helper to load fixture JSON files
- Fake API keys via monkeypatch so tests don't need a real .env
- Cache disable for tests
- A fixture to mock all 8 source URLs at once
"""
import json
from pathlib import Path

import pytest


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to the fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def load_fixture():
    """
    Return a function that loads a fixture JSON file by name.

    Usage:
        def test_something(load_fixture):
            data = load_fixture("vt_response.json")
    """
    def _load(name: str) -> dict:
        path = FIXTURES_DIR / name
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return _load


@pytest.fixture(autouse=True)
def fake_api_keys(monkeypatch):
    """
    Ensure Config has fake API keys during tests.
    """
    from config import Config

    monkeypatch.setattr(Config, "VT_API_KEY", "test-vt-key")
    monkeypatch.setattr(Config, "ABUSE_API_KEY", "test-abuse-key")
    monkeypatch.setattr(Config, "ABUSE_CH_API_KEY", "test-abusech-key")
    monkeypatch.setattr(Config, "OTX_API_KEY", "test-otx-key")
    monkeypatch.setattr(Config, "GREYNOISE_API_KEY", "test-greynoise-key")


@pytest.fixture(autouse=True)
def disable_http_cache(monkeypatch):
    """
    Disable HTTP caching during tests to avoid mock interference.
    """
    monkeypatch.setenv("CACHE_ENABLED", "false")

    try:
        from storage.cache import reset_session
        reset_session()
    except ImportError:
        pass

    yield

    try:
        from storage.cache import reset_session
        reset_session()
    except ImportError:
        pass


@pytest.fixture
def mock_all_sources():
    """
    Register mocks for all 8 sources in the `responses` library.

    Usage:
        @responses.activate
        def test_something(mock_all_sources):
            mock_all_sources("8.8.8.8", "ip")
            result = enrich_one("8.8.8.8")
            ...
    """
    import responses

    def _register(ioc: str = "8.8.8.8", ioc_type: str = "ip") -> None:
        # VirusTotal
        vt_endpoint = {
            "ip": "ip_addresses",
            "domain": "domains",
            "md5": "files",
            "sha1": "files",
            "sha256": "files",
        }.get(ioc_type, "ip_addresses")
        responses.add(
            responses.GET,
            f"https://www.virustotal.com/api/v3/{vt_endpoint}/{ioc}",
            json={"data": {"attributes": {"last_analysis_stats": {
                "malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 10
            }}}},
            status=200,
        )

        # AbuseIPDB (IP only)
        if ioc_type == "ip":
            responses.add(
                responses.GET,
                "https://api.abuseipdb.com/api/v2/check",
                json={"data": {"abuseConfidenceScore": 0}},
                status=200,
            )

        # URLhaus (domain / IP)
        if ioc_type in ("domain", "ip"):
            responses.add(
                responses.POST,
                "https://urlhaus-api.abuse.ch/v1/host/",
                json={"query_status": "no_results"},
                status=200,
            )

        # OTX
        otx_type = {
            "ip": "IPv4",
            "domain": "domain",
            "md5": "file",
            "sha1": "file",
            "sha256": "file",
        }.get(ioc_type, "IPv4")
        responses.add(
            responses.GET,
            f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc}/general",
            json={"pulse_info": {"count": 0, "pulses": []}},
            status=200,
        )

        # GreyNoise (IP only)
        if ioc_type == "ip":
            responses.add(
                responses.GET,
                f"https://api.greynoise.io/v3/community/{ioc}",
                json={"ip": ioc, "noise": False, "riot": True},
                status=200,
            )

        # ThreatFox (IP / domain / hash)
        if ioc_type in ("ip", "domain", "md5", "sha1", "sha256"):
            responses.add(
                responses.POST,
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query_status": "no_result"},
                status=200,
            )

        # Feodo (IP only)
        if ioc_type == "ip":
            responses.add(
                responses.GET,
                "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                json=[],
                status=200,
            )

    return _register
