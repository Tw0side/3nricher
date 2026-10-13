"""
Shared pytest fixtures for 3nricher tests.

Provides:
- Path to fixtures directory
- Helper to load fixture JSON files
- Fake API keys via monkeypatch so tests don't need a real .env
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
    autouse=True means this runs before every test automatically.
    """
    from config import Config

    monkeypatch.setattr(Config, "VT_API_KEY", "test-vt-key")
    monkeypatch.setattr(Config, "ABUSE_API_KEY", "test-abuse-key")
    monkeypatch.setattr(Config, "ABUSE_CH_API_KEY", "test-abusech-key")
    monkeypatch.setattr(Config, "OTX_API_KEY", "test-otx-key")
