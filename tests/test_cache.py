"""
Tests for storage/cache.py — HTTP caching layer.

Covers:
- Session creation and caching behavior
- Cache enable/disable via env var
- Hit/miss tracking
- Stats reporting
- Path handling
"""
import os
from pathlib import Path

import pytest

from storage import cache


@pytest.fixture(autouse=True)
def reset_cache_state(monkeypatch, tmp_path):
    """
    Reset the cache singleton and use a temp directory for each test.

    Ensures tests don't leak cache state between runs.
    """
    monkeypatch.setenv("CACHE_PATH", str(tmp_path / "test_cache"))
    monkeypatch.setenv("CACHE_ENABLED", "true")
    monkeypatch.setenv("CACHE_TTL_HOURS", "24")
    cache.reset_session()
    yield
    cache.reset_session()


class TestCacheSession:
    def test_session_is_created(self):
        """get_session returns a usable session."""
        session = cache.get_session()
        assert session is not None

    def test_session_singleton(self):
        """Repeated calls return the same instance."""
        s1 = cache.get_session()
        s2 = cache.get_session()
        assert s1 is s2

    def test_session_is_cached_when_enabled(self):
        """Session should be a CachedSession subclass when enabled."""
        session = cache.get_session()
        # Our tracked subclass inherits from CachedSession
        assert hasattr(session, "cache")
        assert hasattr(session, "hits")
        assert hasattr(session, "misses")

    def test_cache_disabled_returns_plain_session(self, monkeypatch):
        """When CACHE_ENABLED=false, returns a plain requests.Session."""
        monkeypatch.setenv("CACHE_ENABLED", "false")
        cache.reset_session()

        session = cache.get_session()
        # Plain session has no .cache attribute
        assert not hasattr(session, "cache")

    def test_reset_session_clears_singleton(self):
        """reset_session allows creating a new instance."""
        s1 = cache.get_session()
        cache.reset_session()
        s2 = cache.get_session()
        assert s1 is not s2


class TestCacheStats:
    def test_initial_stats_are_zero(self):
        """Fresh session has zero hits and misses."""
        cache.reset_session()
        stats = cache.cache_stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["total"] == 0
        assert stats["hit_rate"] == 0.0

    def test_stats_include_enabled_flag(self):
        """Stats report whether caching is enabled."""
        stats = cache.cache_stats()
        assert "enabled" in stats
        assert stats["enabled"] is True

    def test_stats_include_config(self):
        """Stats include TTL and path for debugging."""
        stats = cache.cache_stats()
        assert "ttl_hours" in stats
        assert "path" in stats


class TestCacheEnv:
    def test_invalid_ttl_falls_back_to_default(self, monkeypatch):
        """Invalid CACHE_TTL_HOURS doesn't crash — uses default."""
        monkeypatch.setenv("CACHE_TTL_HOURS", "not-a-number")
        cache.reset_session()

        # Should not raise
        session = cache.get_session()
        assert session is not None

    def test_cache_path_directory_created(self, tmp_path, monkeypatch):
        """Missing parent directory is created automatically."""
        custom_path = tmp_path / "new" / "nested" / "cache"
        monkeypatch.setenv("CACHE_PATH", str(custom_path))
        cache.reset_session()

        session = cache.get_session()
        assert session is not None
        # Directory should now exist
        assert custom_path.parent.exists()
