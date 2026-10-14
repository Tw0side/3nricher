"""
HTTP response caching for 3nricher.

Wraps `requests-cache` to provide a persistent SQLite-backed HTTP cache
with manual hit/miss tracking (requests-cache 1.3.x removed this).

Usage:
    from storage.cache import get_session, cache_stats

    session = get_session()
    response = session.get("https://api.example.com/ioc/8.8.8.8")
    print(response.from_cache)  # True/False
"""
import logging
import os
from pathlib import Path

import requests
import requests_cache

log = logging.getLogger("3nricher.storage.cache")


# Defaults
DEFAULT_CACHE_PATH = "cache/3nricher"
DEFAULT_TTL_HOURS = 24


# ---------------------------------------------------------------
# Manual hit/miss tracking
# ---------------------------------------------------------------
class _TrackedSession(requests_cache.CachedSession):
    """
    CachedSession subclass that counts hits and misses.

    requests-cache 1.3.x removed the built-in .hits and .misses counters,
    so we track them ourselves by inspecting `response.from_cache`.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._hits = 0
        self._misses = 0

    def send(self, request, **kwargs):
        response = super().send(request, **kwargs)
        # from_cache is set by requests-cache on the response object
        if getattr(response, "from_cache", False):
            self._hits += 1
        else:
            self._misses += 1
        return response

    @property
    def hits(self) -> int:
        return self._hits

    @property
    def misses(self) -> int:
        return self._misses


# ---------------------------------------------------------------
# Env helpers
# ---------------------------------------------------------------
def _is_cache_enabled() -> bool:
    raw = os.getenv("CACHE_ENABLED", "true").lower()
    return raw not in ("false", "0", "no", "off")


def _get_cache_path() -> str:
    path = os.getenv("CACHE_PATH", DEFAULT_CACHE_PATH)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return path


def _get_ttl_hours() -> int:
    try:
        return int(os.getenv("CACHE_TTL_HOURS", str(DEFAULT_TTL_HOURS)))
    except ValueError:
        log.warning("Invalid CACHE_TTL_HOURS, using default %d", DEFAULT_TTL_HOURS)
        return DEFAULT_TTL_HOURS


# ---------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------
_session = None


def get_session() -> requests.Session:
    """
    Return the process-wide cached session.

    If caching is disabled, returns a plain requests.Session.
    """
    global _session

    if _session is not None:
        return _session

    if not _is_cache_enabled():
        log.info("HTTP caching disabled — using plain requests session")
        _session = requests.Session()
        return _session

    cache_path = _get_cache_path()
    ttl_hours = _get_ttl_hours()

    log.info("HTTP caching enabled: path=%s ttl=%dh", cache_path, ttl_hours)

    _session = _TrackedSession(
        cache_path,
        backend="sqlite",
        expire_after=ttl_hours * 3600,
    )
    return _session


def reset_session() -> None:
    """Reset the cached session (primarily for tests)."""
    global _session
    _session = None


def cache_stats(session: requests.Session | None = None) -> dict:
    """
    Return cache hit/miss stats.

    For tracked sessions, reads our manual counters.
    For plain sessions or untracked caches, returns zeros.
    """
    session = session or get_session()

    hits = getattr(session, "hits", 0)
    misses = getattr(session, "misses", 0)

    total = hits + misses
    hit_rate = (hits / total) if total > 0 else 0.0

    return {
        "hits": hits,
        "misses": misses,
        "total": total,
        "hit_rate": round(hit_rate, 3),
        "enabled": _is_cache_enabled(),
        "path": _get_cache_path() if _is_cache_enabled() else None,
        "ttl_hours": _get_ttl_hours() if _is_cache_enabled() else 0,
    }
