"""
Shared utilities for 3nricher source modules.

Provides a consistent HTTP request wrapper with:
- Structured error handling (no exceptions leak to callers)
- Retry with exponential backoff + jitter
- Respects the Retry-After header from rate-limited APIs
- Centralized timeout enforcement
- Transparent HTTP response caching (via storage.cache)
- Optional JSON body support for POST requests
"""
import logging
import random
import time

import requests

from storage.cache import get_session

log = logging.getLogger("3nricher.sources")

DEFAULT_TIMEOUT = 15
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF_BASE = 1.0  # seconds


def safe_request(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    data: dict | None = None,
    json_body: dict | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    backoff_base: float = DEFAULT_BACKOFF_BASE,
) -> tuple[requests.Response | None, dict | None]:
    """
    Make an HTTP request with structured error handling, retry, and caching.

    Retries on:
    - Network errors (timeout, connection refused, DNS failure)
    - HTTP 429 (rate limited)
    - HTTP 5xx (server errors)

    Uses exponential backoff with jitter, and honors the Retry-After
    header when the server sends one.

    Cached error responses (429 / 5xx from a prior run) are discarded
    and refetched so stale failures don't mask a recovered API.

    Args:
        method:        "GET" or "POST"
        url:           Full URL
        headers:       Optional request headers
        params:        Optional query parameters (GET)
        data:          Optional form data (POST, form-encoded)
        json_body:     Optional JSON body (POST, application/json)
        timeout:       Request timeout in seconds
        retries:       Max number of retry attempts after the first failure
        backoff_base:  Base delay for exponential backoff (seconds)

    Returns:
        On success:  (response, None)
        On failure:  (None, {"status": "error", "reason": "..."})
    """
    method = method.upper()

    if method not in ("GET", "POST"):
        return None, {"status": "error", "reason": f"unsupported method: {method}"}

    last_response: requests.Response | None = None
    session = get_session()

    for attempt in range(retries + 1):
        is_last_attempt = (attempt == retries)

        # ---- Network call (through cached session) ----
        try:
            if method == "GET":
                r = session.get(
                    url, headers=headers, params=params, timeout=timeout,
                )
            else:  # POST
                r = session.post(
                    url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json_body,
                    timeout=timeout,
                )
        except requests.Timeout:
            if is_last_attempt:
                log.warning("Timeout calling %s after %d attempt(s)", url, attempt + 1)
                return None, {"status": "error", "reason": "request timed out"}
            _sleep_backoff(attempt, backoff_base, url, "timeout")
            continue

        except requests.ConnectionError as e:
            if is_last_attempt:
                log.warning("Connection error calling %s after %d attempt(s): %s",
                            url, attempt + 1, e)
                return None, {"status": "error", "reason": "connection error"}
            _sleep_backoff(attempt, backoff_base, url, "connection error")
            continue

        except requests.RequestException as e:
            if is_last_attempt:
                log.warning("Request failed for %s after %d attempt(s): %s",
                            url, attempt + 1, e)
                return None, {"status": "error", "reason": f"request failed: {e}"}
            _sleep_backoff(attempt, backoff_base, url, "request exception")
            continue

        # ---- Got a response ----
        last_response = r

        # If we got a cached error response, discard and refetch.
        if getattr(r, "from_cache", False) and _is_error_status(r.status_code):
            log.debug(
                "Discarding cached error response for %s (HTTP %d)",
                url, r.status_code,
            )
            _invalidate_cached_url(url, method, params, data)

            if is_last_attempt:
                log.warning("HTTP %d from %s after %d attempt(s)",
                            r.status_code, url, attempt + 1)
                return r, None

            _sleep_backoff(attempt, backoff_base, url,
                           f"cached HTTP {r.status_code}")
            continue

        # ---- Retry logic for rate limits / server errors ----
        if _is_error_status(r.status_code):
            if is_last_attempt:
                log.warning("HTTP %d from %s after %d attempt(s)",
                            r.status_code, url, attempt + 1)
                return r, None

            retry_after = _parse_retry_after(r)
            if retry_after is not None:
                log.warning(
                    "HTTP %d from %s — Retry-After: %.1fs (attempt %d/%d)",
                    r.status_code, url, retry_after, attempt + 1, retries,
                )
                time.sleep(retry_after)
            else:
                _sleep_backoff(attempt, backoff_base, url, f"HTTP {r.status_code}")
            continue

        # Non-retryable success status — return immediately
        return r, None

    # Safety net (should not be reached)
    return last_response, None


# ---------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------
def _is_error_status(status_code: int) -> bool:
    """True for HTTP 429 or 5xx."""
    return status_code == 429 or 500 <= status_code < 600


def _invalidate_cached_url(
    url: str,
    method: str,
    params: dict | None,
    data: dict | None,
) -> None:
    """Remove a cached response so the next call hits the API."""
    try:
        session = get_session()
        cache = getattr(session, "cache", None)
        if cache is None:
            return

        if hasattr(cache, "delete"):
            cache.delete(urls=[url])
        elif hasattr(cache, "remove_expired_responses"):
            log.debug("Cache delete unavailable for %s", url)
    except Exception as e:
        log.debug("Failed to invalidate cache for %s: %s", url, e)


def _backoff_delay(attempt: int, base: float) -> float:
    """Exponential backoff with jitter: base * 2^attempt + random(0, 1)."""
    return base * (2 ** attempt) + random.uniform(0, 1)


def _parse_retry_after(r: requests.Response) -> float | None:
    """Extract Retry-After header value in seconds, if present and valid."""
    raw = r.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        return float(raw)
    except (ValueError, TypeError):
        return None


def _sleep_backoff(attempt: int, base: float, url: str, reason: str) -> None:
    """Sleep with exponential backoff, logging the wait."""
    wait = _backoff_delay(attempt, base)
    log.warning("Retrying %s after %s — waiting %.1fs (attempt %d)",
                url, reason, wait, attempt + 1)
    time.sleep(wait)


def http_error_reason(status_code: int) -> str:
    """Map HTTP status codes to human-friendly reason strings."""
    mapping = {
        400: "bad request",
        401: "invalid API key",
        403: "forbidden",
        404: "not found",
        405: "method not allowed",
        408: "request timeout",
        429: "rate limited",
        500: "server error",
        502: "bad gateway",
        503: "service unavailable",
        504: "gateway timeout",
    }
    return mapping.get(status_code, f"http {status_code}")
