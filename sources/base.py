"""
Shared utilities for 3nricher source modules.

Provides a consistent HTTP request wrapper that converts all network
exceptions into structured error dicts, so source modules can stay
focused on parsing responses.
"""
import logging

import requests

log = logging.getLogger("3nricher.sources")

DEFAULT_TIMEOUT = 15


def safe_request(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    data: dict | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[requests.Response | None, dict | None]:
    """
    Make an HTTP request with structured error handling.

    Returns:
        On success: (response, None)
        On failure: (None, {"status": "error", "reason": "..."})
    """
    method = method.upper()

    if method not in ("GET", "POST"):
        return None, {"status": "error", "reason": f"unsupported method: {method}"}

    try:
        if method == "GET":
            r = requests.get(url, headers=headers, params=params, timeout=timeout)
        else:
            r = requests.post(url, headers=headers, params=params, data=data, timeout=timeout)
        return r, None

    except requests.Timeout:
        log.warning("Timeout calling %s", url)
        return None, {"status": "error", "reason": "request timed out"}

    except requests.ConnectionError as e:
        log.warning("Connection error calling %s: %s", url, e)
        return None, {"status": "error", "reason": "connection error"}

    except requests.RequestException as e:
        log.warning("Request failed for %s: %s", url, e)
        return None, {"status": "error", "reason": f"request failed: {e}"}


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
