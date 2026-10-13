"""
Recency weighting for 3nricher.

Some source signals are more meaningful when recent. An IP reported as
malicious yesterday is more relevant than one reported 3 years ago.

This module provides a multiplier (0.3 – 1.0) based on the age of a
timestamp. It's applied selectively:

    - AbuseIPDB "last_reported"      → yes
    - URLhaus "first_seen"           → yes
    - VirusTotal verdict             → no (it's a live snapshot)
    - MalwareBazaar "first_seen"     → no (a known sample stays known)
    - OTX pulses                     → no (pulse dates aren't exposed cleanly)

Design:
    - Returns 1.0 when the timestamp is missing or unparseable (no penalty
      for unknown age — matches prior behavior).
    - Accepts ISO 8601 or the "YYYY-MM-DD HH:MM:SS" format used by abuse.ch.
    - Uses UTC for comparison.
"""
import logging
from datetime import datetime, timezone

log = logging.getLogger("3nricher.recency")


# Multiplier thresholds: (max_age_days, multiplier), checked in order.
# First match wins. Fallback is the last entry (no upper bound).
_RECENCY_TIERS = [
    (7, 1.0),      # < 7 days    → full weight
    (30, 0.9),     # < 30 days   → 90%
    (90, 0.75),    # < 90 days   → 75%
    (365, 0.5),    # < 1 year    → 50%
    (None, 0.3),   # older       → 30%
]


def _parse_timestamp(raw: str) -> datetime | None:
    """
    Parse a timestamp string into a timezone-aware datetime (UTC).

    Supports:
        - ISO 8601 with 'Z' or offset: "2026-10-11T12:00:09+00:00"
        - abuse.ch format:            "2020-07-15 08:04:18"
        - ISO 8601 without tz:        "2026-10-11T12:00:09"

    Returns None if parsing fails.
    """
    if not raw or not isinstance(raw, str):
        return None

    raw = raw.strip()

    # Try ISO 8601 (handles 'Z' automatically in Python 3.11+)
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        pass

    # Try abuse.ch format: "2020-07-15 08:04:18"
    try:
        dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        pass

    log.debug("Could not parse timestamp: %r", raw)
    return None


def recency_multiplier(timestamp: str | None) -> float:
    """
    Return a multiplier between 0.3 and 1.0 based on the age of the timestamp.

    Args:
        timestamp: ISO 8601 or abuse.ch format string, or None.

    Returns:
        1.0 if the timestamp is missing or unparseable (no penalty).
        Otherwise a value from _RECENCY_TIERS.
    """
    dt = _parse_timestamp(timestamp or "")
    if dt is None:
        return 1.0

    now = datetime.now(timezone.utc)
    age_days = (now - dt).days

    # Negative age (future timestamp) → treat as fresh
    if age_days < 0:
        return 1.0

    for max_days, multiplier in _RECENCY_TIERS:
        if max_days is None or age_days < max_days:
            return multiplier

    # Unreachable — last tier has max_days=None
    return 0.3
