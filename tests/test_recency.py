"""
Tests for recency.py — age-based weighting multipliers.
"""
from datetime import datetime, timezone, timedelta

import pytest

from recency import recency_multiplier, _parse_timestamp


def _iso(days_ago: int) -> str:
    """Helper: ISO timestamp N days in the past."""
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


class TestRecencyMultiplier:
    def test_fresh_report_returns_1_0(self):
        """Reports under 7 days old should have full weight."""
        assert recency_multiplier(_iso(0)) == 1.0
        assert recency_multiplier(_iso(1)) == 1.0
        assert recency_multiplier(_iso(6)) == 1.0

    def test_recent_report_returns_0_9(self):
        """7–29 days old → 0.9."""
        assert recency_multiplier(_iso(10)) == 0.9
        assert recency_multiplier(_iso(29)) == 0.9

    def test_aging_report_returns_0_75(self):
        """30–89 days old → 0.75."""
        assert recency_multiplier(_iso(45)) == 0.75
        assert recency_multiplier(_iso(89)) == 0.75

    def test_old_report_returns_0_5(self):
        """90–364 days old → 0.5."""
        assert recency_multiplier(_iso(120)) == 0.5
        assert recency_multiplier(_iso(364)) == 0.5

    def test_stale_report_returns_0_3(self):
        """365+ days old → 0.3."""
        assert recency_multiplier(_iso(400)) == 0.3
        assert recency_multiplier(_iso(730)) == 0.3

    def test_missing_timestamp_returns_1_0(self):
        """Missing timestamp → no penalty (fail-safe)."""
        assert recency_multiplier(None) == 1.0
        assert recency_multiplier("") == 1.0
        assert recency_multiplier("   ") == 1.0

    def test_unparseable_timestamp_returns_1_0(self):
        """Garbage timestamp → no penalty."""
        assert recency_multiplier("not-a-date") == 1.0
        assert recency_multiplier("12345") == 1.0

    def test_abuse_ch_format_parses(self):
        """The 'YYYY-MM-DD HH:MM:SS' format from abuse.ch should parse."""
        # 2020-07-15 is more than 1 year old → 0.3
        assert recency_multiplier("2020-07-15 08:04:18") == 0.3

    def test_z_suffix_parses(self):
        """ISO 8601 with 'Z' suffix should parse."""
        # 1 day ago in Z format
        recent = (datetime.now(timezone.utc) - timedelta(days=1))
        z_format = recent.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert recency_multiplier(z_format) == 1.0

    def test_future_timestamp_returns_1_0(self):
        """Future timestamps → treated as fresh (no penalty)."""
        future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        assert recency_multiplier(future) == 1.0


class TestParseTimestamp:
    def test_iso_with_z(self):
        dt = _parse_timestamp("2026-10-11T12:00:09Z")
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 10

    def test_iso_with_offset(self):
        dt = _parse_timestamp("2026-10-11T12:00:09+00:00")
        assert dt is not None
        assert dt.year == 2026

    def test_abuse_ch_format(self):
        dt = _parse_timestamp("2020-07-15 08:04:18")
        assert dt is not None
        assert dt.year == 2020
        assert dt.month == 7

    def test_returns_none_for_garbage(self):
        assert _parse_timestamp("not-a-date") is None
        assert _parse_timestamp("") is None
        assert _parse_timestamp(None) is None
