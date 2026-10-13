"""
Tests for sources/limiter.py — token bucket rate limiter.
"""
import time

import pytest

from sources.limiter import TokenBucket


class TestTokenBucket:
    def test_burst_within_capacity(self):
        """Should consume up to `capacity` tokens instantly."""
        bucket = TokenBucket(capacity=3, refill_per_second=1)
        assert bucket.consume() is True
        assert bucket.consume() is True
        assert bucket.consume() is True
        # 4th consume fails — no tokens left
        assert bucket.consume() is False

    def test_throttles_beyond_capacity(self):
        """Should block when tokens are exhausted."""
        bucket = TokenBucket(capacity=1, refill_per_second=5, name="test")
        bucket.wait_and_consume()  # consumes the only token

        start = time.monotonic()
        bucket.wait_and_consume()  # must wait ~0.2s for refill
        elapsed = time.monotonic() - start

        assert 0.15 <= elapsed <= 0.5, f"Expected ~0.2s wait, got {elapsed:.2f}s"

    def test_timeout_returns_false(self):
        """Should return False if tokens don't arrive within timeout."""
        bucket = TokenBucket(capacity=1, refill_per_second=0.01)  # very slow
        bucket.wait_and_consume()  # drains the bucket

        result = bucket.wait_and_consume(timeout=0.2)
        assert result is False

    def test_invalid_capacity_raises(self):
        """Should reject invalid capacity."""
        with pytest.raises(ValueError):
            TokenBucket(capacity=0, refill_per_second=1)

    def test_invalid_refill_rate_raises(self):
        """Should reject invalid refill rate."""
        with pytest.raises(ValueError):
            TokenBucket(capacity=1, refill_per_second=0)
