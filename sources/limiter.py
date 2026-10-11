"""
Thread-safe token bucket rate limiter.

Used by source modules to respect per-API rate limits without blocking
unnecessarily. Each source owns its own bucket (e.g., VT has 4/min,
AbuseIPDB has ~17/min, OTX has 600/min).

Design:
- Tokens refill continuously at a steady rate.
- Each request consumes one token.
- If no tokens are available, the caller blocks until one is.
- A threading.Lock protects the bucket for future parallel use.

Example:
    bucket = TokenBucket(capacity=4, refill_per_second=4/60)
    bucket.wait_and_consume()   # blocks until a token is available
    # ... make request ...
"""
import logging
import threading
import time

log = logging.getLogger("3nricher.limiter")


class TokenBucket:
    """
    Thread-safe token bucket rate limiter.

    Args:
        capacity:           Maximum tokens the bucket holds (burst size).
        refill_per_second:  Tokens added per second (sustained rate).
        name:               Optional name for logging/debugging.
    """

    def __init__(self, capacity: int, refill_per_second: float, name: str = "bucket"):
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        if refill_per_second <= 0:
            raise ValueError("refill_per_second must be > 0")

        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.refill_rate = float(refill_per_second)
        self.name = name

        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def _refill(self) -> None:
        """Add tokens based on elapsed time. Caller must hold the lock."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        if elapsed > 0:
            self.tokens = min(
                self.capacity,
                self.tokens + elapsed * self.refill_rate,
            )
            self.last_refill = now

    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens without blocking.

        Returns True if tokens were available and consumed,
        False otherwise.
        """
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def wait_and_consume(self, tokens: int = 1, timeout: float | None = None) -> bool:
        """
        Block until `tokens` are available, then consume them.

        Args:
            tokens:  Number of tokens to consume (default 1).
            timeout: Optional maximum seconds to wait. None = wait forever.

        Returns:
            True if tokens were consumed.
            False if timeout expired without enough tokens.
        """
        start = time.monotonic()

        while True:
            if self.consume(tokens):
                return True

            if timeout is not None and (time.monotonic() - start) >= timeout:
                log.warning("[%s] Timeout waiting for %d token(s)", self.name, tokens)
                return False

            # Small sleep to avoid busy-waiting
            time.sleep(0.05)

    def available(self) -> float:
        """Return the current number of available tokens (approximate)."""
        with self.lock:
            self._refill()
            return self.tokens
