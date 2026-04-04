"""
utils.py — Shared helpers: token-bucket rate limiter, retry decorator.
"""

import time
import threading
from functools import wraps


# ── Token-bucket rate limiter ─────────────────────────────────────────────────

class TokenBucket:
    """Thread-safe token-bucket for controlling request rates."""

    def __init__(self, rate: float = 0.05, burst: int = 20):
        """
        Args:
            rate:  minimum seconds between tokens (1/rate = max requests/sec).
            burst: max tokens that can accumulate (allows short bursts).
        """
        self.rate = max(rate, 0.001)  # avoid division by zero
        self.capacity = burst
        self.tokens = float(burst)
        self._lock = threading.Lock()
        self._last = time.monotonic()

    def acquire(self) -> None:
        """Block until a token is available."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self.tokens = min(self.capacity, self.tokens + elapsed / self.rate)
                self._last = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
            # Not enough tokens — sleep briefly and retry
            time.sleep(self.rate * 0.5)


# Global DNS rate limiter — initialised lazily by init_dns_bucket()
_dns_bucket: TokenBucket | None = None


def init_dns_bucket(rate: float = 0.05, burst: int = 20) -> None:
    """Create (or replace) the global DNS token bucket."""
    global _dns_bucket
    _dns_bucket = TokenBucket(rate=rate, burst=burst)


def acquire_dns_token() -> None:
    """Acquire one DNS token, blocking if necessary. No-op if bucket not initialised."""
    if _dns_bucket is not None:
        _dns_bucket.acquire()


# ── Exponential back-off retry decorator ──────────────────────────────────────

def retry_on_exception(backoff: list[int] | None = None,
                       exc: tuple = (Exception,)):
    """Retry a function with exponential back-off on specified exceptions.

    Args:
        backoff: list of sleep durations between retries (e.g. [1, 2, 4]).
        exc:     tuple of exception types to catch.
    """
    if backoff is None:
        backoff = [1, 2, 4]

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            attempts = [0] + backoff
            last_exc = None
            for attempt, delay in enumerate(attempts):
                if attempt > 0:
                    time.sleep(delay)
                try:
                    return fn(*args, **kwargs)
                except exc as e:
                    last_exc = e
                    if attempt == len(backoff):
                        raise
            raise last_exc  # should not reach here, but safety net
        return wrapper
    return decorator
