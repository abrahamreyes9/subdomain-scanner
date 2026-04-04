"""
context.py — ScanContext: progress tracking, cancellation, and event emission.
"""

import threading
import queue
from typing import Callable


class ScanContext:
    """Thread-safe scan state: progress counters, cancellation, emit wrapper."""

    def __init__(self, q: queue.Queue | None = None):
        self._q = q
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        self.total = 0
        self.completed = 0
        # Accumulated results for output formatting
        self.found: set[str] = set()
        self.resolved: dict[str, str] = {}

    # ── Emit ──────────────────────────────────────────────────────────────────

    def emit(self, data: dict) -> None:
        """Push an event into the SSE queue (if one is attached)."""
        if self._q is not None:
            try:
                self._q.put(data, timeout=5.0)
            except queue.Full:
                self.cancel()

    # ── Progress ──────────────────────────────────────────────────────────────

    def inc_total(self, n: int = 1) -> None:
        with self._lock:
            self.total += n

    def inc_done(self, n: int = 1) -> None:
        with self._lock:
            self.completed += n

    @property
    def progress_pct(self) -> float:
        with self._lock:
            if self.total == 0:
                return 0.0
            return round(self.completed / self.total * 100, 1)

    # ── Cancellation ──────────────────────────────────────────────────────────

    def cancel(self) -> None:
        """Signal all phases to stop."""
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()
