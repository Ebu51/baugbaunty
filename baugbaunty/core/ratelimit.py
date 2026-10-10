"""Politeness controls: a thread-safe token-bucket rate limiter.

Bug bounty programs expect you to be a good guest. Hammering a target can
degrade service for real users, get you banned, and in some jurisdictions
crosses from testing into abuse. Every network-facing module routes its
requests through a shared limiter so the whole toolkit stays under a global
requests-per-second budget, with optional per-host budgets on top.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict


class TokenBucket:
    """Classic token bucket. ``rate`` tokens are added per second up to
    ``capacity``. ``acquire`` blocks until a token is available."""

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else max(rate, 1.0))
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._last = now

    def acquire(self, tokens: float = 1.0) -> None:
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                wait = deficit / self.rate
            time.sleep(min(wait, 0.25))


class RateLimiter:
    """Global + per-host token buckets.

    A request must satisfy BOTH the global budget and the per-host budget,
    so a single noisy host can never exceed its share and the aggregate never
    exceeds the global ceiling.
    """

    def __init__(
        self,
        global_rps: float = 10.0,
        per_host_rps: float | None = 5.0,
        global_burst: float | None = None,
        per_host_burst: float | None = None,
    ) -> None:
        self._global = TokenBucket(global_rps, global_burst)
        self._per_host_rps = per_host_rps
        self._per_host_burst = per_host_burst
        self._hosts: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def _host_bucket(self, host: str) -> TokenBucket | None:
        if not self._per_host_rps:
            return None
        with self._lock:
            bucket = self._hosts.get(host)
            if bucket is None:
                bucket = TokenBucket(self._per_host_rps, self._per_host_burst)
                self._hosts[host] = bucket
            return bucket

    def acquire(self, host: str | None = None) -> None:
        if host:
            bucket = self._host_bucket(host)
            if bucket is not None:
                bucket.acquire()
        self._global.acquire()


class ConcurrencyGuard:
    """A simple bounded-concurrency semaphore usable as a context manager."""

    def __init__(self, limit: int) -> None:
        self._sem = threading.BoundedSemaphore(max(1, int(limit)))

    def __enter__(self) -> "ConcurrencyGuard":
        self._sem.acquire()
        return self

    def __exit__(self, *exc: object) -> None:
        self._sem.release()


# Lightweight per-host failure tracking so modules can back off from hosts that
# are clearly down, rather than retrying into a wall.
class HostHealth:
    def __init__(self, fail_threshold: int = 5) -> None:
        self._failures: dict[str, int] = defaultdict(int)
        self._threshold = fail_threshold
        self._lock = threading.Lock()

    def record_failure(self, host: str) -> None:
        with self._lock:
            self._failures[host] += 1

    def record_success(self, host: str) -> None:
        with self._lock:
            self._failures[host] = 0

    def is_unhealthy(self, host: str) -> bool:
        with self._lock:
            return self._failures[host] >= self._threshold
