"""Pluggable nonce store for replay protection."""

from __future__ import annotations

import heapq
import threading
import time
from typing import Protocol, runtime_checkable

__all__ = ["NonceStore", "MemoryNonceStore"]


@runtime_checkable
class NonceStore(Protocol):
    """Interface for tracking used challenge nonces.

    Implement this protocol to use a shared store (Redis, memcached, etc.)
    for strict single-use enforcement across multiple server instances.
    """

    def mark_used(self, nonce: str, ttl_seconds: float) -> bool:
        """Mark a nonce as used. Return True if first use, False if already seen."""
        ...


class MemoryNonceStore:
    """In-memory nonce store with automatic expiry.

    Thread-safe. Suitable for single-process deployments. With N processes,
    a nonce can be redeemed at most N times (once per process).
    """

    def __init__(self) -> None:
        self._used: dict[str, float] = {}
        # Min-heap of (expiry, nonce), so cleanup touches only expired
        # entries instead of scanning the whole store under the lock.
        self._expiries: list[tuple[float, str]] = []
        self._lock = threading.Lock()

    def mark_used(self, nonce: str, ttl_seconds: float) -> bool:
        now = time.time()
        with self._lock:
            while self._expiries and self._expiries[0][0] <= now:
                exp, old = heapq.heappop(self._expiries)
                # A nonce re-added after expiring has a newer heap entry.
                if self._used.get(old) == exp:
                    del self._used[old]

            if nonce in self._used:
                return False

            exp = now + ttl_seconds
            self._used[nonce] = exp
            heapq.heappush(self._expiries, (exp, nonce))
            return True
