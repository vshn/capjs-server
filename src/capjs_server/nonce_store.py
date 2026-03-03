"""Pluggable nonce store for replay protection."""

from __future__ import annotations

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
        self._lock = threading.Lock()

    def mark_used(self, nonce: str, ttl_seconds: float) -> bool:
        now = time.time()
        with self._lock:
            # Lazy cleanup of expired entries
            expired = [k for k, exp in self._used.items() if exp <= now]
            for k in expired:
                del self._used[k]

            if nonce in self._used:
                return False

            self._used[nonce] = now + ttl_seconds
            return True
