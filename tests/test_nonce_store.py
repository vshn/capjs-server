"""Tests for NonceStore protocol and MemoryNonceStore."""

import time
from unittest.mock import patch

from capjs_server.nonce_store import MemoryNonceStore


class TestMemoryNonceStore:
    def test_first_use_returns_true(self):
        store = MemoryNonceStore()
        assert store.mark_used("nonce-1", ttl_seconds=60.0) is True

    def test_second_use_returns_false(self):
        store = MemoryNonceStore()
        store.mark_used("nonce-1", ttl_seconds=60.0)
        assert store.mark_used("nonce-1", ttl_seconds=60.0) is False

    def test_different_nonces_independent(self):
        store = MemoryNonceStore()
        assert store.mark_used("nonce-1", ttl_seconds=60.0) is True
        assert store.mark_used("nonce-2", ttl_seconds=60.0) is True

    def test_expired_nonce_cleaned_up(self):
        store = MemoryNonceStore()
        with patch("capjs_server.nonce_store.time") as mock_time:
            mock_time.time.return_value = 1000.0
            store.mark_used("nonce-1", ttl_seconds=10.0)
            # Advance past expiry
            mock_time.time.return_value = 1011.0
            # New call triggers cleanup; old nonce should be gone
            store.mark_used("other", ttl_seconds=10.0)
            assert "nonce-1" not in store._used

    def test_expired_nonce_can_be_reused(self):
        store = MemoryNonceStore()
        with patch("capjs_server.nonce_store.time") as mock_time:
            mock_time.time.return_value = 1000.0
            store.mark_used("nonce-1", ttl_seconds=10.0)
            mock_time.time.return_value = 1011.0
            # After expiry, same nonce is accepted again
            assert store.mark_used("nonce-1", ttl_seconds=10.0) is True

    def test_cleanup_with_ttls_out_of_order(self):
        """A short TTL stored after a long one still expires on time."""
        store = MemoryNonceStore()
        with patch("capjs_server.nonce_store.time") as mock_time:
            mock_time.time.return_value = 1000.0
            store.mark_used("long", ttl_seconds=100.0)
            store.mark_used("short", ttl_seconds=5.0)
            mock_time.time.return_value = 1006.0
            store.mark_used("other", ttl_seconds=100.0)
            assert "short" not in store._used
            assert store.mark_used("long", ttl_seconds=100.0) is False
            assert store.mark_used("short", ttl_seconds=5.0) is True

    def test_cost_does_not_grow_with_live_entries(self):
        """Every call used to scan the whole store under the lock, so an
        unauthenticated client could make each call slower by filling it."""
        small, large = MemoryNonceStore(), MemoryNonceStore()
        for i in range(100):
            small.mark_used(f"n{i}", ttl_seconds=600.0)
        for i in range(20_000):
            large.mark_used(f"n{i}", ttl_seconds=600.0)

        def per_call(store):
            start = time.perf_counter()
            for i in range(500):
                store.mark_used(f"probe{i}", ttl_seconds=600.0)
            return time.perf_counter() - start

        # 200x the entries: a full scan is about 200 times slower, a heap is
        # not. The margin absorbs noise on a loaded CI runner.
        assert per_call(large) < 10 * per_call(small)
