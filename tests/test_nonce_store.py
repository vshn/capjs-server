"""Tests for NonceStore protocol and MemoryNonceStore."""

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
