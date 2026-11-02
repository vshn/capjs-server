"""Tests for CapServer — the main public API."""

import hashlib
import time
from unittest.mock import patch

import pytest

from capjs_server import CapServer, MemoryNonceStore
from capjs_server.prng import prng


@pytest.fixture
def cap():
    return CapServer(
        secret_key="test-secret",
        challenge_count=2,
        challenge_size=8,
        challenge_difficulty=1,
        token_expiry_ms=300_000,
    )


def _solve(token, config):
    """Brute-force solver for testing."""
    solutions = []
    for i in range(1, config["c"] + 1):
        salt = prng(token + str(i), config["s"])
        target = prng(token + str(i) + "d", config["d"])
        for n in range(10_000_000):
            h = hashlib.sha256((salt + str(n)).encode()).hexdigest()
            if h.startswith(target):
                solutions.append(n)
                break
        else:
            raise RuntimeError(f"Could not solve challenge {i}")
    return solutions


class TestCreateChallenge:
    def test_returns_required_fields(self, cap):
        data = cap.create_challenge()
        assert "challenge" in data
        assert "token" in data
        assert "expires" in data
        ch = data["challenge"]
        assert ch["c"] == 2
        assert ch["s"] == 8
        assert ch["d"] == 1

    def test_expires_in_future(self, cap):
        data = cap.create_challenge()
        assert data["expires"] > time.time() * 1000


class TestRedeem:
    def test_valid_solutions_succeed(self, cap):
        data = cap.create_challenge()
        solutions = _solve(data["token"], data["challenge"])
        result = cap.redeem(data["token"], solutions)
        assert result["success"] is True
        assert "token" in result
        assert "expires" in result

    def test_wrong_solutions_fail(self, cap):
        data = cap.create_challenge()
        wrong = [999999] * data["challenge"]["c"]
        result = cap.redeem(data["token"], wrong)
        assert result["success"] is False

    def test_tampered_token_fails(self, cap):
        data = cap.create_challenge()
        tampered = "x" + data["token"][1:]
        result = cap.redeem(tampered, [0, 0])
        assert result["success"] is False

    def test_wrong_solution_count_fails(self, cap):
        data = cap.create_challenge()
        result = cap.redeem(data["token"], [0])
        assert result["success"] is False

    def test_expired_challenge_fails(self, cap):
        with patch("capjs_server.tokens.time") as mock_time:
            mock_time.time.return_value = 1.0
            data = cap.create_challenge()
            mock_time.time.return_value = 2000.0
            result = cap.redeem(data["token"], [0, 0])
            assert result["success"] is False

    def test_replay_rejected(self, cap):
        data = cap.create_challenge()
        solutions = _solve(data["token"], data["challenge"])
        first = cap.redeem(data["token"], solutions)
        assert first["success"] is True
        second = cap.redeem(data["token"], solutions)
        assert second["success"] is False

    def test_custom_nonce_store(self):
        class FakeStore:
            def __init__(self):
                self.calls = []

            def mark_used(self, nonce, ttl_seconds):
                self.calls.append((nonce, ttl_seconds))
                return True

        store = FakeStore()
        cap = CapServer(
            secret_key="test-secret",
            challenge_count=2,
            challenge_size=8,
            challenge_difficulty=1,
            nonce_store=store,
        )
        data = cap.create_challenge()
        solutions = _solve(data["token"], data["challenge"])
        cap.redeem(data["token"], solutions)
        assert len(store.calls) == 1
        assert store.calls[0][1] > 0  # ttl_seconds is positive


class TestValidate:
    def test_valid_token_accepted(self, cap):
        data = cap.create_challenge()
        solutions = _solve(data["token"], data["challenge"])
        result = cap.redeem(data["token"], solutions)
        assert cap.validate(result["token"]) is True

    def test_invalid_token_rejected(self, cap):
        assert cap.validate("bad:token:garbage") is False
        assert cap.validate("") is False
        assert cap.validate(None) is False

    def test_tampered_token_rejected(self, cap):
        data = cap.create_challenge()
        solutions = _solve(data["token"], data["challenge"])
        result = cap.redeem(data["token"], solutions)
        tampered = "x" + result["token"][1:]
        assert cap.validate(tampered) is False

    def test_different_secret_rejects(self, cap):
        data = cap.create_challenge()
        solutions = _solve(data["token"], data["challenge"])
        result = cap.redeem(data["token"], solutions)
        other = CapServer(secret_key="other-secret")
        assert other.validate(result["token"]) is False


def _verification_token(cap):
    data = cap.create_challenge()
    solutions = _solve(data["token"], data["challenge"])
    return cap.redeem(data["token"], solutions)["token"]


class _RecordingStore:
    def __init__(self):
        self.calls = []

    def mark_used(self, nonce, ttl_seconds):
        self.calls.append((nonce, ttl_seconds))
        return True


class TestValidateSingleUse:
    """A verification token buys one accepted submission (issue 31)."""

    def test_second_validate_rejected(self, cap):
        token = _verification_token(cap)
        assert cap.validate(token) is True
        assert cap.validate(token) is False

    def test_check_without_consuming_leaves_token_usable(self, cap):
        token = _verification_token(cap)
        assert cap.validate(token, consume=False) is True
        assert cap.validate(token, consume=False) is True
        assert cap.validate(token) is True
        assert cap.validate(token) is False

    def test_shared_store_rejects_replay_on_another_instance(self):
        store = MemoryNonceStore()
        kwargs = dict(
            secret_key="test-secret",
            challenge_count=2,
            challenge_size=8,
            challenge_difficulty=1,
            nonce_store=store,
        )
        first, second = CapServer(**kwargs), CapServer(**kwargs)
        token = _verification_token(first)
        assert first.validate(token) is True
        assert second.validate(token) is False

    def test_store_keeps_record_until_token_expires(self):
        store = _RecordingStore()
        cap = CapServer(
            secret_key="test-secret",
            challenge_count=2,
            challenge_size=8,
            challenge_difficulty=1,
            token_expiry_ms=300_000,
            nonce_store=store,
        )
        token = _verification_token(cap)
        store.calls.clear()
        assert cap.validate(token) is True
        assert len(store.calls) == 1
        # The record must outlive the token, or a replay after the record's
        # cleanup but before the token's expiry would pass.
        assert store.calls[0][1] >= 300

    def test_store_returning_none_on_replay_gives_false(self):
        """redis-py's SET NX returns None, not False, when the key exists."""

        class RedisLikeStore:
            def __init__(self):
                self.keys = set()

            def mark_used(self, nonce, ttl_seconds):
                if nonce in self.keys:
                    return None
                self.keys.add(nonce)
                return True

        cap = CapServer(
            secret_key="test-secret",
            challenge_count=2,
            challenge_size=8,
            challenge_difficulty=1,
            nonce_store=RedisLikeStore(),
        )
        token = _verification_token(cap)
        assert cap.validate(token) is True
        assert cap.validate(token) is False

    def test_invalid_token_does_not_touch_store(self):
        store = _RecordingStore()
        cap = CapServer(secret_key="test-secret", nonce_store=store)
        assert cap.validate("bad:token:garbage") is False
        assert cap.validate("") is False
        assert cap.validate(None) is False
        assert store.calls == []

    def test_expired_token_rejected(self, cap):
        with (
            patch("capjs_server.tokens.time") as token_time,
            patch("capjs_server.time") as server_time,
        ):
            token_time.time.return_value = server_time.time.return_value = 1.0
            token = _verification_token(cap)
            token_time.time.return_value = server_time.time.return_value = 2000.0
            assert cap.validate(token) is False
