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


def _wrong(token, config):
    """Solutions that fail every sub-challenge.

    A fixed guess like 999999 solves a difficulty-1 sub-challenge one time in
    16, so a test using it fails at random.
    """
    wrong = []
    for i in range(1, config["c"] + 1):
        salt = prng(token + str(i), config["s"])
        target = prng(token + str(i) + "d", config["d"])
        n = 0
        while hashlib.sha256((salt + str(n)).encode()).hexdigest().startswith(target):
            n += 1
        wrong.append(n)
    return wrong


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
        wrong = _wrong(data["token"], data["challenge"])
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


class TestRedeemWithoutProofOfWork:
    """A failed redeem must not cost the server a store entry: challenges are
    free to fetch, so otherwise each zero-work request grows the store."""

    @pytest.fixture
    def store(self):
        return MemoryNonceStore()

    @pytest.fixture
    def cap(self, store):
        return CapServer(
            secret_key="test-secret",
            challenge_count=2,
            challenge_size=8,
            challenge_difficulty=1,
            nonce_store=store,
        )

    def test_wrong_solutions_leave_store_empty(self, cap, store):
        for _ in range(20):
            data = cap.create_challenge()
            wrong = _wrong(data["token"], data["challenge"])
            assert cap.redeem(data["token"], wrong)["success"] is False
        assert store._used == {}

    def test_wrong_solution_count_leaves_store_empty(self, cap, store):
        data = cap.create_challenge()
        assert cap.redeem(data["token"], [0])["success"] is False
        assert store._used == {}

    def test_correct_solutions_after_a_failed_attempt_succeed(self, cap):
        data = cap.create_challenge()
        wrong = _wrong(data["token"], data["challenge"])
        assert cap.redeem(data["token"], wrong)["success"] is False
        solutions = _solve(data["token"], data["challenge"])
        assert cap.redeem(data["token"], solutions)["success"] is True
        assert cap.redeem(data["token"], solutions)["success"] is False


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
