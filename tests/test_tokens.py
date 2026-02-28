"""Tests for HMAC-signed stateless token helpers."""

import time

from capjs_server.tokens import (
    make_challenge_token,
    make_verification_token,
    verify_challenge_token,
    verify_verification_token,
)

SECRET = b"test-secret-key"


class TestChallengeToken:
    def test_roundtrip(self):
        config = {"c": 2, "s": 8, "d": 1}
        expires = time.time() * 1000 + 60_000
        token = make_challenge_token(SECRET, "abc123", expires, config)
        parsed = verify_challenge_token(SECRET, token)
        assert parsed is not None
        assert parsed["nonce"] == "abc123"
        assert parsed["config"] == config

    def test_tampered_token_rejected(self):
        config = {"c": 2, "s": 8, "d": 1}
        expires = time.time() * 1000 + 60_000
        token = make_challenge_token(SECRET, "abc123", expires, config)
        tampered = "x" + token[1:]
        assert verify_challenge_token(SECRET, tampered) is None

    def test_expired_token_rejected(self):
        config = {"c": 2, "s": 8, "d": 1}
        expires = time.time() * 1000 - 1  # already expired
        token = make_challenge_token(SECRET, "abc123", expires, config)
        assert verify_challenge_token(SECRET, token) is None

    def test_wrong_secret_rejected(self):
        config = {"c": 2, "s": 8, "d": 1}
        expires = time.time() * 1000 + 60_000
        token = make_challenge_token(SECRET, "abc123", expires, config)
        assert verify_challenge_token(b"wrong-secret", token) is None

    def test_garbage_rejected(self):
        assert verify_challenge_token(SECRET, "garbage") is None
        assert verify_challenge_token(SECRET, "") is None


class TestVerificationToken:
    def test_roundtrip(self):
        expires = time.time() * 1000 + 60_000
        token = make_verification_token(SECRET, expires)
        assert verify_verification_token(SECRET, token) is True

    def test_tampered_rejected(self):
        expires = time.time() * 1000 + 60_000
        token = make_verification_token(SECRET, expires)
        tampered = "x" + token[1:]
        assert verify_verification_token(SECRET, tampered) is False

    def test_expired_rejected(self):
        expires = time.time() * 1000 - 1
        token = make_verification_token(SECRET, expires)
        assert verify_verification_token(SECRET, token) is False

    def test_none_rejected(self):
        assert verify_verification_token(SECRET, None) is False
        assert verify_verification_token(SECRET, "") is False

    def test_no_colon_rejected(self):
        assert verify_verification_token(SECRET, "notokencolon") is False
