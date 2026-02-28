"""Tests for Django integration (views and helpers)."""

import json

from capjs_server.django import get_cap_server, validate_cap_token
from capjs_server.testing import solve


class TestGetCapServer:
    def test_returns_cap_server_instance(self):
        cap = get_cap_server()
        assert cap._count == 2  # from test settings
        assert cap._difficulty == 1

    def test_uses_django_secret_key(self):
        cap = get_cap_server()
        data = cap.create_challenge()
        assert "token" in data


class TestValidateCapToken:
    def test_valid_token_accepted(self, rf):
        cap = get_cap_server()
        data = cap.create_challenge()
        solutions = solve(data["token"], data["challenge"])
        result = cap.redeem(data["token"], solutions)
        request = rf.post("/", {"cap-token": result["token"]})
        assert validate_cap_token(request) is True

    def test_missing_token_rejected(self, rf):
        request = rf.post("/", {})
        assert validate_cap_token(request) is False

    def test_invalid_token_rejected(self, rf):
        request = rf.post("/", {"cap-token": "bad:token"})
        assert validate_cap_token(request) is False


class TestCapChallengeView:
    def test_post_returns_challenge(self, client):
        resp = client.post("/cap/challenge")
        assert resp.status_code == 200
        data = resp.json()
        assert "challenge" in data
        assert "token" in data

    def test_get_not_allowed(self, client):
        resp = client.get("/cap/challenge")
        assert resp.status_code == 405


class TestCapRedeemView:
    def test_valid_solutions_succeed(self, client):
        resp = client.post("/cap/challenge")
        data = resp.json()
        solutions = solve(data["token"], data["challenge"])
        resp = client.post(
            "/cap/redeem",
            data=json.dumps({"token": data["token"], "solutions": solutions}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_missing_body_returns_400(self, client):
        resp = client.post("/cap/redeem", content_type="application/json")
        assert resp.status_code == 400

    def test_get_not_allowed(self, client):
        resp = client.get("/cap/redeem")
        assert resp.status_code == 405
