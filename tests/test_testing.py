"""Tests for the test solver helper."""

from capjs_server import CapServer
from capjs_server.testing import solve


def test_solve_produces_valid_solutions():
    cap = CapServer(
        secret_key="test", challenge_count=2, challenge_size=8, challenge_difficulty=1
    )
    data = cap.create_challenge()
    solutions = solve(data["token"], data["challenge"])
    assert len(solutions) == 2
    result = cap.redeem(data["token"], solutions)
    assert result["success"] is True


def test_solve_returns_list_of_ints():
    cap = CapServer(
        secret_key="test", challenge_count=3, challenge_size=8, challenge_difficulty=1
    )
    data = cap.create_challenge()
    solutions = solve(data["token"], data["challenge"])
    assert isinstance(solutions, list)
    assert all(isinstance(s, int) for s in solutions)
    assert len(solutions) == 3
