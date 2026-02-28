"""Test helpers for Cap.js integration tests.

Provides a brute-force solver so you can write end-to-end tests
without a browser widget::

    from capjs_server.testing import solve

    challenge = cap.create_challenge()
    solutions = solve(challenge["token"], challenge["challenge"])
    result = cap.redeem(challenge["token"], solutions)
    assert result["success"]
"""

import hashlib

from .prng import prng

__all__ = ["solve"]


def solve(token: str, config: dict, *, max_nonce: int = 10_000_000) -> list[int]:
    """Brute-force solve a Cap.js challenge.

    Args:
        token: The challenge token from ``create_challenge()``.
        config: The challenge config dict (with keys ``c``, ``s``, ``d``).
        max_nonce: Maximum nonce to try before giving up (default 10M).

    Returns:
        List of integer nonces, one per sub-challenge.

    Raises:
        RuntimeError: If a sub-challenge cannot be solved within *max_nonce* attempts.
    """
    solutions: list[int] = []
    for i in range(1, config["c"] + 1):
        salt = prng(token + str(i), config["s"])
        target = prng(token + str(i) + "d", config["d"])
        for n in range(max_nonce):
            h = hashlib.sha256((salt + str(n)).encode()).hexdigest()
            if h.startswith(target):
                solutions.append(n)
                break
        else:
            raise RuntimeError(
                f"Could not solve sub-challenge {i}/{config['c']} "
                f"within {max_nonce} attempts"
            )
    return solutions
