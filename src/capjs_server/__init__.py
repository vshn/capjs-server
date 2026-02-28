"""Cap.js proof-of-work CAPTCHA server for Python.

Usage::

    from capjs_server import CapServer

    cap = CapServer(secret_key="your-secret")
    challenge = cap.create_challenge()
    result = cap.redeem(token, solutions)
    if cap.validate(verification_token):
        process_form()
"""

import hashlib
import logging
import secrets
import time

from .prng import prng
from .tokens import (
    make_challenge_token,
    make_verification_token,
    verify_challenge_token,
    verify_verification_token,
)

__all__ = ["CapServer"]
__version__ = "0.1.0"

logger = logging.getLogger(__name__)


class CapServer:
    """Stateless Cap.js proof-of-work CAPTCHA server.

    All state is encoded in HMAC-signed tokens, so this works correctly
    with multi-instance deployments (Cloud Run, Kubernetes, etc.).

    Args:
        secret_key: Secret used for HMAC token signatures. Keep this stable
            across deployments — changing it invalidates all outstanding tokens.
        challenge_count: Number of sub-challenges per solve (default 50).
        challenge_size: Salt length in hex chars (default 32).
        challenge_difficulty: Target prefix length in hex chars (default 4).
        challenge_expiry_ms: Challenge expiry in milliseconds (default 600000 = 10 min).
        token_expiry_ms: Verification token expiry in milliseconds
            (default 300000 = 5 min).
    """

    def __init__(
        self,
        secret_key: str,
        *,
        challenge_count: int = 50,
        challenge_size: int = 32,
        challenge_difficulty: int = 4,
        challenge_expiry_ms: int = 600_000,
        token_expiry_ms: int = 300_000,
    ):
        self._secret = secret_key.encode()
        self._count = challenge_count
        self._size = challenge_size
        self._difficulty = challenge_difficulty
        self._challenge_expiry_ms = challenge_expiry_ms
        self._token_expiry_ms = token_expiry_ms

    def create_challenge(self) -> dict:
        """Generate a new proof-of-work challenge.

        Returns a dict with keys ``challenge``, ``token``, ``expires``
        suitable for JSON serialization to the Cap.js widget.
        """
        nonce = secrets.token_hex(25)
        expires = time.time() * 1000 + self._challenge_expiry_ms
        config = {"c": self._count, "s": self._size, "d": self._difficulty}
        token = make_challenge_token(self._secret, nonce, expires, config)
        return {"challenge": config, "token": token, "expires": expires}

    def redeem(self, token: str, solutions: list[int]) -> dict:
        """Verify proof-of-work solutions and issue a verification token.

        Returns a dict with ``success`` (bool), and on success: ``token``, ``expires``.
        """
        parsed = verify_challenge_token(self._secret, token)
        if parsed is None:
            return {"success": False}

        config = parsed["config"]
        count, size, difficulty = config["c"], config["s"], config["d"]

        if len(solutions) != count:
            return {"success": False}

        for i in range(1, count + 1):
            salt = prng(token + str(i), size)
            target = prng(token + str(i) + "d", difficulty)
            h = hashlib.sha256((salt + str(solutions[i - 1])).encode()).hexdigest()
            if not h.startswith(target):
                return {"success": False}

        expires = time.time() * 1000 + self._token_expiry_ms
        vertoken = make_verification_token(self._secret, expires)
        return {"success": True, "token": vertoken, "expires": expires}

    def validate(self, token) -> bool:
        """Validate a verification token. Returns True if valid."""
        return verify_verification_token(self._secret, token)
