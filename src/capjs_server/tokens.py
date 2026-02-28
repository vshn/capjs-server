"""HMAC-signed stateless token helpers for Cap.js challenges and verification."""
import hashlib
import hmac
import secrets
import time

__all__ = [
    "make_challenge_token",
    "verify_challenge_token",
    "make_verification_token",
    "verify_verification_token",
]


def _sign(secret: bytes, payload: str) -> str:
    return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()


def make_challenge_token(
    secret: bytes, nonce: str, expires_ms: float, config: dict
) -> str:
    """Encode challenge parameters into an HMAC-signed token.

    Format: nonce:expires:c:s:d:hmac
    """
    payload = f"{nonce}:{expires_ms:.0f}:{config['c']}:{config['s']}:{config['d']}"
    return f"{payload}:{_sign(secret, payload)}"


def verify_challenge_token(secret: bytes, token: str) -> dict | None:
    """Verify and decode a challenge token. Returns parsed dict or None."""
    if not token:
        return None
    parts = token.rsplit(":", 1)
    if len(parts) != 2:
        return None
    payload, sig = parts
    if not hmac.compare_digest(sig, _sign(secret, payload)):
        return None
    fields = payload.split(":")
    if len(fields) != 5:
        return None
    nonce, expires_str, c, s, d = fields
    try:
        expires = float(expires_str)
        config = {"c": int(c), "s": int(s), "d": int(d)}
    except (ValueError, TypeError):
        return None
    if expires <= time.time() * 1000:
        return None
    return {"nonce": nonce, "expires": expires, "config": config}


def make_verification_token(secret: bytes, expires_ms: float) -> str:
    """Create an HMAC-signed verification token.

    Format: random:expires:hmac
    """
    random_part = secrets.token_hex(15)
    payload = f"{random_part}:{expires_ms:.0f}"
    return f"{payload}:{_sign(secret, payload)}"


def verify_verification_token(secret: bytes, token) -> bool:
    """Verify a verification token's HMAC signature and expiry."""
    if not token or not isinstance(token, str):
        return False
    parts = token.rsplit(":", 1)
    if len(parts) != 2:
        return False
    payload, sig = parts
    if not hmac.compare_digest(sig, _sign(secret, payload)):
        return False
    fields = payload.split(":")
    if len(fields) != 2:
        return False
    try:
        expires = float(fields[1])
    except (ValueError, TypeError):
        return False
    return expires > time.time() * 1000
