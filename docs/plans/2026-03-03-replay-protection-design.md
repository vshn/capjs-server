# Replay Protection via Pluggable Nonce Store

## Problem

The `redeem()` endpoint accepts a valid challenge token + solutions and issues a verification token. Nothing prevents the same challenge from being redeemed multiple times within its TTL window, allowing an attacker to stockpile valid verification tokens from a single solved challenge.

## Solution

Add a pluggable nonce store that tracks redeemed challenge nonces. The store rejects nonces it has already seen, limiting each challenge to a single successful redemption per server process.

## Design

### New file: `src/capjs_server/nonce_store.py`

**`NonceStore` Protocol:**
- `mark_used(nonce: str, ttl_seconds: float) -> bool` — returns `True` on first use, `False` if already seen

**`MemoryNonceStore` implementation:**
- `dict[str, float]` mapping nonce to expiry timestamp
- `threading.Lock` for thread safety
- Lazy cleanup of expired entries on each `mark_used()` call

### Changes to `src/capjs_server/__init__.py`

- `CapServer.__init__` gets optional `nonce_store` parameter (defaults to `MemoryNonceStore`)
- `redeem()` calls `mark_used(nonce, remaining_ttl)` after signature verification, before solution checking. Returns `{"success": False}` if nonce was already used.

### Changes to Django integration

- `get_cap_server()` reads optional `CAP_NONCE_STORE` setting

### Trade-offs

- In-memory store is per-process: with N replicas, a challenge can be redeemed at most N times (acceptable for most use cases)
- Users needing strict single-use can plug in a shared Redis/memcached backend via the Protocol
- Zero new runtime dependencies

### Tests

- Challenge can be redeemed exactly once
- Second redeem returns `{"success": False}`
- Expired nonces are cleaned up
- Custom NonceStore implementation works via Protocol
- Django integration passes nonce store from settings
