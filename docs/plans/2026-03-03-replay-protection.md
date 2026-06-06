# Replay Protection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Prevent challenge tokens from being redeemed more than once by tracking used nonces in a pluggable store.

**Architecture:** A `NonceStore` Protocol defines the interface (`mark_used`). A `MemoryNonceStore` ships as the default (thread-safe dict with lazy expiry cleanup). `CapServer` accepts an optional `nonce_store` parameter and calls it in `redeem()` after signature verification.

**Tech Stack:** Pure Python stdlib (threading, time). No new dependencies.

---

### Task 1: Create `MemoryNonceStore` with tests

**Files:**
- Create: `src/capjs_server/nonce_store.py`
- Create: `tests/test_nonce_store.py`

**Step 1: Write the failing tests**

Create `tests/test_nonce_store.py`:

```python
"""Tests for NonceStore protocol and MemoryNonceStore."""

import time
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
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/arska/dev/capjs-server && uv run pytest tests/test_nonce_store.py -v`
Expected: FAIL — `ImportError: cannot import name 'MemoryNonceStore'`

**Step 3: Write the implementation**

Create `src/capjs_server/nonce_store.py`:

```python
"""Pluggable nonce store for replay protection."""

from __future__ import annotations

import threading
import time
from typing import Protocol, runtime_checkable

__all__ = ["NonceStore", "MemoryNonceStore"]


@runtime_checkable
class NonceStore(Protocol):
    """Interface for tracking used challenge nonces.

    Implement this protocol to use a shared store (Redis, memcached, etc.)
    for strict single-use enforcement across multiple server instances.
    """

    def mark_used(self, nonce: str, ttl_seconds: float) -> bool:
        """Mark a nonce as used. Return True if first use, False if already seen."""
        ...


class MemoryNonceStore:
    """In-memory nonce store with automatic expiry.

    Thread-safe. Suitable for single-process deployments. With N processes,
    a nonce can be redeemed at most N times (once per process).
    """

    def __init__(self) -> None:
        self._used: dict[str, float] = {}
        self._lock = threading.Lock()

    def mark_used(self, nonce: str, ttl_seconds: float) -> bool:
        now = time.time()
        with self._lock:
            # Lazy cleanup of expired entries
            expired = [k for k, exp in self._used.items() if exp <= now]
            for k in expired:
                del self._used[k]

            if nonce in self._used:
                return False

            self._used[nonce] = now + ttl_seconds
            return True
```

**Step 4: Run tests to verify they pass**

Run: `cd /Users/arska/dev/capjs-server && uv run pytest tests/test_nonce_store.py -v`
Expected: all 5 tests PASS

**Step 5: Commit**

```bash
cd /Users/arska/dev/capjs-server
git add src/capjs_server/nonce_store.py tests/test_nonce_store.py
git commit -m "feat: add NonceStore protocol and MemoryNonceStore"
```

---

### Task 2: Wire nonce store into `CapServer.redeem()`

**Files:**
- Modify: `src/capjs_server/__init__.py`
- Modify: `tests/test_server.py`

**Step 1: Write the failing tests**

Add to `tests/test_server.py` inside `class TestRedeem`:

```python
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
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/arska/dev/capjs-server && uv run pytest tests/test_server.py::TestRedeem::test_replay_rejected tests/test_server.py::TestRedeem::test_custom_nonce_store -v`
Expected: `test_replay_rejected` FAILS (second redeem succeeds), `test_custom_nonce_store` FAILS (unexpected keyword argument)

**Step 3: Modify `CapServer`**

In `src/capjs_server/__init__.py`:

1. Add import: `from .nonce_store import MemoryNonceStore, NonceStore`
2. Update `__all__` to: `["CapServer", "MemoryNonceStore", "NonceStore"]`
3. Add `nonce_store` parameter to `__init__`:
   ```python
   def __init__(
       self,
       secret_key: str,
       *,
       challenge_count: int = 50,
       challenge_size: int = 32,
       challenge_difficulty: int = 4,
       challenge_expiry_ms: int = 600_000,
       token_expiry_ms: int = 300_000,
       nonce_store: NonceStore | None = None,
   ):
       # ... existing code ...
       self._nonce_store = nonce_store or MemoryNonceStore()
   ```
4. In `redeem()`, after `parsed = verify_challenge_token(...)` and the `if parsed is None` check, add:
   ```python
       nonce = parsed["nonce"]
       remaining_ms = parsed["expires"] - time.time() * 1000
       ttl_seconds = max(remaining_ms / 1000, 0)
       if not self._nonce_store.mark_used(nonce, ttl_seconds):
           return {"success": False}
   ```

**Step 4: Run all server tests**

Run: `cd /Users/arska/dev/capjs-server && uv run pytest tests/test_server.py -v`
Expected: all tests PASS

**Step 5: Commit**

```bash
cd /Users/arska/dev/capjs-server
git add src/capjs_server/__init__.py tests/test_server.py
git commit -m "feat: wire nonce store into CapServer.redeem() for replay protection"
```

---

### Task 3: Update Django integration

**Files:**
- Modify: `src/capjs_server/django/__init__.py`
- Modify: `tests/test_django.py`

**Step 1: Write the failing test**

Add to `tests/test_django.py`:

```python
import json
from unittest.mock import patch

# ... existing imports ...

class TestReplayProtectionDjango:
    def test_redeem_replay_rejected(self, client):
        resp = client.post("/cap/challenge")
        data = resp.json()
        solutions = solve(data["token"], data["challenge"])
        body = json.dumps({"token": data["token"], "solutions": solutions})
        first = client.post("/cap/redeem", data=body, content_type="application/json")
        assert first.json()["success"] is True
        second = client.post("/cap/redeem", data=body, content_type="application/json")
        assert second.json()["success"] is False

    def test_custom_nonce_store_setting(self):
        from capjs_server.nonce_store import MemoryNonceStore

        custom_store = MemoryNonceStore()
        with patch("capjs_server.django.settings") as mock_settings:
            mock_settings.SECRET_KEY = "test-key"
            mock_settings.CAP_NONCE_STORE = custom_store
            # Clear the LRU cache to pick up new settings
            from capjs_server.django import get_cap_server
            get_cap_server.cache_clear()
            cap = get_cap_server()
            assert cap._nonce_store is custom_store
            get_cap_server.cache_clear()
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/arska/dev/capjs-server && uv run pytest tests/test_django.py::TestReplayProtectionDjango -v`
Expected: FAIL

**Step 3: Update Django integration**

In `src/capjs_server/django/__init__.py`, add the `nonce_store` parameter to `get_cap_server()`:

```python
@lru_cache(maxsize=1)
def get_cap_server() -> CapServer:
    """Return a CapServer configured from Django settings."""
    return CapServer(
        secret_key=getattr(settings, "CAP_SECRET_KEY", settings.SECRET_KEY),
        challenge_count=getattr(settings, "CAP_CHALLENGE_COUNT", 50),
        challenge_size=getattr(settings, "CAP_CHALLENGE_SIZE", 32),
        challenge_difficulty=getattr(settings, "CAP_CHALLENGE_DIFFICULTY", 4),
        challenge_expiry_ms=getattr(settings, "CAP_CHALLENGE_EXPIRY", 600_000),
        token_expiry_ms=getattr(settings, "CAP_TOKEN_EXPIRY", 300_000),
        nonce_store=getattr(settings, "CAP_NONCE_STORE", None),
    )
```

**Step 4: Run all Django tests**

Run: `cd /Users/arska/dev/capjs-server && uv run pytest tests/test_django.py -v`
Expected: all tests PASS

**Step 5: Commit**

```bash
cd /Users/arska/dev/capjs-server
git add src/capjs_server/django/__init__.py tests/test_django.py
git commit -m "feat: pass CAP_NONCE_STORE setting to CapServer in Django integration"
```

---

### Task 4: Update README and run full test suite

**Files:**
- Modify: `README.md`

**Step 1: Update README**

Add a "Replay Protection" section after the "How It Works" section:

```markdown
## Replay Protection

By default, each challenge can only be redeemed once per server process. This prevents attackers from replaying solved challenges to stockpile verification tokens.

The built-in `MemoryNonceStore` tracks used nonces in-memory with automatic expiry. For multi-process deployments (e.g. Kubernetes with multiple replicas), a challenge can be redeemed at most once per replica.

For strict single-use enforcement across replicas, provide a shared nonce store:

\```python
from capjs_server import CapServer, NonceStore

class RedisNonceStore:
    def __init__(self, redis_client):
        self.redis = redis_client

    def mark_used(self, nonce: str, ttl_seconds: float) -> bool:
        # SET NX returns True only if the key was newly created
        return self.redis.set(f"cap:nonce:{nonce}", 1, nx=True, ex=int(ttl_seconds) + 1)

cap = CapServer(secret_key="...", nonce_store=RedisNonceStore(redis_client))
\```

Django:
\```python
# settings.py
CAP_NONCE_STORE = RedisNonceStore(redis_client)
\```
```

Add `nonce_store` to the Configuration table:

```markdown
| `nonce_store` | `MemoryNonceStore()` | Pluggable replay protection store |
```

**Step 2: Run full test suite**

Run: `cd /Users/arska/dev/capjs-server && uv run pytest -v`
Expected: all tests PASS

**Step 3: Run linter**

Run: `cd /Users/arska/dev/capjs-server && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/`
Expected: no errors

**Step 4: Commit**

```bash
cd /Users/arska/dev/capjs-server
git add README.md
git commit -m "docs: add replay protection section to README"
```
