# capjs-server

Python server-side implementation of the [Cap.js](https://capjs.js.org/) proof-of-work CAPTCHA protocol. Framework-agnostic core with optional Django integration.

Cap.js is a privacy-friendly, cookie-free CAPTCHA that uses proof-of-work challenges instead of image recognition. This package provides the server side — challenge creation, solution verification, and token validation.

## Installation

```bash
pip install capjs-server

# With Django integration
pip install capjs-server[django]
```

## Quick Start

```python
from capjs_server import CapServer

cap = CapServer(secret_key="your-secret-key")

# Create challenge → return as JSON to the Cap.js widget
challenge = cap.create_challenge()

# Verify solutions from the widget → return as JSON
result = cap.redeem(challenge["token"], solutions)

# Validate verification token in your form handler
if cap.validate(request.POST["cap-token"]):
    process_form()
```

## Django Integration

```python
# settings.py (all optional — sensible defaults)
CAP_SECRET_KEY = SECRET_KEY         # defaults to Django's SECRET_KEY
CAP_CHALLENGE_COUNT = 50            # sub-challenges per solve
CAP_CHALLENGE_DIFFICULTY = 4        # target prefix length (hex chars)

# urls.py
from capjs_server.django.views import CapChallengeView, CapRedeemView

urlpatterns = [
    path("cap/challenge", CapChallengeView.as_view()),
    path("cap/redeem", CapRedeemView.as_view()),
]

# views.py
from capjs_server.django import validate_cap_token

def contact(request):
    if not validate_cap_token(request):
        return HttpResponseForbidden()
    # process form...
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `secret_key` | *(required)* | HMAC signing key. Keep stable across deploys. |
| `challenge_count` | `50` | Sub-challenges per solve |
| `challenge_size` | `32` | Salt length in hex chars |
| `challenge_difficulty` | `4` | Target prefix length in hex chars |
| `challenge_expiry_ms` | `600000` | Challenge token lifetime (10 min) |
| `token_expiry_ms` | `300000` | Verification token lifetime (5 min) |
| `nonce_store` | `MemoryNonceStore()` | Pluggable replay protection store |

## Testing

A brute-force solver is included for writing integration tests without a browser:

```python
from capjs_server import CapServer
from capjs_server.testing import solve

cap = CapServer(secret_key="test", challenge_count=2, challenge_difficulty=1)
challenge = cap.create_challenge()
solutions = solve(challenge["token"], challenge["challenge"])
result = cap.redeem(challenge["token"], solutions)
assert result["success"]
```

## How It Works

All state is encoded in HMAC-signed tokens — no server-side storage. This makes it safe for multi-instance deployments (Kubernetes, Cloud Run, serverless).

1. **Challenge**: Server generates a random nonce and signs it with difficulty parameters into a token
2. **Solve**: The Cap.js widget finds nonces whose SHA-256 hash starts with a PRNG-derived prefix
3. **Redeem**: Server verifies the HMAC, checks solutions, and issues a signed verification token
4. **Validate**: Server verifies the verification token's HMAC and expiry

## Replay Protection

By default, each challenge can only be redeemed once per server process. This prevents attackers from replaying solved challenges to stockpile verification tokens.

The built-in `MemoryNonceStore` tracks used nonces in-memory with automatic expiry. For multi-process deployments (e.g. Kubernetes with multiple replicas), a challenge can be redeemed at most once per replica.

For strict single-use enforcement across replicas, provide a shared nonce store:

```python
from capjs_server import CapServer, NonceStore

class RedisNonceStore:
    def __init__(self, redis_client):
        self.redis = redis_client

    def mark_used(self, nonce: str, ttl_seconds: float) -> bool:
        # SET NX returns True only if the key was newly created
        return self.redis.set(f"cap:nonce:{nonce}", 1, nx=True, ex=int(ttl_seconds) + 1)

cap = CapServer(secret_key="...", nonce_store=RedisNonceStore(redis_client))
```

Django:
```python
# settings.py
CAP_NONCE_STORE = RedisNonceStore(redis_client)
```

## License

Apache-2.0 — same as Cap.js.
