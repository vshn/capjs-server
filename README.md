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

Challenges and verification tokens are HMAC-signed, so any instance can verify any token (Kubernetes, Cloud Run, serverless). The only server-side state is the nonce store that makes each one single use (see Replay Protection).

1. **Challenge**: Server generates a random nonce and signs it with difficulty parameters into a token
2. **Solve**: The Cap.js widget finds nonces whose SHA-256 hash starts with a PRNG-derived prefix
3. **Redeem**: Server verifies the HMAC, checks solutions, and issues a signed verification token
4. **Validate**: Server verifies the verification token's HMAC and expiry, then spends it

## Replay Protection

By default, each challenge can only be redeemed once, and each verification token is accepted by `validate()` once. The first stops attackers from replaying solved challenges to stockpile verification tokens; the second stops one token from being resubmitted for its whole lifetime.

The built-in `MemoryNonceStore` tracks both in memory with automatic expiry. For multi-process deployments (e.g. Kubernetes with multiple replicas), "once" means once per process.

### Checking a token without spending it

A form view often checks the CAPTCHA before it validates the form. If the token were spent there, a user who fixes a rejected form and resubmits would be refused, because the Cap.js widget keeps its token after a failed submit. Check first, spend once the submission is accepted:

```python
if not cap.validate(token, consume=False):  # signature and expiry only
    return forbidden()
if not form.is_valid():
    return show_errors(form)                 # token still usable for the retry
if not cap.validate(token):                  # spend it; False if already used
    return forbidden()
process_form()
```

`validate_cap_token(request, consume=False)` does the same in Django.

For strict single-use enforcement across replicas, provide a shared nonce store:

```python
from capjs_server import CapServer, NonceStore

class RedisNonceStore:
    def __init__(self, redis_client):
        self.redis = redis_client

    def mark_used(self, nonce: str, ttl_seconds: float) -> bool:
        # SET NX returns True only if the key was newly created
        return bool(self.redis.set(f"cap:nonce:{nonce}", 1, nx=True, ex=int(ttl_seconds) + 1))

cap = CapServer(secret_key="...", nonce_store=RedisNonceStore(redis_client))
```

Django:
```python
# settings.py
CAP_NONCE_STORE = RedisNonceStore(redis_client)
```

## License

Apache-2.0 — same as Cap.js.
