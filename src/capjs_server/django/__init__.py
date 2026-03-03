"""Django integration for capjs-server.

Requires ``pip install capjs-server[django]``.

Quick start::

    # settings.py (all optional — sensible defaults)
    CAP_SECRET_KEY = SECRET_KEY     # defaults to SECRET_KEY
    CAP_CHALLENGE_COUNT = 50
    CAP_CHALLENGE_DIFFICULTY = 4

    # urls.py
    from capjs_server.django.views import CapChallengeView, CapRedeemView
    urlpatterns = [
        path("cap/challenge", CapChallengeView.as_view()),
        path("cap/redeem", CapRedeemView.as_view()),
    ]

    # views.py
    from capjs_server.django import validate_cap_token
    if not validate_cap_token(request):
        return HttpResponseForbidden()
"""

from functools import lru_cache

from django.conf import settings

from capjs_server import CapServer

__all__ = ["get_cap_server", "validate_cap_token"]


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


def validate_cap_token(request, field_name: str = "cap-token") -> bool:
    """Validate the Cap.js verification token from a Django request.

    Reads the token from ``request.POST[field_name]`` and validates it.
    """
    token = request.POST.get(field_name, "")
    return get_cap_server().validate(token)
