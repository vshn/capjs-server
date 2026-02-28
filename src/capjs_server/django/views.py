"""Django views for Cap.js challenge and redeem endpoints."""
import json

from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from . import get_cap_server

__all__ = ["CapChallengeView", "CapRedeemView"]


@method_decorator(csrf_exempt, name="dispatch")
class CapChallengeView(View):
    """POST endpoint to create a proof-of-work challenge."""

    def post(self, request, *args, **kwargs):
        data = get_cap_server().create_challenge()
        return JsonResponse(data)


@method_decorator(csrf_exempt, name="dispatch")
class CapRedeemView(View):
    """POST endpoint to verify solutions and issue a verification token."""

    def post(self, request, *args, **kwargs):
        try:
            body = json.loads(request.body)
            token = body["token"]
            solutions = body["solutions"]
        except (json.JSONDecodeError, KeyError, TypeError):
            return JsonResponse(
                {"success": False, "error": "invalid request"}, status=400
            )
        result = get_cap_server().redeem(token, solutions)
        return JsonResponse(result)
