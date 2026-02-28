from django.urls import path

from capjs_server.django.views import CapChallengeView, CapRedeemView

urlpatterns = [
    path("cap/challenge", CapChallengeView.as_view()),
    path("cap/redeem", CapRedeemView.as_view()),
]
