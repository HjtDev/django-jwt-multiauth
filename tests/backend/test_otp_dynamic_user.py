"""The dynamic-user leg for ``OtpService`` — proves a real phone-channel OTP round trip against
``phone_user_app.User``'s genuine unique ``phone`` field, not a hand-rolled test double, and that
phone-channel auto-provisioning creates a real account the same way the email-channel tests
(``test_otp_service.py``) already prove against the default leg.

Guarded on the *resolved* ``settings.AUTH_USER_MODEL``, same as ``test_dynamic_user.py`` — the
default leg gets its settings module from ``pyproject.toml``'s ini option, not the environment, so
an env-var guard would read ``None`` there and skip for the wrong reason. Run with:

    DJANGO_SETTINGS_MODULE=tests.backend.settings_dynamic_user \\
      uv run pytest -k dynamic_user --no-cov
"""

from __future__ import annotations

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import override_settings

from jwt_multiauth.factories import UserFactory
from jwt_multiauth.models import OtpChallenge, VerifiedContact
from jwt_multiauth.services import OtpService, OtpVerifyResult
from jwt_multiauth.signals import email_otp_requested, phone_otp_requested, user_provisioned
from tests.backend.conftest import captured

pytestmark = [
    pytest.mark.django_db,
    pytest.mark.skipif(
        settings.AUTH_USER_MODEL != "phone_user_app.User",
        reason="only meaningful under tests.backend.settings_dynamic_user",
    ),
]


def test_real_request_verify_round_trip_on_phone() -> None:
    user = UserFactory(phone="+15550001234")

    with captured(phone_otp_requested) as received:
        request_result = OtpService.request("+15550001234", channel="phone", purpose="login")
    code = received[0]["code"]
    assert received[0]["user_id"] == user.pk

    result = OtpService.verify(request_result.challenge_id, code=code)

    assert result == OtpVerifyResult(user=user, purpose="login", created=False)


def test_request_for_an_unknown_phone_is_a_decoy_when_not_auto_provisioning() -> None:
    before_count = OtpChallenge.objects.count()
    with captured(phone_otp_requested) as received:
        OtpService.request("+15559999999", channel="phone", purpose="login")

    assert OtpChallenge.objects.count() == before_count
    assert received == []


@override_settings(
    JWT_MULTIAUTH={
        "ALLOWED_AUTH_METHODS": ["password", "phone_otp"],
        "USER_FIELDS": {"PHONE_FIELD": "phone", "AUTO_PROVISION_METHODS": ["phone_otp"]},
    }
)
def test_phone_auto_provisioning_creates_exactly_one_user() -> None:
    with captured(phone_otp_requested) as received:
        request_result = OtpService.request("+15551110000", channel="phone", purpose="login")
    code = received[0]["code"]
    assert received[0]["user_id"] is None

    challenge = OtpChallenge.objects.get(pk=request_result.challenge_id)
    assert challenge.user_id is None

    with captured(user_provisioned) as provisioned:
        result = OtpService.verify(request_result.challenge_id, code=code)

    assert result.created is True
    assert get_user_model().objects.filter(phone="+15551110000").count() == 1
    assert VerifiedContact.objects.filter(
        user=result.user, field="phone", value="+15551110000"
    ).exists()
    assert len(provisioned) == 1
    assert provisioned[0]["field"] == "phone"
    assert provisioned[0]["value"] == "+15551110000"
    # username is phone_user_app.User's USERNAME_FIELD, different from "phone" and still empty
    # on the new instance — the built-in default must have filled it too.
    assert result.user.username == "+15551110000"
    assert result.user.has_usable_password() is False


def test_email_channel_field_not_configured_falls_back_to_decoy_not_a_crash() -> None:
    # USER_FIELDS.EMAIL_FIELD is unset entirely on this leg — an email_otp request must behave
    # exactly like an unresolvable identifier (no row, no signal, no crash), even though
    # "email_otp" isn't in ALLOWED_AUTH_METHODS here (that 400 is a Phase 6 view-layer concern,
    # never OtpService.request's own job).
    before_count = OtpChallenge.objects.count()
    with captured(email_otp_requested) as received:
        result = OtpService.request("someone@example.com", channel="email", purpose="login")

    assert OtpChallenge.objects.count() == before_count
    assert received == []
    assert result.challenge_id  # a real decoy shape was still returned, not an exception
