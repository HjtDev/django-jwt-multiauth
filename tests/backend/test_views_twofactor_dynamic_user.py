"""The dynamic-user leg for Phase 7's 2FA views: a real ``phone_otp`` SECOND-FACTOR round trip
over HTTP against ``phone_user_app.User``'s genuine unique ``phone`` field — proving
``TwoFactorService.eligible_methods``/``.verify_second_factor`` and the new
``POST /2fa/otp/request/`` endpoint all resolve ``USER_FIELDS["PHONE_FIELD"]`` correctly against a
real non-default user model, zero package-level code changes needed.

Guarded on the *resolved* ``settings.AUTH_USER_MODEL``, same as ``test_views_otp_dynamic_user.py``.
Run with:

    DJANGO_SETTINGS_MODULE=tests.backend.settings_dynamic_user \\
      uv run pytest -k dynamic_user --no-cov
"""

from __future__ import annotations

import pytest
from django.conf import settings
from django.test import override_settings
from rest_framework.test import APIClient

from jwt_multiauth.factories import UserFactory, VerifiedContactFactory
from jwt_multiauth.signals import phone_otp_requested
from tests.backend.conftest import captured

pytestmark = [
    pytest.mark.django_db,
    pytest.mark.requires_extra,
    pytest.mark.skipif(
        settings.AUTH_USER_MODEL != "phone_user_app.User",
        reason="only meaningful under tests.backend.settings_dynamic_user",
    ),
]

_LOGIN_URL = "/api/v1/auth/login/"
_STATUS_URL = "/api/v1/auth/2fa/status/"
_OTP_REQUEST_2FA_URL = "/api/v1/auth/2fa/otp/request/"
_VERIFY_URL = "/api/v1/auth/2fa/verify/"

_PASSWORD = "correct-horse-battery-staple-9"

_PHONE_2FA_SETTINGS = {
    "ALLOWED_AUTH_METHODS": ["password", "phone_otp"],
    "USER_FIELDS": {"PHONE_FIELD": "phone"},
    "TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["phone_otp"]},
}


@override_settings(JWT_MULTIAUTH=_PHONE_2FA_SETTINGS)
def test_phone_otp_second_factor_round_trip_over_http(api_client: APIClient) -> None:
    user = UserFactory(username="alice", phone="+15550001234")
    user.set_password(_PASSWORD)
    user.save()
    VerifiedContactFactory(user=user, field="phone", value="+15550001234")

    login_response = api_client.post(
        _LOGIN_URL, {"identifier": "alice", "password": _PASSWORD}, format="json"
    )
    assert login_response.status_code == 200
    pending_token = login_response.json()["pending_token"]
    assert login_response.json()["eligible_methods"] == ["phone_otp"]

    with captured(phone_otp_requested) as received:
        otp_request_response = api_client.post(
            _OTP_REQUEST_2FA_URL,
            {"pending_token": pending_token, "method": "phone_otp"},
            format="json",
        )
    assert otp_request_response.status_code == 200
    challenge_id = otp_request_response.json()["challenge_id"]
    code = received[0]["code"]
    assert received[0]["destination"] == "+15550001234"

    verify_response = api_client.post(
        _VERIFY_URL,
        {
            "pending_token": pending_token,
            "method": "phone_otp",
            "challenge_id": challenge_id,
            "code": code,
        },
        format="json",
    )
    assert verify_response.status_code == 200
    body = verify_response.json()
    assert "access" in body
    assert body["created"] is False


@override_settings(JWT_MULTIAUTH=_PHONE_2FA_SETTINGS)
def test_phone_otp_status_reflects_the_verified_phone_as_enrolled(api_client: APIClient) -> None:
    user = UserFactory(username="alice", phone="+15550001234")
    user.set_password(_PASSWORD)
    user.save()
    VerifiedContactFactory(user=user, field="phone", value="+15550001234")
    api_client.force_authenticate(user=user)

    response = api_client.get(_STATUS_URL)
    assert response.status_code == 200
    body = response.json()
    assert body["enrolled_methods"] == ["phone_otp"]
    assert body["eligible_methods"] == ["phone_otp"]
