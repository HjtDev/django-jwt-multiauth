"""The dynamic-user leg for Phase 6's OTP login views: a real ``phone_otp`` login round trip over
HTTP against ``phone_user_app.User``'s genuine unique ``phone`` field, zero package-level code
changes needed — proving ``docs/CONTRACT.md``'s "works against ANY user model whose enabled
methods' fields exist" promise at the HTTP layer, not just the service layer
(``test_otp_dynamic_user.py`` already covers the service layer).

Guarded on the *resolved* ``settings.AUTH_USER_MODEL``, same as ``test_otp_dynamic_user.py``. Run
with:

    DJANGO_SETTINGS_MODULE=tests.backend.settings_dynamic_user \\
      uv run pytest -k dynamic_user --no-cov
"""

from __future__ import annotations

import pytest
from django.conf import settings
from django.test import override_settings
from rest_framework.test import APIClient

from jwt_multiauth.factories import UserFactory
from jwt_multiauth.models import OtpChallenge
from jwt_multiauth.signals import phone_otp_requested
from tests.backend.conftest import captured

pytestmark = [
    pytest.mark.django_db,
    pytest.mark.skipif(
        settings.AUTH_USER_MODEL != "phone_user_app.User",
        reason="only meaningful under tests.backend.settings_dynamic_user",
    ),
]

_OTP_REQUEST_URL = "/api/v1/auth/otp/request/"
_OTP_VERIFY_URL = "/api/v1/auth/otp/verify/"


def test_phone_otp_request_and_verify_round_trip_over_http(api_client: APIClient) -> None:
    UserFactory(phone="+15550001234")

    with captured(phone_otp_requested) as received:
        request_response = api_client.post(
            _OTP_REQUEST_URL, {"identifier": "+15550001234", "channel": "phone"}, format="json"
        )
    assert request_response.status_code == 200
    challenge_id = OtpChallenge.objects.get().challenge_id
    code = received[0]["code"]

    verify_response = api_client.post(
        _OTP_VERIFY_URL, {"challenge_id": str(challenge_id), "code": code}, format="json"
    )
    assert verify_response.status_code == 200
    body = verify_response.json()
    assert body["created"] is False
    assert "access" in body


def test_email_channel_is_rejected_under_the_default_dynamic_user_settings(
    api_client: APIClient,
) -> None:
    # tests.backend.settings_dynamic_user only enables ["password", "phone_otp"] — email_otp
    # isn't in ALLOWED_AUTH_METHODS for this host, mirroring the default leg's own
    # phone-under-default-settings rejection test from the other direction.
    response = api_client.post(
        _OTP_REQUEST_URL, {"identifier": "someone@example.com", "channel": "email"}, format="json"
    )
    assert response.status_code == 400
    assert response.json()["error"]["details"] == {"code": "channel_not_allowed"}


@override_settings(
    JWT_MULTIAUTH={
        "ALLOWED_AUTH_METHODS": ["password", "phone_otp"],
        "USER_FIELDS": {"PHONE_FIELD": "phone", "AUTO_PROVISION_METHODS": ["phone_otp"]},
        "TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]},
    }
)
def test_phone_auto_provisioning_carve_out_over_http(api_client: APIClient) -> None:
    """The same §11 item 19 carve-out proven for email_otp in test_views_otp.py, proven here for
    phone_otp against a real phone field — a brand-new phone number bootstraps real tokens even
    under TWO_FACTOR.POLICY="required".
    """
    with captured(phone_otp_requested) as received:
        api_client.post(
            _OTP_REQUEST_URL, {"identifier": "+15559998888", "channel": "phone"}, format="json"
        )
    challenge_id = OtpChallenge.objects.get().challenge_id
    code = received[0]["code"]

    response = api_client.post(
        _OTP_VERIFY_URL, {"challenge_id": str(challenge_id), "code": code}, format="json"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["created"] is True
    assert "access" in body
