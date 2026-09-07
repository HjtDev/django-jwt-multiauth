"""Proves ``POST /otp/request/``, ``POST /otp/verify/``, and ``POST /otp/resend/``
(``views_otp.py``): the decoy path for an unrecognized identifier writes zero rows and fires zero
signals while returning a real-shaped response; a channel whose auth method isn't in
``ALLOWED_AUTH_METHODS`` 400s before ``OtpService`` is ever touched; ``/otp/verify/`` accepts a
magic-link token when ``EMIT_LINK_TOKEN`` is on and rejects one when it's off; a successful verify
runs through the same shared login-response shape as ``/login/``; and the §11 item 19
2FA-bootstrap carve-out fires for a freshly auto-provisioned account but never for an existing
user with no enrolled second factor.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APIClient

from jwt_multiauth.factories import UserFactory
from jwt_multiauth.models import OtpChallenge
from jwt_multiauth.services import OtpService
from jwt_multiauth.signals import email_otp_requested, otp_verified, phone_otp_requested
from tests.backend.conftest import captured

pytestmark = pytest.mark.django_db

_OTP_REQUEST_URL = "/api/v1/auth/otp/request/"
_OTP_VERIFY_URL = "/api/v1/auth/otp/verify/"
_OTP_RESEND_URL = "/api/v1/auth/otp/resend/"

_EMAIL_OTP_SETTINGS = {
    "ALLOWED_AUTH_METHODS": ["password", "email_otp"],
    "USER_FIELDS": {"EMAIL_FIELD": "email"},
}


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    cache.clear()
    yield
    cache.clear()


# --------------------------------------------------------------------- otp/request


def test_request_for_an_unknown_identifier_is_a_zero_row_zero_signal_decoy(
    api_client: APIClient,
) -> None:
    with (
        override_settings(JWT_MULTIAUTH=_EMAIL_OTP_SETTINGS),
        captured(email_otp_requested) as received,
    ):
        response = api_client.post(
            _OTP_REQUEST_URL,
            {"identifier": "nobody@example.com", "channel": "email"},
            format="json",
        )
    assert response.status_code == 200
    assert set(response.json()) == {"challenge_id", "expires_at", "resend_available_at"}
    assert received == []
    assert not OtpChallenge.objects.exists()


def test_request_for_a_real_identifier_persists_a_row_and_fires_the_signal(
    api_client: APIClient,
) -> None:
    UserFactory(email="alice@example.com")
    with (
        override_settings(JWT_MULTIAUTH=_EMAIL_OTP_SETTINGS),
        captured(email_otp_requested) as received,
    ):
        response = api_client.post(
            _OTP_REQUEST_URL,
            {"identifier": "alice@example.com", "channel": "email"},
            format="json",
        )
    assert response.status_code == 200
    assert len(received) == 1
    assert OtpChallenge.objects.filter(destination="alice@example.com").exists()


def test_request_rejects_a_channel_not_in_allowed_auth_methods(api_client: APIClient) -> None:
    # Default settings only enable "password" — phone_otp is not allowed.
    response = api_client.post(
        _OTP_REQUEST_URL, {"identifier": "+15551234567", "channel": "phone"}, format="json"
    )
    assert response.status_code == 400
    assert response.json()["error"]["details"] == {"code": "channel_not_allowed"}


def test_request_rejects_a_channel_not_in_allowed_auth_methods_produces_no_signal(
    api_client: APIClient,
) -> None:
    with captured(phone_otp_requested) as received:
        api_client.post(
            _OTP_REQUEST_URL, {"identifier": "+15551234567", "channel": "phone"}, format="json"
        )
    assert received == []


# --------------------------------------------------------------------- otp/verify


def test_verify_wrong_code_returns_the_challenge_invalid_shape(api_client: APIClient) -> None:
    UserFactory(email="alice@example.com")
    with override_settings(JWT_MULTIAUTH=_EMAIL_OTP_SETTINGS):
        request_response = api_client.post(
            _OTP_REQUEST_URL,
            {"identifier": "alice@example.com", "channel": "email"},
            format="json",
        )
        response = api_client.post(
            _OTP_VERIFY_URL,
            {"challenge_id": request_response.json()["challenge_id"], "code": "000000"},
            format="json",
        )
    assert response.status_code == 400
    assert response.json()["error"]["details"] == {"code": "otp_challenge_invalid"}


def test_verify_unknown_challenge_id_returns_the_same_shape(api_client: APIClient) -> None:
    response = api_client.post(
        _OTP_VERIFY_URL,
        {"challenge_id": "00000000-0000-0000-0000-000000000000", "code": "000000"},
        format="json",
    )
    assert response.status_code == 400
    assert response.json()["error"]["details"] == {"code": "otp_challenge_invalid"}


def test_verify_happy_path_returns_tokens(api_client: APIClient) -> None:
    UserFactory(email="alice@example.com")
    with (
        override_settings(JWT_MULTIAUTH=_EMAIL_OTP_SETTINGS),
        captured(email_otp_requested) as received,
    ):
        api_client.post(
            _OTP_REQUEST_URL,
            {"identifier": "alice@example.com", "channel": "email"},
            format="json",
        )
        challenge_id = OtpChallenge.objects.get().challenge_id
        code = received[0]["code"]

        with captured(otp_verified) as verified:
            response = api_client.post(
                _OTP_VERIFY_URL, {"challenge_id": str(challenge_id), "code": code}, format="json"
            )

    assert response.status_code == 200
    body = response.json()
    assert body["created"] is False
    assert "access" in body
    assert len(verified) == 1


def test_verify_rejects_a_wrong_purpose_challenge(api_client: APIClient) -> None:
    UserFactory(email="alice@example.com")
    with (
        override_settings(
            JWT_MULTIAUTH={**_EMAIL_OTP_SETTINGS, "USER_FIELDS": {"EMAIL_FIELD": "email"}}
        ),
        captured(email_otp_requested) as received,
    ):
        OtpService.request("alice@example.com", channel="email", purpose="verify_contact")
        challenge_id = OtpChallenge.objects.get().challenge_id
        code = received[0]["code"]

        response = api_client.post(
            _OTP_VERIFY_URL, {"challenge_id": str(challenge_id), "code": code}, format="json"
        )
    assert response.status_code == 400
    assert response.json()["error"]["details"] == {"code": "otp_challenge_invalid"}


@override_settings(
    JWT_MULTIAUTH={**_EMAIL_OTP_SETTINGS, "OTP": {"DEFAULTS": {"EMIT_LINK_TOKEN": True}}}
)
def test_verify_accepts_a_link_token_when_emit_link_token_is_on(api_client: APIClient) -> None:
    UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        api_client.post(
            _OTP_REQUEST_URL,
            {"identifier": "alice@example.com", "channel": "email"},
            format="json",
        )
    challenge_id = OtpChallenge.objects.get().challenge_id
    link_token = received[0]["link_token"]
    assert link_token is not None

    response = api_client.post(
        _OTP_VERIFY_URL,
        {"challenge_id": str(challenge_id), "link_token": link_token},
        format="json",
    )
    assert response.status_code == 200


def test_verify_rejects_a_link_token_when_emit_link_token_is_off(api_client: APIClient) -> None:
    UserFactory(email="alice@example.com")
    with override_settings(JWT_MULTIAUTH=_EMAIL_OTP_SETTINGS):
        api_client.post(
            _OTP_REQUEST_URL,
            {"identifier": "alice@example.com", "channel": "email"},
            format="json",
        )
        challenge_id = OtpChallenge.objects.get().challenge_id
        response = api_client.post(
            _OTP_VERIFY_URL,
            {"challenge_id": str(challenge_id), "link_token": "whatever"},
            format="json",
        )
    assert response.status_code == 400
    assert response.json()["error"]["details"] == {"code": "otp_challenge_invalid"}


def test_verify_requires_exactly_one_of_code_or_link_token(api_client: APIClient) -> None:
    neither = api_client.post(
        _OTP_VERIFY_URL, {"challenge_id": "00000000-0000-0000-0000-000000000000"}, format="json"
    )
    both = api_client.post(
        _OTP_VERIFY_URL,
        {
            "challenge_id": "00000000-0000-0000-0000-000000000000",
            "code": "000000",
            "link_token": "whatever",
        },
        format="json",
    )
    assert neither.status_code == 400
    assert both.status_code == 400


# --------------------------------------------------------------------- otp/resend


def test_resend_happy_path_returns_a_fresh_expiry(api_client: APIClient) -> None:
    UserFactory(email="alice@example.com")
    # RESEND_COOLDOWN_SECONDS defaults to 60 — a resend called immediately after request would
    # otherwise hit the cooldown itself (a real, working rail, not a bug this test should trip).
    settings = {**_EMAIL_OTP_SETTINGS, "OTP": {"DEFAULTS": {"RESEND_COOLDOWN_SECONDS": 0}}}
    with override_settings(JWT_MULTIAUTH=settings):
        request_response = api_client.post(
            _OTP_REQUEST_URL,
            {"identifier": "alice@example.com", "channel": "email"},
            format="json",
        )
        response = api_client.post(
            _OTP_RESEND_URL,
            {"challenge_id": request_response.json()["challenge_id"]},
            format="json",
        )
    assert response.status_code == 200
    assert set(response.json()) == {"challenge_id", "expires_at", "resend_available_at"}


def test_resend_unknown_challenge_returns_the_challenge_invalid_shape(
    api_client: APIClient,
) -> None:
    response = api_client.post(
        _OTP_RESEND_URL,
        {"challenge_id": "00000000-0000-0000-0000-000000000000"},
        format="json",
    )
    assert response.status_code == 400
    assert response.json()["error"]["details"] == {"code": "otp_challenge_invalid"}


# --------------------------------------------------------------------- §11 item 19 carve-out


_AUTO_PROVISION_2FA_SETTINGS = {
    "ALLOWED_AUTH_METHODS": ["password", "email_otp"],
    "USER_FIELDS": {"EMAIL_FIELD": "email", "AUTO_PROVISION_METHODS": ["email_otp"]},
    "TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]},
}


@override_settings(JWT_MULTIAUTH=_AUTO_PROVISION_2FA_SETTINGS)
def test_auto_provisioned_login_bootstraps_real_tokens_even_under_2fa_required(
    api_client: APIClient,
) -> None:
    """The 2FA-bootstrap carve-out (docs/CONTRACT.md §10/§11 item 19): a brand-new identifier on
    an AUTO_PROVISION_METHODS-enabled channel gets real tokens immediately, `created: true`,
    never a pending_2fa response — even though TWO_FACTOR.POLICY="required" and the just-created
    account obviously has no enrolled second factor yet.
    """
    assert not get_user_model().objects.filter(email="new-person@example.com").exists()

    with captured(email_otp_requested) as received:
        api_client.post(
            _OTP_REQUEST_URL,
            {"identifier": "new-person@example.com", "channel": "email"},
            format="json",
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
    assert "pending_token" not in body
    assert get_user_model().objects.filter(email="new-person@example.com").exists()


@override_settings(JWT_MULTIAUTH=_AUTO_PROVISION_2FA_SETTINGS)
def test_existing_user_with_no_enrolled_factor_still_fails_closed_under_2fa_required(
    api_client: APIClient,
) -> None:
    """The carve-out's narrowness, proven: an EXISTING user (not created in this request) with no
    enrolled second factor, under the identical settings, still fails closed exactly as an
    ordinary login would — the carve-out never applies retroactively.
    """
    UserFactory(email="existing@example.com")

    with captured(email_otp_requested) as received:
        api_client.post(
            _OTP_REQUEST_URL,
            {"identifier": "existing@example.com", "channel": "email"},
            format="json",
        )
    challenge_id = OtpChallenge.objects.get().challenge_id
    code = received[0]["code"]

    response = api_client.post(
        _OTP_VERIFY_URL, {"challenge_id": str(challenge_id), "code": code}, format="json"
    )
    assert response.status_code == 401
    assert response.json()["error"]["details"] == {"code": "two_factor_unavailable"}
