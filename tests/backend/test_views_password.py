"""Proves ``POST /password/change/``, ``POST /password/reset/request/``, and
``POST /password/reset/confirm/`` (``views_password.py``): a wrong old password and a failing
validator both 400 with field-level detail; a password reset request always returns 200
regardless of whether the identifier resolves; and reset-confirm collapses every invalid-challenge
cause into the identical ``otp_challenge_invalid`` shape, including a wrong-purpose challenge and
one that just auto-provisioned a new account.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APIClient

from jwt_multiauth import otp as otp_module
from jwt_multiauth.factories import UserFactory
from jwt_multiauth.models import AuthSession, OtpChallenge
from jwt_multiauth.services import OtpService, PasswordService, RequestMeta, TokenService

pytestmark = pytest.mark.django_db

_PASSWORD_CHANGE_URL = "/api/v1/auth/password/change/"
_RESET_REQUEST_URL = "/api/v1/auth/password/reset/request/"
_RESET_CONFIRM_URL = "/api/v1/auth/password/reset/confirm/"
_REQUEST_META: RequestMeta = {"ip": "203.0.113.5", "method": "password"}


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    cache.clear()
    yield
    cache.clear()


def _authed_client(user: object) -> APIClient:
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {pair.access}")
    return client


# --------------------------------------------------------------------- password/change


def test_password_change_wrong_old_password_returns_400_with_field_detail() -> None:
    user = UserFactory()
    user.set_password("the-real-password-9")
    user.save()
    client = _authed_client(user)

    response = client.post(
        _PASSWORD_CHANGE_URL,
        {"old_password": "not-the-real-password", "new_password": "a-brand-new-password-9"},
        format="json",
    )
    assert response.status_code == 400
    assert "old_password" in response.json()["error"]["details"]


@override_settings(
    AUTH_PASSWORD_VALIDATORS=[
        {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"}
    ]
)
def test_password_change_weak_new_password_returns_400_with_field_detail() -> None:
    # AUTH_PASSWORD_VALIDATORS is [] in tests/backend/settings.py (Django's own real default,
    # not the four validators django-admin startproject's TEMPLATE adds) — a validator is
    # overridden in explicitly for this one test, or nothing here would ever fail validation.
    user = UserFactory()
    user.set_password("the-real-password-9")
    user.save()
    client = _authed_client(user)

    response = client.post(
        _PASSWORD_CHANGE_URL,
        {"old_password": "the-real-password-9", "new_password": "12345678"},
        format="json",
    )
    assert response.status_code == 400
    assert "new_password" in response.json()["error"]["details"]


def test_password_change_success_revokes_every_session() -> None:
    user = UserFactory()
    user.set_password("the-real-password-9")
    user.save()
    other_pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)
    client = _authed_client(user)

    response = client.post(
        _PASSWORD_CHANGE_URL,
        {"old_password": "the-real-password-9", "new_password": "a-brand-new-password-9"},
        format="json",
    )
    assert response.status_code == 204
    assert not AuthSession.objects.filter(
        pk=other_pair.session_id, revoked_at__isnull=True
    ).exists()
    user.refresh_from_db()
    assert user.check_password("a-brand-new-password-9")


def test_password_change_requires_authentication(api_client: APIClient) -> None:
    response = api_client.post(
        _PASSWORD_CHANGE_URL,
        {"old_password": "whatever", "new_password": "whatever-else-9"},
        format="json",
    )
    assert response.status_code == 401


# --------------------------------------------------------------------- password/reset/request


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_reset_request_always_returns_200_for_an_unknown_identifier(api_client: APIClient) -> None:
    response = api_client.post(_RESET_REQUEST_URL, {"identifier": "nobody-at-all"}, format="json")
    assert response.status_code == 200
    assert response.json() == {}


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_reset_request_always_returns_200_for_a_real_identifier(api_client: APIClient) -> None:
    UserFactory(username="alice")
    response = api_client.post(_RESET_REQUEST_URL, {"identifier": "alice"}, format="json")
    assert response.status_code == 200
    assert response.json() == {}


# --------------------------------------------------------------------- password/reset/confirm


def test_reset_confirm_unknown_challenge_id_returns_the_challenge_invalid_shape(
    api_client: APIClient,
) -> None:
    response = api_client.post(
        _RESET_CONFIRM_URL,
        {
            "challenge_id": "00000000-0000-0000-0000-000000000000",
            "code": "000000",
            "new_password": "a-brand-new-password-9",
        },
        format="json",
    )
    assert response.status_code == 400
    assert response.json()["error"]["details"] == {"code": "otp_challenge_invalid"}


@override_settings(
    JWT_MULTIAUTH={
        "ALLOWED_AUTH_METHODS": ["password", "email_otp"],
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
    }
)
def test_reset_confirm_wrong_purpose_challenge_is_rejected(api_client: APIClient) -> None:
    user = UserFactory(email="alice@example.com")
    # A "login" purpose challenge, not "password_reset" — must not be redeemable here.
    result = OtpService.request("alice@example.com", channel="email", purpose="login")
    challenge = OtpChallenge.objects.get(pk=result.challenge_id)

    # Recovering the real code isn't possible (hashed) — patch verify_secret instead so the OTP
    # comparison itself succeeds, isolating this test to the purpose check alone.
    with patch.object(otp_module, "verify_secret", return_value=True):
        response = api_client.post(
            _RESET_CONFIRM_URL,
            {
                "challenge_id": str(challenge.challenge_id),
                "code": "000000",
                "new_password": "a-brand-new-password-9",
            },
            format="json",
        )
    assert response.status_code == 400
    assert response.json()["error"]["details"] == {"code": "otp_challenge_invalid"}
    user.refresh_from_db()
    assert not user.check_password("a-brand-new-password-9")


@override_settings(
    JWT_MULTIAUTH={
        "ALLOWED_AUTH_METHODS": ["password", "email_otp"],
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
        "PASSWORD": {"RESET_CHANNEL_PREFERENCE": ["email"]},
    }
)
def test_reset_confirm_happy_path_sets_the_new_password(api_client: APIClient) -> None:
    user = UserFactory(email="alice@example.com", username="alice")
    user.set_password("old-password-9")
    user.save()

    PasswordService.request_reset("alice")
    challenge = OtpChallenge.objects.get(purpose="password_reset")

    with patch.object(otp_module, "verify_secret", return_value=True):
        response = api_client.post(
            _RESET_CONFIRM_URL,
            {
                "challenge_id": str(challenge.challenge_id),
                "code": "000000",
                "new_password": "a-brand-new-password-9",
            },
            format="json",
        )
    assert response.status_code == 204
    user.refresh_from_db()
    assert user.check_password("a-brand-new-password-9")


@override_settings(
    JWT_MULTIAUTH={
        "ALLOWED_AUTH_METHODS": ["password", "email_otp"],
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
        "PASSWORD": {"RESET_CHANNEL_PREFERENCE": ["email"]},
    },
    AUTH_PASSWORD_VALIDATORS=[
        {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"}
    ],
)
def test_reset_confirm_weak_new_password_returns_400_with_field_detail(
    api_client: APIClient,
) -> None:
    user = UserFactory(email="alice@example.com", username="alice")
    user.set_password("old-password-9")
    user.save()

    PasswordService.request_reset("alice")
    challenge = OtpChallenge.objects.get(purpose="password_reset")

    with patch.object(otp_module, "verify_secret", return_value=True):
        response = api_client.post(
            _RESET_CONFIRM_URL,
            {
                "challenge_id": str(challenge.challenge_id),
                "code": "000000",
                "new_password": "12345678",
            },
            format="json",
        )
    assert response.status_code == 400
    assert "new_password" in response.json()["error"]["details"]
    user.refresh_from_db()
    assert not user.check_password("12345678")
