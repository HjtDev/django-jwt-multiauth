"""Proves the ``/account/verify-contact/request/``, ``/account/verify-contact/confirm/`` HTTP
surface (``views_account.py``): no decoy path (the caller is already authenticated), an
unconfigured/empty contact field 400s with a distinguishable ``details.code``, and a wrong/expired/
wrong-purpose/cross-user challenge all collapse into the identical ``otp_challenge_invalid`` shape
``OtpVerifyView`` also uses.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.test import override_settings
from rest_framework.test import APIClient

from jwt_multiauth.factories import UserFactory
from jwt_multiauth.services import RequestMeta, TokenService
from jwt_multiauth.signals import email_otp_requested
from tests.backend.conftest import captured

pytestmark = pytest.mark.django_db

_REQUEST_URL = "/api/v1/auth/account/verify-contact/request/"
_CONFIRM_URL = "/api/v1/auth/account/verify-contact/confirm/"
_REQUEST_META: RequestMeta = {"ip": "203.0.113.5", "method": "password"}
_EMAIL_FIELD_SETTINGS = {"USER_FIELDS": {"EMAIL_FIELD": "email"}}


def _authed_client(user: Any) -> APIClient:
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {pair.access}")
    return client


# ---------------------------------------------------------------------------------- unauth


@pytest.mark.parametrize("url", [_REQUEST_URL, _CONFIRM_URL])
def test_both_routes_require_authentication(url: str) -> None:
    client = APIClient()
    response = client.post(url, {}, format="json")
    assert response.status_code == 401


# -------------------------------------------------------------------------------- request


@override_settings(JWT_MULTIAUTH=_EMAIL_FIELD_SETTINGS)
def test_request_succeeds_for_a_user_with_a_current_value() -> None:
    user = UserFactory(email="alice@example.com")
    client = _authed_client(user)

    with captured(email_otp_requested) as received:
        response = client.post(_REQUEST_URL, {"field": "email"}, format="json")

    assert response.status_code == 200
    body = response.json()
    assert body["challenge_id"] == received[0]["challenge_id"]
    assert "expires_at" in body
    assert "resend_available_at" in body


@override_settings(JWT_MULTIAUTH=_EMAIL_FIELD_SETTINGS)
def test_request_with_no_current_value_returns_400_no_contact_value() -> None:
    user = UserFactory(email="")
    client = _authed_client(user)

    response = client.post(_REQUEST_URL, {"field": "email"}, format="json")

    assert response.status_code == 400
    assert response.json()["error"]["details"]["code"] == "no_contact_value"


def test_request_with_field_not_configured_returns_400() -> None:
    user = UserFactory()
    client = _authed_client(user)

    response = client.post(_REQUEST_URL, {"field": "email"}, format="json")

    assert response.status_code == 400
    assert response.json()["error"]["details"]["code"] == "field_not_configured"


def test_request_rejects_a_field_outside_the_choice_set() -> None:
    user = UserFactory()
    client = _authed_client(user)
    response = client.post(_REQUEST_URL, {"field": "username"}, format="json")
    assert response.status_code == 400


# -------------------------------------------------------------------------------- confirm


@override_settings(JWT_MULTIAUTH=_EMAIL_FIELD_SETTINGS)
def test_confirm_happy_path_returns_204() -> None:
    user = UserFactory(email="alice@example.com")
    client = _authed_client(user)
    with captured(email_otp_requested) as received:
        client.post(_REQUEST_URL, {"field": "email"}, format="json")
    challenge_id = received[0]["challenge_id"]
    code = received[0]["code"]

    response = client.post(
        _CONFIRM_URL, {"challenge_id": challenge_id, "code": code}, format="json"
    )

    assert response.status_code == 204


@override_settings(JWT_MULTIAUTH=_EMAIL_FIELD_SETTINGS)
def test_confirm_wrong_code_returns_400_otp_challenge_invalid() -> None:
    user = UserFactory(email="alice@example.com")
    client = _authed_client(user)
    with captured(email_otp_requested) as received:
        client.post(_REQUEST_URL, {"field": "email"}, format="json")
    challenge_id = received[0]["challenge_id"]

    response = client.post(
        _CONFIRM_URL, {"challenge_id": challenge_id, "code": "000000"}, format="json"
    )

    assert response.status_code == 400
    assert response.json()["error"]["details"]["code"] == "otp_challenge_invalid"


@override_settings(JWT_MULTIAUTH=_EMAIL_FIELD_SETTINGS)
def test_confirm_a_different_users_challenge_returns_the_same_otp_challenge_invalid_shape() -> None:
    owner = UserFactory(email="alice@example.com")
    stranger = UserFactory(email="bob@example.com")
    owner_client = _authed_client(owner)
    stranger_client = _authed_client(stranger)
    with captured(email_otp_requested) as received:
        owner_client.post(_REQUEST_URL, {"field": "email"}, format="json")
    challenge_id = received[0]["challenge_id"]
    code = received[0]["code"]

    response = stranger_client.post(
        _CONFIRM_URL, {"challenge_id": challenge_id, "code": code}, format="json"
    )

    assert response.status_code == 400
    assert response.json()["error"]["details"]["code"] == "otp_challenge_invalid"


def test_confirm_an_unresolvable_challenge_id_returns_the_same_shape() -> None:
    user = UserFactory()
    client = _authed_client(user)
    response = client.post(
        _CONFIRM_URL,
        {"challenge_id": "00000000-0000-0000-0000-000000000000", "code": "000000"},
        format="json",
    )
    assert response.status_code == 400
    assert response.json()["error"]["details"]["code"] == "otp_challenge_invalid"
