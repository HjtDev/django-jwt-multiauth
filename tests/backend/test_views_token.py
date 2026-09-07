"""Proves the ``/token/refresh/``, ``/token/verify/``, ``/logout/``, ``/logout/all/`` HTTP surface
(``views_token.py``): refresh rotates and re-sets the cookie under the default transport, and
round-trips ``refresh`` in the body under ``REFRESH_COOKIE["TRANSPORT"] == "body"``; a missing or
replayed refresh token 401s, and a replay fires ``refresh_reuse_detected`` and kills the whole
session (a subsequent refresh with the OLD token still 401s); ``/token/verify/`` never returns
anything but ``200``; ``/logout/`` fires ``user_logged_out`` for the CALLER's own session only and
clears both cookies; ``/logout/all/`` revokes every session and reports ``revoked_count``.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.test import override_settings
from rest_framework.test import APIClient

from jwt_multiauth import conf
from jwt_multiauth.factories import AuthSessionFactory, UserFactory
from jwt_multiauth.models import AuthSession
from jwt_multiauth.services import RequestMeta, TokenService
from jwt_multiauth.signals import user_logged_out
from tests.backend.conftest import captured

pytestmark = pytest.mark.django_db

_REFRESH_URL = "/api/v1/auth/token/refresh/"
_VERIFY_URL = "/api/v1/auth/token/verify/"
_LOGOUT_URL = "/api/v1/auth/logout/"
_LOGOUT_ALL_URL = "/api/v1/auth/logout/all/"
_REQUEST_META: RequestMeta = {"ip": "203.0.113.5", "method": "password"}


def _authed_client(user: Any) -> APIClient:
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {pair.access}")
    return client


def _refresh_cookie_name() -> str:
    return str(conf.get_setting("REFRESH_COOKIE")["NAME"])


# ------------------------------------------------------------------------------ token/refresh


def test_refresh_rotates_via_cookie_and_re_sets_it() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)
    client = APIClient()
    client.cookies[_refresh_cookie_name()] = pair.refresh

    response = client.post(_REFRESH_URL, {}, format="json")

    assert response.status_code == 200
    body = response.json()
    assert body["session_id"] == pair.session_id
    assert "access" in body
    assert "refresh" not in body
    new_cookie = response.cookies[_refresh_cookie_name()].value
    assert new_cookie and new_cookie != pair.refresh


@override_settings(JWT_MULTIAUTH={"REFRESH_COOKIE": {"TRANSPORT": "body"}})
def test_refresh_round_trips_refresh_token_via_body_transport() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)
    client = APIClient()

    response = client.post(_REFRESH_URL, {"refresh": pair.refresh}, format="json")

    assert response.status_code == 200
    body = response.json()
    assert body["refresh"] != pair.refresh
    assert body["session_id"] == pair.session_id


def test_refresh_with_no_token_anywhere_returns_401() -> None:
    client = APIClient()
    response = client.post(_REFRESH_URL, {}, format="json")
    assert response.status_code == 401
    assert response.json()["error"]["details"]["code"] == "invalid_refresh_token"


def test_refresh_replay_detects_reuse_and_revokes_the_session() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)
    client = APIClient()
    client.cookies[_refresh_cookie_name()] = pair.refresh

    first = client.post(_REFRESH_URL, {}, format="json")
    assert first.status_code == 200

    # Replay the ORIGINAL (now-superseded) refresh token — a fresh client, since the first
    # client's cookie jar now holds the rotated value.
    replay_client = APIClient()
    replay_client.cookies[_refresh_cookie_name()] = pair.refresh

    from jwt_multiauth.signals import refresh_reuse_detected

    with captured(refresh_reuse_detected) as received:
        second = replay_client.post(_REFRESH_URL, {}, format="json")

    assert second.status_code == 401
    assert second.json()["error"]["details"]["code"] == "refresh_reuse_detected"
    assert received == [
        {
            "sender": AuthSession,
            "user_id": user.pk,
            "session_id": pair.session_id,
            "ip": "127.0.0.1",
        }
    ]

    session = AuthSession.objects.get(pk=pair.session_id)
    assert session.revoked_at is not None
    assert session.revoked_reason == "reuse_detected"


# ------------------------------------------------------------------------------- token/verify


def test_verify_a_live_access_token_returns_valid_true_with_claims() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)
    client = APIClient()

    response = client.post(_VERIFY_URL, {"token": pair.access}, format="json")

    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["claims"]["sub"] == str(user.pk)


def test_verify_a_garbage_token_returns_200_valid_false_never_401() -> None:
    client = APIClient()
    response = client.post(_VERIFY_URL, {"token": "not-a-real-token"}, format="json")
    assert response.status_code == 200
    assert response.json() == {"valid": False}


def test_verify_a_refresh_token_presented_as_an_access_token_is_invalid() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)
    client = APIClient()
    response = client.post(_VERIFY_URL, {"token": pair.refresh}, format="json")
    assert response.status_code == 200
    assert response.json()["valid"] is False


# ------------------------------------------------------------------------------------- logout


def test_logout_requires_authentication() -> None:
    client = APIClient()
    response = client.post(_LOGOUT_URL, {}, format="json")
    assert response.status_code == 401


def test_logout_revokes_only_the_callers_current_session_and_fires_user_logged_out() -> None:
    user = UserFactory()
    other_session = AuthSessionFactory(user=user)
    client = _authed_client(user)

    with captured(user_logged_out) as received:
        response = client.post(_LOGOUT_URL, {}, format="json")

    assert response.status_code == 204
    assert len(received) == 1
    assert received[0]["sender"] == AuthSession
    assert received[0]["user_id"] == user.pk
    own_session_id = received[0]["session_id"]

    own_session = AuthSession.objects.get(pk=own_session_id)
    assert own_session.revoked_at is not None
    assert own_session.revoked_reason == "user_logout"

    # The OTHER session for this same user is untouched — logout revokes the caller's own
    # session only, never every session for the user.
    other_session.refresh_from_db()
    assert other_session.revoked_at is None


def test_logout_clears_both_auth_cookies() -> None:
    user = UserFactory()
    client = _authed_client(user)
    response = client.post(_LOGOUT_URL, {}, format="json")
    assert response.status_code == 204
    refresh_cookie = response.cookies[_refresh_cookie_name()]
    assert refresh_cookie.value == ""
    trusted_device_cookie_name = conf.get_setting("TWO_FACTOR")["TRUSTED_DEVICE"]["COOKIE_NAME"]
    assert response.cookies[trusted_device_cookie_name].value == ""


def test_logout_then_refresh_with_the_now_revoked_session_401s() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {pair.access}")

    logout_response = client.post(_LOGOUT_URL, {}, format="json")
    assert logout_response.status_code == 204

    refresh_client = APIClient()
    refresh_client.cookies[_refresh_cookie_name()] = pair.refresh
    refresh_response = refresh_client.post(_REFRESH_URL, {}, format="json")
    assert refresh_response.status_code == 401


# --------------------------------------------------------------------------------- logout/all


def test_logout_all_requires_authentication() -> None:
    client = APIClient()
    response = client.post(_LOGOUT_ALL_URL, {}, format="json")
    assert response.status_code == 401


def test_logout_all_revokes_every_session_and_reports_the_count() -> None:
    user = UserFactory()
    AuthSessionFactory(user=user)
    AuthSessionFactory(user=user)
    client = _authed_client(user)  # a THIRD session, the caller's own

    response = client.post(_LOGOUT_ALL_URL, {}, format="json")

    assert response.status_code == 200
    assert response.json() == {"revoked_count": 3}
    assert not AuthSession.objects.filter(user=user, revoked_at__isnull=True).exists()


def test_logout_all_clears_auth_cookies() -> None:
    user = UserFactory()
    client = _authed_client(user)
    response = client.post(_LOGOUT_ALL_URL, {}, format="json")
    assert response.status_code == 200
    assert response.cookies[_refresh_cookie_name()].value == ""
