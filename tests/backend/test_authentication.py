"""Proves ``jwt_multiauth.authentication.JWTAuthentication``: a valid access token resolves
``request.user``; a missing header authenticates as anonymous (returns ``None``, never raises);
and a refresh or ``pending_2fa`` token — or any other malformed/expired/forged token — is
rejected with ``AuthenticationFailed``, never silently authenticated. Also proves the end-to-end
HTTP path via ``POST /password/change/``, the one Phase 6 endpoint that actually requires it.
"""

from __future__ import annotations

import pytest
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request
from rest_framework.test import APIClient, APIRequestFactory

from jwt_multiauth.authentication import JWTAuthentication
from jwt_multiauth.factories import UserFactory
from jwt_multiauth.services import RequestMeta, TokenService

pytestmark = pytest.mark.django_db

_REQUEST_META: RequestMeta = {"ip": "203.0.113.5", "method": "password"}


def _drf_request(*, authorization: str | None = None) -> Request:
    factory = APIRequestFactory()
    kwargs = {"HTTP_AUTHORIZATION": authorization} if authorization else {}
    return Request(factory.get("/", **kwargs))


def test_no_header_authenticates_as_none() -> None:
    assert JWTAuthentication().authenticate(_drf_request()) is None


def test_header_without_bearer_prefix_authenticates_as_none() -> None:
    request = _drf_request(authorization="Basic somevalue")
    assert JWTAuthentication().authenticate(request) is None


def test_valid_access_token_resolves_the_user() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)

    request = _drf_request(authorization=f"Bearer {pair.access}")
    result = JWTAuthentication().authenticate(request)

    assert result is not None
    resolved_user, claims = result
    assert resolved_user == user
    assert claims["sub"] == str(user.pk)


def test_refresh_token_is_rejected() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)

    request = _drf_request(authorization=f"Bearer {pair.refresh}")
    with pytest.raises(AuthenticationFailed):
        JWTAuthentication().authenticate(request)


def test_pending_2fa_token_is_rejected() -> None:
    user = UserFactory()
    pending = TokenService.issue_pending_2fa_token(
        user, primary_method="password", request_meta=_REQUEST_META
    )

    request = _drf_request(authorization=f"Bearer {pending}")
    with pytest.raises(AuthenticationFailed):
        JWTAuthentication().authenticate(request)


def test_malformed_token_is_rejected() -> None:
    request = _drf_request(authorization="Bearer not-a-real-token")
    with pytest.raises(AuthenticationFailed):
        JWTAuthentication().authenticate(request)


def test_token_for_a_deleted_user_is_rejected() -> None:
    user = UserFactory()
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)
    user.delete()

    request = _drf_request(authorization=f"Bearer {pair.access}")
    with pytest.raises(AuthenticationFailed):
        JWTAuthentication().authenticate(request)


def test_authenticate_header_is_bearer() -> None:
    assert JWTAuthentication().authenticate_header(_drf_request()) == "Bearer"


# --------------------------------------------------------------------- end-to-end over HTTP


def test_password_change_over_http_accepts_a_valid_bearer_token() -> None:
    user = UserFactory()
    user.set_password("correct-horse-battery-staple-9")
    user.save()
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)

    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {pair.access}")
    response = client.post(
        "/api/v1/auth/password/change/",
        {
            "old_password": "correct-horse-battery-staple-9",
            "new_password": "another-correct-horse-battery-8",
        },
        format="json",
    )
    assert response.status_code == 204


def test_password_change_over_http_rejects_a_missing_token() -> None:
    client = APIClient()
    response = client.post(
        "/api/v1/auth/password/change/",
        {"old_password": "whatever", "new_password": "whatever-else-9"},
        format="json",
    )
    assert response.status_code == 401
