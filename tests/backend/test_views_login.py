"""Proves ``POST /login/`` (``views_password.LoginView``): an unknown identifier and a known
identifier with a wrong password produce byte-for-byte the same 401 body; a locked-out account
never reaches ``PasswordService.authenticate`` at all; a successful login issues real tokens
(with the refresh cookie set per ``REFRESH_COOKIE`` settings, or in the body under
``TRANSPORT="body"``); and 2FA-enabled settings produce the ``pending_2fa`` shape instead.
"""

from __future__ import annotations

import statistics
import time
from unittest.mock import patch

import pytest
from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APIClient

from jwt_multiauth.factories import TwoFactorDeviceFactory, UserFactory
from jwt_multiauth.models import LoginAttempt
from jwt_multiauth.services import PasswordService

pytestmark = pytest.mark.django_db

_LOGIN_URL = "/api/v1/auth/login/"
_PASSWORD = "correct-horse-battery-staple-9"


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    cache.clear()
    yield
    cache.clear()


def _make_user(**extra: str) -> object:
    user = UserFactory(**extra)
    user.set_password(_PASSWORD)
    user.save()
    return user


def test_unknown_identifier_and_wrong_password_are_byte_for_byte_identical(
    api_client: APIClient,
) -> None:
    _make_user(username="alice")

    unknown = api_client.post(
        _LOGIN_URL,
        {"identifier": "nobody-at-all", "password": "whatever"},
        format="json",
        HTTP_X_REQUEST_ID="fixed-test-request-id",
    )
    wrong_password = api_client.post(
        _LOGIN_URL,
        {"identifier": "alice", "password": "wrong-password"},
        format="json",
        HTTP_X_REQUEST_ID="fixed-test-request-id",
    )

    assert unknown.status_code == 401
    assert wrong_password.status_code == 401
    assert unknown.json() == wrong_password.json()
    assert unknown.json() == {
        "error": {
            "code": "authentication_failed",
            "message": "Request failed.",
            "details": {"code": "invalid_credentials"},
            "request_id": "fixed-test-request-id",
        }
    }


@pytest.mark.slow
@override_settings(
    REST_FRAMEWORK={
        "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
        "EXCEPTION_HANDLER": "appkit.exceptions.standard_exception_handler",
        "NUM_PROXIES": 1,
        # Well above this test's own 60 requests — a real "20/min" would throttle partway
        # through and skew the timing measurement toward near-zero on later requests.
        "DEFAULT_THROTTLE_RATES": {"jwt_multiauth_login": "10000/min"},
    }
)
def test_unknown_identifier_and_wrong_password_cost_comparable_time(
    api_client: APIClient,
) -> None:
    _make_user(username="alice")

    def timed(identifier: str) -> float:
        start = time.perf_counter()
        api_client.post(_LOGIN_URL, {"identifier": identifier, "password": "wrong"}, format="json")
        return time.perf_counter() - start

    unknown_times = [timed("nobody-at-all") for _ in range(30)]
    wrong_password_times = [timed("alice") for _ in range(30)]

    unknown_median = statistics.median(unknown_times)
    wrong_password_median = statistics.median(wrong_password_times)
    ratio = max(unknown_median, wrong_password_median) / max(
        min(unknown_median, wrong_password_median), 1e-9
    )
    assert ratio < 5  # generous tolerance — proving "comparable", not "identical"; view-layer
    # overhead (serializer validation, middleware) adds noise on top of the service-layer number


def test_a_locked_account_never_reaches_password_service_authenticate(
    api_client: APIClient,
) -> None:
    _make_user(username="alice")
    lockout_settings = {"LOCKOUT": {"MAX_ATTEMPTS": 1, "WINDOW_SECONDS": 900}}
    with override_settings(JWT_MULTIAUTH=lockout_settings):
        # First bad attempt trips the lock (MAX_ATTEMPTS=1).
        api_client.post(_LOGIN_URL, {"identifier": "alice", "password": "wrong"}, format="json")

        with patch.object(PasswordService, "authenticate") as mock_authenticate:
            response = api_client.post(
                _LOGIN_URL, {"identifier": "alice", "password": _PASSWORD}, format="json"
            )

        mock_authenticate.assert_not_called()
        assert response.status_code == 401
        assert response.json()["error"]["details"] == {"code": "account_locked"}


def test_a_locked_account_login_attempt_is_still_recorded(api_client: APIClient) -> None:
    _make_user(username="alice")
    with override_settings(JWT_MULTIAUTH={"LOCKOUT": {"MAX_ATTEMPTS": 1, "WINDOW_SECONDS": 900}}):
        api_client.post(_LOGIN_URL, {"identifier": "alice", "password": "wrong"}, format="json")
        api_client.post(_LOGIN_URL, {"identifier": "alice", "password": _PASSWORD}, format="json")

    reasons = list(
        LoginAttempt.objects.filter(identifier="alice")
        .order_by("created_at")
        .values_list("failure_reason", flat=True)
    )
    assert reasons == ["wrong_credential", "locked"]


def test_successful_login_issues_real_tokens_and_sets_the_refresh_cookie(
    api_client: APIClient,
) -> None:
    _make_user(username="alice")
    response = api_client.post(
        _LOGIN_URL, {"identifier": "alice", "password": _PASSWORD}, format="json"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["created"] is False
    assert "access" in body
    assert "session_id" in body
    assert "refresh" not in body  # default TRANSPORT="cookie"
    assert "jwt_multiauth_refresh" in response.cookies
    cookie = response.cookies["jwt_multiauth_refresh"]
    assert cookie["httponly"]
    assert cookie["samesite"] == "Lax"


@override_settings(JWT_MULTIAUTH={"REFRESH_COOKIE": {"TRANSPORT": "body"}})
def test_successful_login_returns_refresh_in_body_under_body_transport(
    api_client: APIClient,
) -> None:
    _make_user(username="alice")
    response = api_client.post(
        _LOGIN_URL, {"identifier": "alice", "password": _PASSWORD}, format="json"
    )
    assert response.status_code == 200
    assert "refresh" in response.json()
    assert "jwt_multiauth_refresh" not in response.cookies


def test_successful_login_records_a_successful_login_attempt(api_client: APIClient) -> None:
    _make_user(username="alice")
    api_client.post(_LOGIN_URL, {"identifier": "alice", "password": _PASSWORD}, format="json")
    attempt = LoginAttempt.objects.get(identifier="alice")
    assert attempt.success is True
    assert attempt.failure_reason is None


@override_settings(
    JWT_MULTIAUTH={"TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]}}
)
def test_login_with_2fa_required_and_an_eligible_method_returns_pending_2fa(
    api_client: APIClient,
) -> None:
    user = _make_user(username="alice")
    TwoFactorDeviceFactory(user=user, method="totp")

    response = api_client.post(
        _LOGIN_URL, {"identifier": "alice", "password": _PASSWORD}, format="json"
    )
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"pending_token", "eligible_methods"}
    assert body["eligible_methods"] == ["totp"]
    assert "error" not in body


@override_settings(
    JWT_MULTIAUTH={"TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]}}
)
def test_login_with_2fa_required_and_no_eligible_method_fails_closed(
    api_client: APIClient,
) -> None:
    _make_user(username="alice")  # no TwoFactorDevice enrolled at all

    response = api_client.post(
        _LOGIN_URL, {"identifier": "alice", "password": _PASSWORD}, format="json"
    )
    assert response.status_code == 401
    assert response.json()["error"]["details"] == {"code": "two_factor_unavailable"}


# The throttle-scope-per-endpoint tests live in test_views_throttling.py, one file covering
# every Phase 6 endpoint — see that module's docstring for why a direct monkeypatch of
# ScopedRateThrottle.THROTTLE_RATES, not override_settings, is the only technique that works.
