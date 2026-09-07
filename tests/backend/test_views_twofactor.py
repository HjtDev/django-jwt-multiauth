"""Proves the ``/2fa/*`` HTTP surface (``views_twofactor.py``): ``GET /2fa/status/``,
``POST /2fa/totp/enroll/``, ``POST /2fa/totp/confirm/``, ``POST /2fa/disable/``,
``POST /2fa/recovery-codes/regenerate/``, ``POST /2fa/otp/request/`` (a Phase 7 addition, not in
``docs/CONTRACT.md``'s frozen §5 table — see its own docstring), and ``POST /2fa/verify/``. Every
``IsAuthenticated`` route 401s with no credentials; ``/2fa/disable/``/``/2fa/recovery-codes/
regenerate/`` reject a wrong password before ever reaching ``TwoFactorService``; the TOTP secret
appears in exactly one response body, never again afterward; and ``/2fa/verify/`` returns only
``200``/``401`` — never ``400`` — for every failure mode, per §5's own literal row for that route.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from django.core.cache import cache
from django.test import override_settings
from freezegun import freeze_time
from rest_framework.test import APIClient

from jwt_multiauth.factories import RecoveryCodeFactory, UserFactory, VerifiedContactFactory
from jwt_multiauth.models import RecoveryCode, TwoFactorDevice
from jwt_multiauth.services import TokenService

#: A hard `import pyotp` at module scope would crash collection under the bare-install leg
#: (`make test-bare`) BEFORE `pytestmark`'s `requires_extra` marker ever gets a chance to
#: deselect anything — marker filtering only applies to already-collected tests.
#: `importorskip` converts that would-be collection error into a clean whole-module skip instead.
pyotp = pytest.importorskip("pyotp")

pytestmark = [pytest.mark.django_db, pytest.mark.requires_extra]

_STATUS_URL = "/api/v1/auth/2fa/status/"
_TOTP_ENROLL_URL = "/api/v1/auth/2fa/totp/enroll/"
_TOTP_CONFIRM_URL = "/api/v1/auth/2fa/totp/confirm/"
_DISABLE_URL = "/api/v1/auth/2fa/disable/"
_RECOVERY_REGENERATE_URL = "/api/v1/auth/2fa/recovery-codes/regenerate/"
_OTP_REQUEST_2FA_URL = "/api/v1/auth/2fa/otp/request/"
_VERIFY_URL = "/api/v1/auth/2fa/verify/"

_PASSWORD = "correct-horse-battery-staple-9"
_BASE_TIME = datetime(2026, 1, 1, 0, 0, 0)
_STEP = timedelta(seconds=30)

_TOTP_SETTINGS = {"TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]}}


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


def _authed_client(user: object) -> APIClient:
    pair = TokenService.issue_token_pair(
        user, request_meta={"ip": "203.0.113.5", "method": "password"}
    )
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {pair.access}")
    return client


def _enroll_and_confirm_totp(user: object, client: APIClient) -> str:
    """Enrolls + confirms a TOTP device over real HTTP at ``_BASE_TIME``, returning the plaintext
    secret so a caller can generate a later-step login code (see the service-layer tests'
    identical reasoning for why confirm and login codes must land on different TOTP steps).

    The confirm request needs a FRESH Bearer token minted at the frozen instant itself — `client`'s
    own token was issued at real "now" and would read as "not yet valid" once time is frozen
    backward to `_BASE_TIME` (JWT `nbf` in the future relative to frozen "now").
    """
    enroll_response = client.post(_TOTP_ENROLL_URL)
    secret = enroll_response.json()["secret"]
    with freeze_time(_BASE_TIME):
        confirm_client = _authed_client(user)
        confirm_response = confirm_client.post(
            _TOTP_CONFIRM_URL, {"code": pyotp.TOTP(secret).now()}
        )
    assert confirm_response.status_code == 204
    return secret


# ------------------------------------------------------------------- unauthenticated rejection


@pytest.mark.parametrize(
    "url",
    [_STATUS_URL, _TOTP_ENROLL_URL, _TOTP_CONFIRM_URL, _DISABLE_URL, _RECOVERY_REGENERATE_URL],
)
def test_authenticated_routes_reject_an_unauthenticated_caller(
    api_client: APIClient, url: str
) -> None:
    method = api_client.get if url == _STATUS_URL else api_client.post
    response = method(url, {} if url != _STATUS_URL else None, format="json")
    assert response.status_code == 401


# ------------------------------------------------------------------------------------ status


def test_status_reflects_no_enrollment() -> None:
    user = _make_user(username="alice")
    client = _authed_client(user)

    response = client.get(_STATUS_URL)
    assert response.status_code == 200
    body = response.json()
    assert body["policy"] == "off"
    assert body["enrolled_methods"] == []
    assert body["eligible_methods"] == []


@override_settings(JWT_MULTIAUTH=_TOTP_SETTINGS)
def test_status_reflects_a_confirmed_totp_device() -> None:
    user = _make_user(username="alice")
    client = _authed_client(user)
    _enroll_and_confirm_totp(user, client)

    response = client.get(_STATUS_URL)
    body = response.json()
    assert body["policy"] == "required"
    assert body["enrolled_methods"] == ["totp"]
    assert body["eligible_methods"] == ["totp"]


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
        "TWO_FACTOR": {
            "POLICY": "required",
            "ALLOWED_METHODS": ["totp", "email_otp", "recovery_code"],
        },
    }
)
def test_status_reflects_email_otp_and_recovery_code_enrollment() -> None:
    user = _make_user(username="alice", email="alice@example.com")
    client = _authed_client(user)
    _enroll_and_confirm_totp(user, client)
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")
    RecoveryCodeFactory(user=user)

    response = client.get(_STATUS_URL)
    body = response.json()
    assert set(body["enrolled_methods"]) == {"totp", "email_otp", "recovery_code"}
    assert set(body["eligible_methods"]) == {"totp", "email_otp", "recovery_code"}


# -------------------------------------------------------------------------------- totp enroll


def test_totp_enroll_returns_a_secret_and_otpauth_uri_exactly_once() -> None:
    user = _make_user(username="alice")
    client = _authed_client(user)

    response = client.post(_TOTP_ENROLL_URL)
    assert response.status_code == 200
    body = response.json()
    assert "secret" in body
    assert body["otpauth_uri"].startswith("otpauth://totp/")

    status_response = client.get(_STATUS_URL)
    assert "secret" not in status_response.json()
    assert body["secret"] not in status_response.content.decode()


# -------------------------------------------------------------------------------- totp confirm


def test_totp_confirm_happy_path_returns_204() -> None:
    user = _make_user(username="alice")
    client = _authed_client(user)
    secret = _enroll_and_confirm_totp(user, client)
    assert TwoFactorDevice.objects.get(user=user, method="totp").confirmed_at is not None
    assert secret  # sanity — enrollment actually happened


def test_totp_confirm_wrong_code_returns_400() -> None:
    user = _make_user(username="alice")
    client = _authed_client(user)
    client.post(_TOTP_ENROLL_URL)

    response = client.post(_TOTP_CONFIRM_URL, {"code": "000000"})
    assert response.status_code == 400
    assert response.json()["error"]["details"] == {"code": "invalid_totp_code"}


def test_totp_confirm_with_no_pending_enrollment_returns_400() -> None:
    user = _make_user(username="alice")
    client = _authed_client(user)

    response = client.post(_TOTP_CONFIRM_URL, {"code": "000000"})
    assert response.status_code == 400
    assert response.json()["error"]["details"] == {"code": "no_pending_totp_enrollment"}


# -------------------------------------------------------------------------------------- disable


def test_disable_rejects_a_wrong_password() -> None:
    user = _make_user(username="alice")
    client = _authed_client(user)
    _enroll_and_confirm_totp(user, client)

    response = client.post(_DISABLE_URL, {"method": "totp", "password": "not-the-password"})
    assert response.status_code == 400
    assert TwoFactorDevice.objects.get(user=user, method="totp").disabled_at is None


def test_disable_happy_path_disables_the_method() -> None:
    user = _make_user(username="alice")
    client = _authed_client(user)
    _enroll_and_confirm_totp(user, client)

    response = client.post(_DISABLE_URL, {"method": "totp", "password": _PASSWORD})
    assert response.status_code == 204
    assert TwoFactorDevice.objects.get(user=user, method="totp").disabled_at is not None


def test_disable_a_method_not_enrolled_returns_400() -> None:
    user = _make_user(username="alice")
    client = _authed_client(user)

    response = client.post(_DISABLE_URL, {"method": "totp", "password": _PASSWORD})
    assert response.status_code == 400
    assert response.json()["error"]["details"] == {"code": "method_not_enrolled"}


# --------------------------------------------------------------- recovery-codes regenerate


def test_recovery_codes_regenerate_rejects_a_wrong_password() -> None:
    user = _make_user(username="alice")
    client = _authed_client(user)

    response = client.post(_RECOVERY_REGENERATE_URL, {"password": "not-the-password"})
    assert response.status_code == 400


def test_recovery_codes_regenerate_happy_path_returns_plaintext_codes() -> None:
    user = _make_user(username="alice")
    RecoveryCodeFactory(user=user)  # a stale, prior code — must be invalidated
    client = _authed_client(user)

    response = client.post(_RECOVERY_REGENERATE_URL, {"password": _PASSWORD})
    assert response.status_code == 200
    codes = response.json()["codes"]
    assert len(codes) == 10  # TWO_FACTOR.RECOVERY_CODE_COUNT default
    assert RecoveryCode.objects.filter(user=user, used_at__isnull=True).count() == 10


# --------------------------------------------------------------------------- 2fa/otp/request


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
        "TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["email_otp"]},
    }
)
def test_otp_request_happy_path_returns_a_challenge() -> None:
    user = _make_user(username="alice", email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")
    pending_token = TokenService.issue_pending_2fa_token(
        user, primary_method="password", request_meta={"ip": "203.0.113.5"}
    )

    response = _authed_client(user).post(
        # AllowAny — pending-token-scoped, no client credentials needed.
        _OTP_REQUEST_2FA_URL,
        {"pending_token": pending_token, "method": "email_otp"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "challenge_id" in body


def test_otp_request_with_an_invalid_pending_token_returns_401() -> None:
    response = APIClient().post(
        _OTP_REQUEST_2FA_URL, {"pending_token": "not-a-real-token", "method": "email_otp"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["details"] == {"code": "invalid_pending_token"}


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
        "TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]},
    }
)
def test_otp_request_for_an_ineligible_method_returns_401() -> None:
    user = _make_user(username="alice", email="alice@example.com")
    pending_token = TokenService.issue_pending_2fa_token(
        user, primary_method="password", request_meta={"ip": "203.0.113.5"}
    )

    response = APIClient().post(
        _OTP_REQUEST_2FA_URL, {"pending_token": pending_token, "method": "email_otp"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["details"] == {"code": "two_factor_unavailable"}


# ------------------------------------------------------------------------------------ verify


@override_settings(JWT_MULTIAUTH=_TOTP_SETTINGS)
def test_verify_happy_path_returns_tokens_and_sets_the_refresh_cookie() -> None:
    user = _make_user(username="alice")
    client = _authed_client(user)
    secret = _enroll_and_confirm_totp(user, client)

    with freeze_time(_BASE_TIME + _STEP):
        pending_token = TokenService.issue_pending_2fa_token(
            user, primary_method="password", request_meta={"ip": "203.0.113.5"}
        )
        response = APIClient().post(
            _VERIFY_URL,
            {"pending_token": pending_token, "method": "totp", "code": pyotp.TOTP(secret).now()},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["created"] is False
    assert "access" in body
    assert "session_id" in body
    assert "jwt_multiauth_refresh" in response.cookies


@override_settings(
    JWT_MULTIAUTH={
        "TWO_FACTOR": {
            "POLICY": "required",
            "ALLOWED_METHODS": ["totp"],
            "TRUSTED_DEVICE": {"ENABLED": True},
        }
    }
)
def test_verify_with_trust_device_sets_the_trusted_device_cookie() -> None:
    user = _make_user(username="alice")
    client = _authed_client(user)
    secret = _enroll_and_confirm_totp(user, client)

    with freeze_time(_BASE_TIME + _STEP):
        pending_token = TokenService.issue_pending_2fa_token(
            user, primary_method="password", request_meta={"ip": "203.0.113.5"}
        )
        response = APIClient().post(
            _VERIFY_URL,
            {
                "pending_token": pending_token,
                "method": "totp",
                "code": pyotp.TOTP(secret).now(),
                "trust_device": True,
            },
        )

    assert response.status_code == 200
    assert "jwt_multiauth_td" in response.cookies


@override_settings(JWT_MULTIAUTH=_TOTP_SETTINGS)
def test_verify_does_not_set_a_trusted_device_cookie_when_trust_device_is_false() -> None:
    user = _make_user(username="alice")
    client = _authed_client(user)
    secret = _enroll_and_confirm_totp(user, client)

    with freeze_time(_BASE_TIME + _STEP):
        pending_token = TokenService.issue_pending_2fa_token(
            user, primary_method="password", request_meta={"ip": "203.0.113.5"}
        )
        response = APIClient().post(
            _VERIFY_URL,
            {"pending_token": pending_token, "method": "totp", "code": pyotp.TOTP(secret).now()},
        )

    assert response.status_code == 200
    assert "jwt_multiauth_td" not in response.cookies


def test_verify_with_an_invalid_pending_token_returns_401_not_400() -> None:
    response = APIClient().post(
        _VERIFY_URL, {"pending_token": "not-a-real-token", "method": "totp", "code": "000000"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["details"] == {"code": "invalid_pending_token"}


@override_settings(JWT_MULTIAUTH=_TOTP_SETTINGS)
def test_verify_with_a_wrong_code_returns_401_not_400() -> None:
    """docs/CONTRACT.md §5's own row for /2fa/verify/ lists only 200/401 — ChallengeInvalid
    (raised for a wrong TOTP code) maps to 401 here, unlike /otp/verify/'s 400 for the same
    exception class.
    """
    user = _make_user(username="alice")
    client = _authed_client(user)
    _enroll_and_confirm_totp(user, client)

    pending_token = TokenService.issue_pending_2fa_token(
        user, primary_method="password", request_meta={"ip": "203.0.113.5"}
    )
    response = APIClient().post(
        _VERIFY_URL, {"pending_token": pending_token, "method": "totp", "code": "000000"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["details"] == {"code": "otp_challenge_invalid"}


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
        "TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]},
    }
)
def test_verify_rejects_a_method_the_server_does_not_consider_eligible() -> None:
    """The re-derivation enforcement point, proven over real HTTP: email_otp isn't even in
    ALLOWED_METHODS, so a client claiming it is rejected regardless of any code presented.
    """
    user = _make_user(username="alice", email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")
    pending_token = TokenService.issue_pending_2fa_token(
        user, primary_method="password", request_meta={"ip": "203.0.113.5"}
    )

    response = APIClient().post(
        _VERIFY_URL, {"pending_token": pending_token, "method": "email_otp", "code": "000000"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["details"] == {"code": "two_factor_unavailable"}


def test_verify_requires_exactly_one_of_code_or_link_token() -> None:
    response = APIClient().post(_VERIFY_URL, {"pending_token": "irrelevant", "method": "totp"})
    assert response.status_code == 400
