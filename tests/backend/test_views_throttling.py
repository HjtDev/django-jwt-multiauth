"""Proves every Phase 6 endpoint actually enforces its declared ``throttle_scope`` at the HTTP
layer — one test per scope, per ``docs/CLAUDE-CODE-GUIDE-APP-JWT-MULTIAUTH.md``'s Phase 6 prompt.

``django.test.override_settings(REST_FRAMEWORK=...)`` does NOT work for this: DRF's
``rest_framework.throttling.SimpleRateThrottle.THROTTLE_RATES`` snapshots
``api_settings.DEFAULT_THROTTLE_RATES`` once, at class-body-evaluation time (import time) —
DRF's own ``setting_changed`` receiver (``rest_framework.settings.reload_api_settings``) only
clears ``api_settings``' cached attributes, it never re-assigns
``SimpleRateThrottle.THROTTLE_RATES`` itself, so an ``override_settings`` block changes what
``api_settings.DEFAULT_THROTTLE_RATES`` returns without changing what any already-imported
throttle class actually reads (verified against a real request that ignored the override,
not assumed from DRF's source). Directly monkeypatching
``rest_framework.throttling.ScopedRateThrottle.THROTTLE_RATES`` is the one technique that
actually takes effect.
"""

from __future__ import annotations

import pytest
from django.core.cache import cache
from rest_framework.test import APIClient
from rest_framework.throttling import ScopedRateThrottle

from jwt_multiauth import throttling
from jwt_multiauth.factories import UserFactory

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    cache.clear()
    yield
    cache.clear()


def _throttle_to_one_per_minute(monkeypatch: pytest.MonkeyPatch, scope: str) -> None:
    monkeypatch.setattr(ScopedRateThrottle, "THROTTLE_RATES", {scope: "1/min"})


def test_login_throttle_scope(api_client: APIClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _throttle_to_one_per_minute(monkeypatch, throttling.LOGIN)
    payload = {"identifier": "nobody", "password": "whatever"}
    first = api_client.post("/api/v1/auth/login/", payload, format="json")
    second = api_client.post("/api/v1/auth/login/", payload, format="json")
    assert first.status_code != 429
    assert second.status_code == 429


def test_password_change_throttle_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    _throttle_to_one_per_minute(monkeypatch, throttling.PASSWORD_CHANGE)
    client = APIClient()
    client.force_authenticate(user=UserFactory())
    payload = {"old_password": "whatever", "new_password": "whatever-else-9"}
    first = client.post("/api/v1/auth/password/change/", payload, format="json")
    second = client.post("/api/v1/auth/password/change/", payload, format="json")
    assert first.status_code != 429
    assert second.status_code == 429


def test_password_reset_request_throttle_scope(
    api_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _throttle_to_one_per_minute(monkeypatch, throttling.PASSWORD_RESET_REQUEST)
    payload = {"identifier": "nobody"}
    first = api_client.post("/api/v1/auth/password/reset/request/", payload, format="json")
    second = api_client.post("/api/v1/auth/password/reset/request/", payload, format="json")
    assert first.status_code != 429
    assert second.status_code == 429


def test_password_reset_confirm_throttle_scope(
    api_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _throttle_to_one_per_minute(monkeypatch, throttling.PASSWORD_RESET_CONFIRM)
    payload = {
        "challenge_id": "00000000-0000-0000-0000-000000000000",
        "code": "000000",
        "new_password": "whatever-else-9",
    }
    first = api_client.post("/api/v1/auth/password/reset/confirm/", payload, format="json")
    second = api_client.post("/api/v1/auth/password/reset/confirm/", payload, format="json")
    assert first.status_code != 429
    assert second.status_code == 429


def test_otp_request_throttle_scope(api_client: APIClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _throttle_to_one_per_minute(monkeypatch, throttling.OTP_REQUEST)
    payload = {"identifier": "nobody@example.com", "channel": "email"}
    first = api_client.post("/api/v1/auth/otp/request/", payload, format="json")
    second = api_client.post("/api/v1/auth/otp/request/", payload, format="json")
    assert first.status_code != 429
    assert second.status_code == 429


def test_otp_verify_throttle_scope(api_client: APIClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _throttle_to_one_per_minute(monkeypatch, throttling.OTP_VERIFY)
    payload = {"challenge_id": "00000000-0000-0000-0000-000000000000", "code": "000000"}
    first = api_client.post("/api/v1/auth/otp/verify/", payload, format="json")
    second = api_client.post("/api/v1/auth/otp/verify/", payload, format="json")
    assert first.status_code != 429
    assert second.status_code == 429


def test_otp_resend_throttle_scope(api_client: APIClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _throttle_to_one_per_minute(monkeypatch, throttling.OTP_RESEND)
    payload = {"challenge_id": "00000000-0000-0000-0000-000000000000"}
    first = api_client.post("/api/v1/auth/otp/resend/", payload, format="json")
    second = api_client.post("/api/v1/auth/otp/resend/", payload, format="json")
    assert first.status_code != 429
    assert second.status_code == 429


def test_methods_throttle_scope(api_client: APIClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _throttle_to_one_per_minute(monkeypatch, throttling.METHODS)
    first = api_client.get("/api/v1/auth/methods/")
    second = api_client.get("/api/v1/auth/methods/")
    assert first.status_code != 429
    assert second.status_code == 429
