"""Proves ``GET /methods/``: returns the deployment's enabled auth methods and 2FA policy,
nothing user-specific, unauthenticated, and cached (``appkit.mixins.CachedListMixin``).
"""

from __future__ import annotations

import pytest
from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APIClient

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    cache.clear()
    yield
    cache.clear()


def test_methods_returns_the_default_configuration(api_client: APIClient) -> None:
    response = api_client.get("/api/v1/auth/methods/")
    assert response.status_code == 200
    assert response.json() == {
        "allowed_auth_methods": ["password"],
        "two_factor": {"policy": "off", "allowed_methods": ["totp"]},
    }


@override_settings(
    JWT_MULTIAUTH={
        "ALLOWED_AUTH_METHODS": ["password", "email_otp"],
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
        "TWO_FACTOR": {"POLICY": "opt_in", "ALLOWED_METHODS": ["totp", "email_otp"]},
    }
)
def test_methods_reflects_a_non_default_configuration(api_client: APIClient) -> None:
    response = api_client.get("/api/v1/auth/methods/")
    assert response.status_code == 200
    assert response.json() == {
        "allowed_auth_methods": ["password", "email_otp"],
        "two_factor": {"policy": "opt_in", "allowed_methods": ["totp", "email_otp"]},
    }


def test_methods_is_unauthenticated(api_client: APIClient) -> None:
    # No credentials at all — AllowAny, no authentication_classes.
    response = api_client.get("/api/v1/auth/methods/")
    assert response.status_code == 200


def test_methods_response_is_cached(api_client: APIClient) -> None:
    first = api_client.get("/api/v1/auth/methods/")
    with override_settings(JWT_MULTIAUTH={"ALLOWED_AUTH_METHODS": ["password", "email_otp"]}):
        second = api_client.get("/api/v1/auth/methods/")
    # The cached body from the first call is served again, proving CachedListMixin is wired up —
    # a live (uncached) call under the override would return a different allowed_auth_methods.
    assert second.json() == first.json()
