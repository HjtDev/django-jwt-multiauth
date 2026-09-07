"""The dynamic-user leg for Phase 8: contact verification and the admin unlock/security views,
round-tripped over real HTTP against ``phone_user_app.User``'s genuine unique ``phone`` field —
proving ``VerificationService``/``LockoutService``/``TwoFactorService`` all resolve
``USER_FIELDS["PHONE_FIELD"]`` correctly against a real non-default user model, zero package-level
code changes needed.

Guarded on the *resolved* ``settings.AUTH_USER_MODEL``, same as every other ``*_dynamic_user.py``
leg. Run with:

    DJANGO_SETTINGS_MODULE=tests.backend.settings_dynamic_user \\
      uv run pytest -k dynamic_user --no-cov
"""

from __future__ import annotations

import pytest
from django.conf import settings
from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APIClient

from jwt_multiauth.factories import UserFactory
from jwt_multiauth.services import LockoutService
from jwt_multiauth.signals import phone_otp_requested
from tests.backend.conftest import captured

pytestmark = [
    pytest.mark.django_db,
    pytest.mark.requires_extra,
    pytest.mark.skipif(
        settings.AUTH_USER_MODEL != "phone_user_app.User",
        reason="only meaningful under tests.backend.settings_dynamic_user",
    ),
]

_VERIFY_REQUEST_URL = "/api/v1/auth/account/verify-contact/request/"
_VERIFY_CONFIRM_URL = "/api/v1/auth/account/verify-contact/confirm/"
_ADMIN_SECURITY_URL = "/api/v1/admin/auth/users/{pk}/security/"
_ADMIN_UNLOCK_URL = "/api/v1/admin/auth/users/{pk}/unlock/"

_PHONE_SETTINGS = {"USER_FIELDS": {"PHONE_FIELD": "phone"}}


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    cache.clear()
    yield
    cache.clear()


@override_settings(JWT_MULTIAUTH=_PHONE_SETTINGS)
def test_verify_contact_phone_round_trip_over_http(api_client: APIClient) -> None:
    user = UserFactory(username="alice", phone="+15550001234")
    api_client.force_authenticate(user=user)

    with captured(phone_otp_requested) as received:
        request_response = api_client.post(_VERIFY_REQUEST_URL, {"field": "phone"}, format="json")
    assert request_response.status_code == 200
    assert received[0]["destination"] == "+15550001234"
    challenge_id = request_response.json()["challenge_id"]
    code = received[0]["code"]

    confirm_response = api_client.post(
        _VERIFY_CONFIRM_URL, {"challenge_id": challenge_id, "code": code}, format="json"
    )
    assert confirm_response.status_code == 204

    from jwt_multiauth.models import VerifiedContact

    assert VerifiedContact.objects.filter(user=user, field="phone", value="+15550001234").exists()


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {"PHONE_FIELD": "phone", "IDENTIFIER_FIELDS": ["username", "phone"]},
        "LOCKOUT": {"LOCK_SCOPE": "identifier", "MAX_ATTEMPTS": 1},
    }
)
def test_admin_unlock_clears_a_lock_recorded_under_the_users_phone(
    api_client: APIClient,
) -> None:
    user = UserFactory(username="alice", phone="+15550009999")
    admin = UserFactory(username="root", is_staff=True, is_superuser=True)
    LockoutService.record_attempt(
        "+15550009999", ip="203.0.113.1", success=False, reason="wrong_credential"
    )
    assert LockoutService.is_locked("+15550009999", ip="203.0.113.1").locked is True
    api_client.force_authenticate(user=admin)

    response = api_client.post(_ADMIN_UNLOCK_URL.format(pk=user.pk), {}, format="json")

    assert response.status_code == 204
    assert LockoutService.is_locked("+15550009999", ip="203.0.113.1").locked is False


@override_settings(JWT_MULTIAUTH=_PHONE_SETTINGS)
def test_admin_security_view_resolves_against_the_phone_field_user(
    api_client: APIClient,
) -> None:
    user = UserFactory(username="alice", phone="+15550001234")
    admin = UserFactory(username="root", is_staff=True, is_superuser=True)
    api_client.force_authenticate(user=admin)

    response = api_client.get(_ADMIN_SECURITY_URL.format(pk=user.pk))

    assert response.status_code == 200
    body = response.json()
    assert body["two_factor_status"]["enrolled_methods"] == []
    assert body["active_session_count"] == 0
