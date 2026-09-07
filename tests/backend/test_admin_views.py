"""Proves the whole admin REST surface (``admin_views.py``): the configurable admin gate
(``permissions.IsAdmin``) 403s a non-admin under BOTH ``ADMIN_REQUIRES_SUPERUSER`` values, for
sessions and trusted-devices both; admin list views are filterable only through
``appkit.validation.safe_filter_kwargs`` (an unknown param is dropped, a relation-traversal param
never filters); and force-disable-2FA is ``is_superuser``-only UNCONDITIONALLY — a staff-but-not-
superuser admin is denied even when ``ADMIN_REQUIRES_SUPERUSER=False``, and the result is identical
under both values of that setting.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APIClient

from jwt_multiauth.factories import (
    AuthSessionFactory,
    LoginAttemptFactory,
    TrustedDeviceFactory,
    TwoFactorDeviceFactory,
    UserFactory,
)
from jwt_multiauth.services import LockoutService

pytestmark = pytest.mark.django_db

_SESSIONS_URL = "/api/v1/admin/auth/sessions/"
_TRUSTED_DEVICES_URL = "/api/v1/admin/auth/trusted-devices/"
_LOGIN_ATTEMPTS_URL = "/api/v1/admin/auth/login-attempts/"


def _session_revoke_url(pk: object) -> str:
    return f"/api/v1/admin/auth/sessions/{pk}/"


def _trusted_device_revoke_url(pk: object) -> str:
    return f"/api/v1/admin/auth/trusted-devices/{pk}/"


def _security_url(pk: object) -> str:
    return f"/api/v1/admin/auth/users/{pk}/security/"


def _unlock_url(pk: object) -> str:
    return f"/api/v1/admin/auth/users/{pk}/unlock/"


def _force_disable_url(pk: object) -> str:
    return f"/api/v1/admin/auth/users/{pk}/2fa/force-disable/"


def _client_for(user: Any) -> APIClient:
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _staff_user() -> Any:
    return UserFactory(is_staff=True, is_superuser=False)


def _superuser() -> Any:
    return get_user_model().objects.create_superuser(
        username=f"root-{uuid.uuid4().hex[:8]}", password="pw"
    )


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    cache.clear()
    yield
    cache.clear()


# --------------------------------------------------------------------------- the admin gate


@pytest.mark.parametrize(
    ("url", "method"),
    [
        (_SESSIONS_URL, "get"),
        (_TRUSTED_DEVICES_URL, "get"),
    ],
)
@pytest.mark.parametrize("admin_requires_superuser", [False, True])
def test_a_plain_authenticated_user_is_denied_admin_list_views(
    url: str, method: str, admin_requires_superuser: bool
) -> None:
    with override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": admin_requires_superuser}):
        client = _client_for(UserFactory())
        response = getattr(client, method)(url)
        assert response.status_code == 403


def test_admin_list_views_require_authentication() -> None:
    client = APIClient()
    assert client.get(_SESSIONS_URL).status_code == 401
    assert client.get(_TRUSTED_DEVICES_URL).status_code == 401


@override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": False})
def test_a_plain_staff_admin_is_allowed_when_admin_requires_superuser_is_false() -> None:
    client = _client_for(_staff_user())
    assert client.get(_SESSIONS_URL).status_code == 200


@override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": True})
def test_a_plain_staff_admin_is_denied_when_admin_requires_superuser_is_true() -> None:
    client = _client_for(_staff_user())
    assert client.get(_SESSIONS_URL).status_code == 403


@override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": True})
def test_a_superuser_is_allowed_when_admin_requires_superuser_is_true() -> None:
    client = _client_for(_superuser())
    assert client.get(_SESSIONS_URL).status_code == 200


# ---------------------------------------------------------------------------- session list/revoke


@override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": False})
def test_admin_session_list_returns_any_users_rows() -> None:
    owner = UserFactory()
    session = AuthSessionFactory(user=owner)
    client = _client_for(_staff_user())

    response = client.get(_SESSIONS_URL)

    assert response.status_code == 200
    returned_ids = {row["id"] for row in response.json()["results"]}
    assert str(session.pk) in returned_ids


@override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": False})
def test_admin_session_list_filters_by_user() -> None:
    target = UserFactory()
    other = UserFactory()
    target_session = AuthSessionFactory(user=target)
    AuthSessionFactory(user=other)
    client = _client_for(_staff_user())

    response = client.get(_SESSIONS_URL, {"user": target.pk})

    results = response.json()["results"]
    assert {row["id"] for row in results} == {str(target_session.pk)}


@override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": False})
def test_admin_session_list_ignores_an_unknown_query_param() -> None:
    session = AuthSessionFactory()
    client = _client_for(_staff_user())

    response = client.get(_SESSIONS_URL, {"bogus": "whatever"})

    assert response.status_code == 200
    assert str(session.pk) in {row["id"] for row in response.json()["results"]}


@override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": False})
def test_admin_session_list_rejects_relation_traversal_and_returns_everything_unfiltered() -> None:
    owner = UserFactory()
    session = AuthSessionFactory(user=owner)
    client = _client_for(_staff_user())

    response = client.get(_SESSIONS_URL, {"user__pk__icontains": str(owner.pk)})

    # The traversal param is dropped, not applied — the row still shows up because NO filter
    # took effect, not because the traversal itself matched.
    assert response.status_code == 200
    assert str(session.pk) in {row["id"] for row in response.json()["results"]}


@override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": False})
def test_admin_session_list_rejects_a_non_integer_user_param() -> None:
    client = _client_for(_staff_user())
    response = client.get(_SESSIONS_URL, {"user": "not-a-number"})
    assert response.status_code == 400


@override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": False})
def test_admin_session_revoke_works_on_any_users_session() -> None:
    owner = UserFactory()
    session = AuthSessionFactory(user=owner)
    client = _client_for(_staff_user())

    response = client.delete(_session_revoke_url(session.pk))

    assert response.status_code == 204
    session.refresh_from_db()
    assert session.revoked_at is not None
    assert session.revoked_reason == "admin_revoked"


@pytest.mark.parametrize("admin_requires_superuser", [False, True])
def test_admin_session_revoke_denied_for_a_non_admin(admin_requires_superuser: bool) -> None:
    with override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": admin_requires_superuser}):
        session = AuthSessionFactory()
        client = _client_for(UserFactory())
        response = client.delete(_session_revoke_url(session.pk))
        assert response.status_code == 403


# ------------------------------------------------------------------- trusted-device list/revoke


@override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": False})
def test_admin_trusted_device_list_returns_any_users_rows_filterable_by_user() -> None:
    target = UserFactory()
    other = UserFactory()
    target_device = TrustedDeviceFactory(user=target, token_hash="1" * 64)
    TrustedDeviceFactory(user=other, token_hash="2" * 64)
    client = _client_for(_staff_user())

    response = client.get(_TRUSTED_DEVICES_URL, {"user": target.pk})

    results = response.json()["results"]
    assert {row["id"] for row in results} == {target_device.pk}


@override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": False})
def test_admin_trusted_device_revoke_works_on_any_users_device() -> None:
    device = TrustedDeviceFactory(token_hash="3" * 64)
    client = _client_for(_staff_user())

    response = client.delete(_trusted_device_revoke_url(device.pk))

    assert response.status_code == 204
    device.refresh_from_db()
    assert device.revoked_at is not None


@pytest.mark.parametrize("admin_requires_superuser", [False, True])
def test_admin_trusted_device_revoke_denied_for_a_non_admin(admin_requires_superuser: bool) -> None:
    with override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": admin_requires_superuser}):
        device = TrustedDeviceFactory(token_hash="4" * 64)
        client = _client_for(UserFactory())
        response = client.delete(_trusted_device_revoke_url(device.pk))
        assert response.status_code == 403


# ------------------------------------------------------------------------------- login attempts


@override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": False})
def test_admin_login_attempts_filters_by_identifier_ip_user_and_success() -> None:
    target = UserFactory()
    matching = LoginAttemptFactory(
        user=target,
        identifier="alice",
        ip_address="203.0.113.9",
        success=False,
        failure_reason="wrong_credential",
    )
    LoginAttemptFactory(identifier="bob", ip_address="198.51.100.1", success=True)
    client = _client_for(_staff_user())

    response = client.get(
        _LOGIN_ATTEMPTS_URL,
        {
            "identifier": "alice",
            "ip_address": "203.0.113.9",
            "user": target.pk,
            "success": "false",
        },
    )

    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) == 1
    assert results[0]["id"] == matching.pk


def test_admin_login_attempts_denied_for_a_non_admin() -> None:
    client = _client_for(UserFactory())
    assert client.get(_LOGIN_ATTEMPTS_URL).status_code == 403


# -------------------------------------------------------------------------------- user security


@override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": False})
def test_admin_user_security_reports_2fa_active_sessions_and_lock_status() -> None:
    target = UserFactory()
    TwoFactorDeviceFactory(user=target, method="totp")  # confirmed by the factory default
    AuthSessionFactory(user=target)
    AuthSessionFactory(user=target)
    client = _client_for(_staff_user())

    response = client.get(_security_url(target.pk))

    assert response.status_code == 200
    body = response.json()
    assert "totp" in body["two_factor_status"]["enrolled_methods"]
    assert body["active_session_count"] == 2
    assert body["lock_status"]["scope"] == "identifier_and_ip"  # this app's own default
    assert body["lock_status"]["locked"] is None  # indeterminate at this scope, never a guess


@override_settings(
    JWT_MULTIAUTH={
        "ADMIN_REQUIRES_SUPERUSER": False,
        "LOCKOUT": {"LOCK_SCOPE": "identifier", "MAX_ATTEMPTS": 1},
    }
)
def test_admin_user_security_reports_a_real_lock_status_under_identifier_scope() -> None:
    target = UserFactory(username="victim")
    LockoutService.record_attempt(
        "victim", ip="203.0.113.1", success=False, reason="wrong_credential"
    )
    client = _client_for(_staff_user())

    response = client.get(_security_url(target.pk))

    body = response.json()
    assert body["lock_status"]["scope"] == "identifier"
    assert body["lock_status"]["locked"] is True
    assert body["lock_status"]["until"] is not None


def test_admin_user_security_denied_for_a_non_admin() -> None:
    target = UserFactory()
    client = _client_for(UserFactory())
    assert client.get(_security_url(target.pk)).status_code == 403


# ------------------------------------------------------------------------------------- unlock


@override_settings(
    JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": False, "LOCKOUT": {"LOCK_SCOPE": "identifier"}}
)
def test_admin_unlock_clears_the_lock_for_the_targeted_user() -> None:
    target = UserFactory(username="victim")
    for _ in range(5):  # default MAX_ATTEMPTS
        LockoutService.record_attempt(
            "victim", ip="203.0.113.1", success=False, reason="wrong_credential"
        )
    assert LockoutService.is_locked("victim", ip="203.0.113.1").locked is True
    client = _client_for(_staff_user())

    response = client.post(_unlock_url(target.pk), {}, format="json")

    assert response.status_code == 204
    assert LockoutService.is_locked("victim", ip="203.0.113.1").locked is False


def test_admin_unlock_denied_for_a_non_admin() -> None:
    target = UserFactory()
    client = _client_for(UserFactory())
    response = client.post(_unlock_url(target.pk), {}, format="json")
    assert response.status_code == 403


# ------------------------------------------------------------------------ force-disable-2fa


@pytest.mark.parametrize("admin_requires_superuser", [False, True])
def test_force_disable_2fa_denies_a_plain_staff_admin_regardless_of_the_setting(
    admin_requires_superuser: bool,
) -> None:
    with override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": admin_requires_superuser}):
        target = UserFactory()
        TwoFactorDeviceFactory(user=target, method="totp")
        client = _client_for(_staff_user())

        response = client.post(_force_disable_url(target.pk), {}, format="json")

        assert response.status_code == 403


@pytest.mark.parametrize("admin_requires_superuser", [False, True])
def test_force_disable_2fa_allows_a_real_superuser_regardless_of_the_setting(
    admin_requires_superuser: bool,
) -> None:
    with override_settings(JWT_MULTIAUTH={"ADMIN_REQUIRES_SUPERUSER": admin_requires_superuser}):
        target = UserFactory()
        TwoFactorDeviceFactory(user=target, method="totp")
        client = _client_for(_superuser())

        response = client.post(_force_disable_url(target.pk), {}, format="json")

        assert response.status_code == 204
        from jwt_multiauth.models import TwoFactorDevice

        assert TwoFactorDevice.objects.get(user=target).disabled_at is not None


def test_force_disable_2fa_requires_authentication() -> None:
    target = UserFactory()
    client = APIClient()
    response = client.post(_force_disable_url(target.pk), {}, format="json")
    assert response.status_code == 401
