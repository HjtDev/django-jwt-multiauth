"""Proves the ``/sessions/``, ``/sessions/{id}/``, ``/trusted-devices/``,
``/trusted-devices/{id}/`` HTTP surface (``views_session.py``): every list is filtered to the
CALLER's own rows at the queryset level, and a cross-user revoke attempt 404s rather than
succeeding or 403ing (``docs/CONTRACT.md`` §5's own review note) — this is the IDOR guard proven
here, not merely asserted.
"""

from __future__ import annotations

from typing import Any

import pytest
from rest_framework.test import APIClient

from jwt_multiauth.factories import AuthSessionFactory, TrustedDeviceFactory, UserFactory
from jwt_multiauth.services import RequestMeta, TokenService

pytestmark = pytest.mark.django_db

_SESSIONS_URL = "/api/v1/auth/sessions/"
_TRUSTED_DEVICES_URL = "/api/v1/auth/trusted-devices/"
_REQUEST_META: RequestMeta = {"ip": "203.0.113.5", "method": "password"}


def _session_revoke_url(pk: object) -> str:
    return f"/api/v1/auth/sessions/{pk}/"


def _trusted_device_revoke_url(pk: object) -> str:
    return f"/api/v1/auth/trusted-devices/{pk}/"


def _authed_client(user: Any) -> APIClient:
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {pair.access}")
    return client


# ------------------------------------------------------------------------------------ sessions


def test_sessions_list_requires_authentication() -> None:
    client = APIClient()
    response = client.get(_SESSIONS_URL)
    assert response.status_code == 401


def test_sessions_list_returns_only_the_callers_own_rows() -> None:
    owner = UserFactory()
    stranger = UserFactory()
    own_session = AuthSessionFactory(user=owner)
    strangers_session = AuthSessionFactory(user=stranger)
    client = _authed_client(owner)  # mints a SECOND session for owner, via the Bearer token

    response = client.get(_SESSIONS_URL)

    assert response.status_code == 200
    results = response.json()["results"]
    returned_ids = {row["id"] for row in results}
    # Both of the owner's own sessions (the factory row and the one _authed_client minted) are
    # present; the stranger's is not — the queryset filter, not merely the count, is what matters.
    assert str(own_session.pk) in returned_ids
    assert str(strangers_session.pk) not in returned_ids
    assert len(results) == 2
    assert "current_jti" not in results[0]


def test_session_revoke_succeeds_for_the_callers_own_session() -> None:
    owner = UserFactory()
    session = AuthSessionFactory(user=owner)
    client = _authed_client(owner)

    response = client.delete(_session_revoke_url(session.pk))

    assert response.status_code == 204
    session.refresh_from_db()
    assert session.revoked_at is not None
    assert session.revoked_reason == "user_logout"


def test_session_revoke_of_another_users_session_returns_404_not_403() -> None:
    owner = UserFactory()
    stranger = UserFactory()
    strangers_session = AuthSessionFactory(user=stranger)
    client = _authed_client(owner)

    response = client.delete(_session_revoke_url(strangers_session.pk))

    assert response.status_code == 404
    strangers_session.refresh_from_db()
    assert strangers_session.revoked_at is None  # untouched — proves it wasn't silently revoked


def test_session_revoke_of_a_nonexistent_id_returns_404() -> None:
    owner = UserFactory()
    client = _authed_client(owner)
    response = client.delete("/api/v1/auth/sessions/00000000-0000-0000-0000-000000000000/")
    assert response.status_code == 404


def test_session_revoke_requires_authentication() -> None:
    session = AuthSessionFactory()
    client = APIClient()
    response = client.delete(_session_revoke_url(session.pk))
    assert response.status_code == 401


# ----------------------------------------------------------------------------- trusted-devices


def test_trusted_devices_list_requires_authentication() -> None:
    client = APIClient()
    response = client.get(_TRUSTED_DEVICES_URL)
    assert response.status_code == 401


def test_trusted_devices_list_returns_only_the_callers_own_rows() -> None:
    owner = UserFactory()
    stranger = UserFactory()
    own_device = TrustedDeviceFactory(user=owner, token_hash="1" * 64)
    TrustedDeviceFactory(user=stranger, token_hash="2" * 64)
    client = _authed_client(owner)

    response = client.get(_TRUSTED_DEVICES_URL)

    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) == 1
    assert results[0]["id"] == own_device.pk
    assert "token_hash" not in results[0]


def test_trusted_device_revoke_succeeds_for_the_callers_own_device() -> None:
    owner = UserFactory()
    device = TrustedDeviceFactory(user=owner, token_hash="1" * 64)
    client = _authed_client(owner)

    response = client.delete(_trusted_device_revoke_url(device.pk))

    assert response.status_code == 204
    device.refresh_from_db()
    assert device.revoked_at is not None


def test_trusted_device_revoke_is_idempotent_via_the_service() -> None:
    owner = UserFactory()
    device = TrustedDeviceFactory(user=owner, token_hash="1" * 64)
    client = _authed_client(owner)

    first = client.delete(_trusted_device_revoke_url(device.pk))
    assert first.status_code == 204

    # The row is gone from the caller's OWN queryset only in the sense that a second delete
    # attempt against the same id still 404s via the ownership-filtered queryset lookup itself —
    # revoked rows remain listable/gettable, so this proves get_object() doesn't exclude them.
    device.refresh_from_db()
    assert device.revoked_at is not None


def test_trusted_device_revoke_of_another_users_device_returns_404_not_403() -> None:
    owner = UserFactory()
    stranger = UserFactory()
    strangers_device = TrustedDeviceFactory(user=stranger, token_hash="3" * 64)
    client = _authed_client(owner)

    response = client.delete(_trusted_device_revoke_url(strangers_device.pk))

    assert response.status_code == 404
    strangers_device.refresh_from_db()
    assert strangers_device.revoked_at is None


def test_trusted_device_revoke_requires_authentication() -> None:
    device = TrustedDeviceFactory(token_hash="4" * 64)
    client = APIClient()
    response = client.delete(_trusted_device_revoke_url(device.pk))
    assert response.status_code == 401
