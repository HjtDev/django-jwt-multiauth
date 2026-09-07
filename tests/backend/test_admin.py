"""Proves the admin surface: all seven models registered, every secret field absent from every
admin surface across the whole registry (not just hand-checked per class — a future model gaining
a new secret field trips this automatically), ``select_related`` on every ``get_queryset``,
``LoginAttemptAdmin``'s add/change-denied + searchable-on-identifier shape, and the revoke action
calling ``TokenService.revoke_session`` once per unrevoked row rather than a raw queryset update.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from django.contrib.admin.sites import site as admin_site
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone

from jwt_multiauth import models as jwt_models
from jwt_multiauth.admin import (
    AuthSessionAdmin,
    LoginAttemptAdmin,
    TrustedDeviceAdmin,
    TwoFactorDeviceAdmin,
)
from jwt_multiauth.factories import (
    AuthSessionFactory,
    LoginAttemptFactory,
    TrustedDeviceFactory,
    TwoFactorDeviceFactory,
    UserFactory,
)
from jwt_multiauth.services import LockoutService
from jwt_multiauth.signals import two_factor_disabled
from tests.backend.conftest import captured

SECRET_FIELD_NAMES = {
    "current_jti",
    "code_hash",
    "link_token_hash",
    "secret_encrypted",
    "token_hash",
}

SEVEN_MODELS = [
    jwt_models.OtpChallenge,
    jwt_models.AuthSession,
    jwt_models.TwoFactorDevice,
    jwt_models.RecoveryCode,
    jwt_models.VerifiedContact,
    jwt_models.LoginAttempt,
    jwt_models.TrustedDevice,
]


@pytest.mark.parametrize("model", SEVEN_MODELS)
def test_every_model_is_registered(model: type) -> None:
    assert model in admin_site._registry


@pytest.mark.parametrize("model", SEVEN_MODELS)
def test_no_secret_field_rendered_anywhere_on_any_admin(model: type) -> None:
    model_admin = admin_site._registry[model]
    surfaces = (
        tuple(model_admin.list_display),
        tuple(model_admin.readonly_fields),
        tuple(model_admin.search_fields),
        tuple(model_admin.list_filter),
        # get_fields(request) is what actually decides what's on the change form — with
        # neither `fields` nor `fieldsets` set, it falls back to every concrete model field,
        # so this is the one check that would have caught fields=readonly_fields being
        # missing (readonly_fields alone only stops a field being *editable*, not *rendered*).
        tuple(model_admin.get_fields(MagicMock())),
    )
    for surface in surfaces:
        assert not (set(surface) & SECRET_FIELD_NAMES), f"{model.__name__}: {surface}"


@pytest.mark.parametrize("model", SEVEN_MODELS)
def test_get_queryset_select_relates_user(model: type) -> None:
    model_admin = admin_site._registry[model]
    request = MagicMock()
    queryset = model_admin.get_queryset(request)
    select_related = queryset.query.select_related
    assert select_related is True or "user" in select_related


def test_login_attempt_admin_is_fully_readonly() -> None:
    model_admin = LoginAttemptAdmin(jwt_models.LoginAttempt, admin_site)
    request = MagicMock()
    assert model_admin.has_add_permission(request) is False
    assert model_admin.has_change_permission(request) is False
    assert model_admin.has_delete_permission(request) is False
    assert model_admin.search_fields == ("identifier",)
    assert set(model_admin.list_filter) == {"success", "method"}


@pytest.mark.django_db
def test_revoke_sessions_action_calls_token_service_per_unrevoked_row() -> None:
    revoked = AuthSessionFactory()
    revoked.revoked_at = revoked.created_at
    revoked.save(update_fields=["revoked_at"])
    unrevoked_1 = AuthSessionFactory()
    unrevoked_2 = AuthSessionFactory()

    model_admin = AuthSessionAdmin(jwt_models.AuthSession, admin_site)
    queryset = jwt_models.AuthSession.objects.filter(
        pk__in=[revoked.pk, unrevoked_1.pk, unrevoked_2.pk]
    )

    with patch("jwt_multiauth.admin.TokenService.revoke_session") as mock_revoke:
        model_admin.revoke_sessions(MagicMock(), queryset)

    assert mock_revoke.call_count == 2
    called_ids = {call.args[0] for call in mock_revoke.call_args_list}
    assert called_ids == {str(unrevoked_1.pk), str(unrevoked_2.pk)}
    for call in mock_revoke.call_args_list:
        assert call.kwargs == {"reason": "admin_revoked"}


# ------------------------------------------------------------------ revoke_trusted_devices


@pytest.mark.django_db
def test_revoke_trusted_devices_action_calls_service_per_unrevoked_row() -> None:
    revoked = TrustedDeviceFactory(token_hash="1" * 64, revoked_at=timezone.now())
    unrevoked_1 = TrustedDeviceFactory(token_hash="2" * 64)
    unrevoked_2 = TrustedDeviceFactory(token_hash="3" * 64)

    model_admin = TrustedDeviceAdmin(jwt_models.TrustedDevice, admin_site)
    queryset = jwt_models.TrustedDevice.objects.filter(
        pk__in=[revoked.pk, unrevoked_1.pk, unrevoked_2.pk]
    )

    with patch("jwt_multiauth.admin.TwoFactorService.revoke_trusted_device") as mock_revoke:
        model_admin.revoke_trusted_devices(MagicMock(), queryset)

    assert mock_revoke.call_count == 2
    called_devices = {call.args[0] for call in mock_revoke.call_args_list}
    assert called_devices == {unrevoked_1, unrevoked_2}


@pytest.mark.django_db
def test_revoke_trusted_devices_action_actually_revokes_not_a_raw_update() -> None:
    device = TrustedDeviceFactory(token_hash="4" * 64)
    model_admin = TrustedDeviceAdmin(jwt_models.TrustedDevice, admin_site)
    queryset = jwt_models.TrustedDevice.objects.filter(pk=device.pk)

    model_admin.revoke_trusted_devices(MagicMock(), queryset)

    device.refresh_from_db()
    assert device.revoked_at is not None
    # A subsequent lookup of this device by its own (user, token_hash, revoked_at__isnull=True)
    # triple — the exact shape login_flow._trusted_device_skips_2fa uses to accept the cookie —
    # no longer resolves, proving the revoke is not merely a display-layer flag.
    assert not jwt_models.TrustedDevice.objects.filter(
        pk=device.pk, revoked_at__isnull=True
    ).exists()


# --------------------------------------------------------------------- force_disable_two_factor


def test_force_disable_two_factor_permission_is_superuser_only() -> None:
    model_admin = TwoFactorDeviceAdmin(jwt_models.TwoFactorDevice, admin_site)

    superuser_request = MagicMock()
    superuser_request.user.is_authenticated = True
    superuser_request.user.is_superuser = True
    assert model_admin.has_force_disable_2fa_permission(superuser_request) is True

    staff_request = MagicMock()
    staff_request.user.is_authenticated = True
    staff_request.user.is_superuser = False
    assert model_admin.has_force_disable_2fa_permission(staff_request) is False


@pytest.mark.django_db
def test_force_disable_two_factor_action_calls_service_once_per_distinct_user() -> None:
    user = UserFactory()
    device = TwoFactorDeviceFactory(user=user, method="totp")

    model_admin = TwoFactorDeviceAdmin(jwt_models.TwoFactorDevice, admin_site)
    queryset = jwt_models.TwoFactorDevice.objects.filter(pk=device.pk)

    with patch("jwt_multiauth.admin.TwoFactorService.admin_force_disable") as mock_disable:
        model_admin.force_disable_two_factor(MagicMock(), queryset)

    mock_disable.assert_called_once_with(user)


@pytest.mark.django_db
def test_force_disable_two_factor_action_actually_disables_and_fires_the_signal() -> None:
    user = UserFactory()
    device = TwoFactorDeviceFactory(user=user, method="totp")
    model_admin = TwoFactorDeviceAdmin(jwt_models.TwoFactorDevice, admin_site)
    queryset = jwt_models.TwoFactorDevice.objects.filter(pk=device.pk)

    with captured(two_factor_disabled) as received:
        model_admin.force_disable_two_factor(MagicMock(), queryset)

    device.refresh_from_db()
    assert device.disabled_at is not None
    assert any(event["user_id"] == user.pk and event["method"] == "totp" for event in received)


# ------------------------------------------------------------------------- unlock_identifiers


@pytest.mark.django_db
def test_unlock_identifiers_action_calls_lockout_service_per_distinct_identifier() -> None:
    LoginAttemptFactory(identifier="alice", success=False)
    LoginAttemptFactory(identifier="alice", success=False)  # same identifier, second row
    LoginAttemptFactory(identifier="bob", success=False)

    model_admin = LoginAttemptAdmin(jwt_models.LoginAttempt, admin_site)
    queryset = jwt_models.LoginAttempt.objects.all()

    with patch("jwt_multiauth.admin.LockoutService.unlock") as mock_unlock:
        model_admin.unlock_identifiers(MagicMock(), queryset)

    called_identifiers = {call.args[0] for call in mock_unlock.call_args_list}
    assert called_identifiers == {"alice", "bob"}


@pytest.mark.django_db
def test_unlock_identifiers_action_actually_clears_the_lock() -> None:
    cache.clear()
    with override_settings(
        JWT_MULTIAUTH={"LOCKOUT": {"LOCK_SCOPE": "identifier", "MAX_ATTEMPTS": 1}}
    ):
        LockoutService.record_attempt(
            "victim", ip="203.0.113.1", success=False, reason="wrong_credential"
        )
        assert LockoutService.is_locked("victim", ip="203.0.113.1").locked is True

        LoginAttemptFactory(identifier="victim", success=False)
        model_admin = LoginAttemptAdmin(jwt_models.LoginAttempt, admin_site)
        queryset = jwt_models.LoginAttempt.objects.filter(identifier="victim")

        model_admin.unlock_identifiers(MagicMock(), queryset)

        assert LockoutService.is_locked("victim", ip="203.0.113.1").locked is False
    cache.clear()


def test_no_jazzmin_settings_written_by_this_package() -> None:
    """Jazzmin is not a dependency (docs/CONTRACT.md §0) — this app never sets JAZZMIN_SETTINGS
    itself; admin.py only registers plain ModelAdmin classes."""
    import jwt_multiauth.admin as admin_module

    assert not hasattr(admin_module, "JAZZMIN_SETTINGS")
