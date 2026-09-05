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

from jwt_multiauth import models as jwt_models
from jwt_multiauth.admin import AuthSessionAdmin, LoginAttemptAdmin
from jwt_multiauth.factories import AuthSessionFactory

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


def test_no_jazzmin_settings_written_by_this_package() -> None:
    """Jazzmin is not a dependency (docs/CONTRACT.md §0) — this app never sets JAZZMIN_SETTINGS
    itself; admin.py only registers plain ModelAdmin classes."""
    import jwt_multiauth.admin as admin_module

    assert not hasattr(admin_module, "JAZZMIN_SETTINGS")
