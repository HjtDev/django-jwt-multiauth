"""Plain ``django.contrib.admin.ModelAdmin`` registrations for the seven models.

Phase 2 implements registrations for ``OtpChallenge``, ``AuthSession``, ``TwoFactorDevice``,
``RecoveryCode``, ``VerifiedContact``, ``LoginAttempt``, ``TrustedDevice``. Jazzmin is **not** a
dependency of this package — this app never writes to ``JAZZMIN_SETTINGS`` itself; a suggested
icon per model lives in the README (``docs/CONTRACT.md`` §0's "Jazzmin" row) — see the comment
block at the bottom of this file for the suggested icons themselves.

Every model reference here is indirect — ``django.contrib.auth.get_user_model()`` for the user,
never a concrete import (this repo's ``CLAUDE.md`` rule 1). Never renders ``secret_encrypted``,
``code_hash``, ``link_token_hash``, or ``token_hash``; session revocation goes through
``services.TokenService``, never a raw queryset ``.update()``, so the revoked-session signal path
always fires.
"""

from __future__ import annotations

from typing import Any

from django.contrib import admin
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _

from jwt_multiauth import permissions as jwt_permissions
from jwt_multiauth.models import (
    AuthSession,
    LoginAttempt,
    OtpChallenge,
    RecoveryCode,
    TrustedDevice,
    TwoFactorDevice,
    VerifiedContact,
)
from jwt_multiauth.services import LockoutService, TokenService, TwoFactorService


@admin.register(OtpChallenge)
class OtpChallengeAdmin(admin.ModelAdmin):
    """``code_hash``/``link_token_hash`` are secrets (this repo's ``CLAUDE.md`` rule 4) — absent
    from every attribute below, not merely excluded from ``list_display``.
    """

    list_display = (
        "challenge_id",
        "user",
        "channel",
        "purpose",
        "destination",
        "attempts",
        "resend_count",
        "created_at",
        "expires_at",
        "consumed_at",
    )
    list_filter = ("channel", "purpose")
    search_fields = ("destination",)
    readonly_fields = (
        "challenge_id",
        "user",
        "channel",
        "purpose",
        "destination",
        "attempts",
        "max_attempts",
        "resend_count",
        "max_resends",
        "last_sent_at",
        "created_at",
        "expires_at",
        "consumed_at",
    )
    # Explicit `fields`, matching `readonly_fields` exactly: with neither `fields` nor
    # `fieldsets` set, Django's change form falls back to every concrete model field —
    # code_hash/link_token_hash included. `readonly_fields` alone only stops them being
    # *editable*, not *rendered*; this is what actually keeps them off the page.
    fields = readonly_fields

    def get_queryset(self, request: HttpRequest) -> QuerySet[OtpChallenge]:
        return super().get_queryset(request).select_related("user")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False


@admin.register(AuthSession)
class AuthSessionAdmin(admin.ModelAdmin):
    """``current_jti`` is a secret (this repo's ``CLAUDE.md`` rule 4) — absent from every
    attribute below. ``revoke_sessions`` never calls ``queryset.update()``: it loops the
    unrevoked rows and calls ``TokenService.revoke_session`` per row, so the ``session_revoked``
    signal fires for each one (this repo's ``CLAUDE.md``'s Phase 2 prompt, verbatim).
    """

    list_display = (
        "id",
        "user",
        "ip_address",
        "device_label",
        "rotation_count",
        "remember_me",
        "created_at",
        "revoked_at",
        "revoked_reason",
    )
    list_filter = ("remember_me", "revoked_reason")
    search_fields = ("user__pk",)
    readonly_fields = (
        "id",
        "user",
        "rotation_count",
        "device_label",
        "ip_address",
        "user_agent",
        "remember_me",
        "created_at",
        "last_used_at",
        "expires_at",
        "revoked_at",
        "revoked_reason",
    )
    # See OtpChallengeAdmin's comment above — this is what actually keeps current_jti off the
    # rendered change form, not just out of readonly_fields.
    fields = readonly_fields
    actions = ("revoke_sessions",)

    def get_queryset(self, request: HttpRequest) -> QuerySet[AuthSession]:
        return super().get_queryset(request).select_related("user")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    @admin.action(description=_("Revoke selected sessions"))
    def revoke_sessions(self, request: HttpRequest, queryset: QuerySet[AuthSession]) -> None:
        for session in queryset.filter(revoked_at__isnull=True):
            TokenService.revoke_session(str(session.pk), reason="admin_revoked")


@admin.register(TwoFactorDevice)
class TwoFactorDeviceAdmin(admin.ModelAdmin):
    """``secret_encrypted`` is a secret (this repo's ``CLAUDE.md`` rule 4) — absent from every
    attribute below, not truncated, not masked: absent. ``force_disable_two_factor`` is
    ``is_superuser``-only via ``permissions.is_superuser`` — the SAME always-on check
    ``permissions.IsSuperUser`` uses for the REST route, never the configurable
    ``ADMIN_REQUIRES_SUPERUSER`` gate (Phase 8, ``docs/CONTRACT.md`` §11 item 18). Calls
    ``TwoFactorService.admin_force_disable``, never a raw ``queryset.delete()`` — a raw delete
    would skip the service and never fire ``two_factor_disabled``.
    """

    list_display = (
        "user",
        "method",
        "last_used_step",
        "created_at",
        "confirmed_at",
        "disabled_at",
    )
    list_filter = ("method",)
    readonly_fields = (
        "user",
        "method",
        "last_used_step",
        "created_at",
        "confirmed_at",
        "disabled_at",
    )
    # See OtpChallengeAdmin's comment above — this is what actually keeps secret_encrypted off
    # the rendered change form, not just out of readonly_fields.
    fields = readonly_fields
    actions = ("force_disable_two_factor",)

    def get_queryset(self, request: HttpRequest) -> QuerySet[TwoFactorDevice]:
        return super().get_queryset(request).select_related("user")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_force_disable_2fa_permission(self, request: HttpRequest) -> bool:
        return jwt_permissions.is_superuser(request.user)

    @admin.action(
        description=_("Force-disable 2FA for selected devices' users"),
        permissions=["force_disable_2fa"],
    )
    def force_disable_two_factor(
        self, request: HttpRequest, queryset: QuerySet[TwoFactorDevice]
    ) -> None:
        # Distinct users, not distinct rows: admin_force_disable already handles every method
        # (totp, recovery_code) and every TrustedDevice for the user in one call — calling it
        # once per selected TwoFactorDevice row (rather than once per user) would be redundant,
        # not incorrect, but a user with two selected rows would otherwise fire the service twice.
        seen_user_ids: set[Any] = set()
        for device in queryset.select_related("user"):
            if device.user_id in seen_user_ids:
                continue
            seen_user_ids.add(device.user_id)
            TwoFactorService.admin_force_disable(device.user)


@admin.register(RecoveryCode)
class RecoveryCodeAdmin(admin.ModelAdmin):
    """``code_hash`` is a secret (this repo's ``CLAUDE.md`` rule 4) — absent from every attribute
    below.
    """

    list_display = ("user", "used_at", "created_at")
    list_filter = ("used_at",)
    readonly_fields = ("user", "used_at", "created_at")
    # See OtpChallengeAdmin's comment above — this is what actually keeps code_hash off the
    # rendered change form, not just out of readonly_fields.
    fields = readonly_fields

    def get_queryset(self, request: HttpRequest) -> QuerySet[RecoveryCode]:
        return super().get_queryset(request).select_related("user")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False


@admin.register(VerifiedContact)
class VerifiedContactAdmin(admin.ModelAdmin):
    list_display = ("user", "field", "value", "verified_at")
    list_filter = ("field",)
    search_fields = ("value",)
    readonly_fields = ("user", "field", "value", "verified_at", "created_at")

    def get_queryset(self, request: HttpRequest) -> QuerySet[VerifiedContact]:
        return super().get_queryset(request).select_related("user")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    """Fully readonly — this model is an audit log, never edited from the admin. ``identifier``
    is the one deliberately plaintext, searchable field in this whole app (``docs/CONTRACT.md``
    §0 rail 4: not a secret by that rule's own definition, and an admin needs to search it) — do
    not "fix" this into a hash.

    ``unlock_identifiers`` (Phase 8, ``docs/CONTRACT.md`` §11 item 18) lives HERE rather than on
    the ``User`` admin: lockout state is an ``appkit.cache`` counter, not a model row, so this
    action needs an identifier string to resolve it, and a selected ``LoginAttempt`` row already
    carries the EXACT string ``LockoutService``'s cache key was built from — a ``User`` admin
    action would have to re-derive one instead. Calls ``LockoutService.unlock`` once per distinct
    ``identifier`` in the selection, never acting on a lock "object" that doesn't exist.
    """

    list_display = (
        "identifier",
        "method",
        "success",
        "failure_reason",
        "ip_address",
        "user",
        "created_at",
    )
    list_filter = ("success", "method")
    search_fields = ("identifier",)
    readonly_fields = (
        "user",
        "identifier",
        "method",
        "ip_address",
        "user_agent",
        "success",
        "failure_reason",
        "created_at",
    )
    actions = ("unlock_identifiers",)

    def get_queryset(self, request: HttpRequest) -> QuerySet[LoginAttempt]:
        return super().get_queryset(request).select_related("user")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    @admin.action(description=_("Unlock selected identifiers"))
    def unlock_identifiers(self, request: HttpRequest, queryset: QuerySet[LoginAttempt]) -> None:
        identifiers = set(queryset.values_list("identifier", flat=True))
        for identifier in identifiers:
            LockoutService.unlock(identifier)


@admin.register(TrustedDevice)
class TrustedDeviceAdmin(admin.ModelAdmin):
    """``token_hash`` is a secret (this repo's ``CLAUDE.md`` rule 4) — absent from every attribute
    below. ``revoke_trusted_devices`` never calls ``queryset.update()``: it loops the unrevoked
    rows and calls ``TwoFactorService.revoke_trusted_device`` per row, the same
    loop-and-call-the-service pattern ``AuthSessionAdmin.revoke_sessions`` uses (Phase 8,
    ``docs/CONTRACT.md`` §11 item 18).
    """

    list_display = (
        "user",
        "device_label",
        "created_at",
        "last_used_at",
        "expires_at",
        "revoked_at",
    )
    list_filter = ("revoked_at",)
    readonly_fields = (
        "user",
        "device_label",
        "created_at",
        "last_used_at",
        "expires_at",
        "revoked_at",
    )
    # See OtpChallengeAdmin's comment above — this is what actually keeps token_hash off the
    # rendered change form, not just out of readonly_fields.
    fields = readonly_fields
    actions = ("revoke_trusted_devices",)

    def get_queryset(self, request: HttpRequest) -> QuerySet[TrustedDevice]:
        return super().get_queryset(request).select_related("user")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    @admin.action(description=_("Revoke selected trusted devices"))
    def revoke_trusted_devices(
        self, request: HttpRequest, queryset: QuerySet[TrustedDevice]
    ) -> None:
        for device in queryset.filter(revoked_at__isnull=True):
            TwoFactorService.revoke_trusted_device(device)


# Suggested Jazzmin icons (docs/CONTRACT.md §0 — this app never sets JAZZMIN_SETTINGS itself;
# a host running Jazzmin copies these into its own icons config under the Phase 12 README):
#   jwt_multiauth.OtpChallenge     -> fas fa-key
#   jwt_multiauth.AuthSession      -> fas fa-desktop
#   jwt_multiauth.TwoFactorDevice  -> fas fa-shield-alt
#   jwt_multiauth.RecoveryCode     -> fas fa-life-ring
#   jwt_multiauth.VerifiedContact  -> fas fa-check-circle
#   jwt_multiauth.LoginAttempt     -> fas fa-history
#   jwt_multiauth.TrustedDevice    -> fas fa-mobile-alt
