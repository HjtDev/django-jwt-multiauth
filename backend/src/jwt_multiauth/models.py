"""Data models: ``OtpChallenge``, ``AuthSession``, ``TwoFactorDevice``, ``RecoveryCode``,
``VerifiedContact``, ``LoginAttempt``, ``TrustedDevice``.

Phase 2 implements all seven exactly as ``docs/CONTRACT.md`` §1 specifies, with
``Meta.indexes`` on every field used in a frequent filter/ordering/lookup
(``APP-DESIGN.md`` §2's baseline query-optimization note).

Every FK/O2O-shaped reference anywhere in this module is ``settings.AUTH_USER_MODEL`` — never a
concrete user-model import (this repo's ``CLAUDE.md`` rule 1). ``OtpChallenge.user`` is nullable
in the schema, and Phase 4 is the first code path that ever writes it as ``None``: for a method
NOT in ``USER_FIELDS.AUTO_PROVISION_METHODS``, an unresolved identifier is still a decoy — nothing
is ever persisted, exactly as before. For a method IN that list, an unresolved identifier now
persists a REAL row with ``user=None`` instead (``docs/CONTRACT.md`` §11 item 19) — the account
doesn't exist yet, but the challenge is genuine and may create one at verify time
(``services.UserProvisioningService``). Either way, ``user=None`` never means "decoy"; it means
"not yet resolved to an account", and ``OtpService.verify()`` treats a decoy and a real-but-expired
challenge identically (§10) regardless of which reason produced the null.

Every secret-holding field (an OTP code, a recovery code, a TOTP seed, a refresh/session token)
is a plain ``CharField``/``TextField`` here — hashing (``otp.hash_secret``, HMAC-SHA256 via
``hmac.compare_digest``) and encryption (``appkit.crypto.Cipher``, keyed by
``jwt_multiauth.keys.get_encryption_key()``) happen in ``services.py``, never in a custom field
descriptor (this repo's ``CLAUDE.md`` rule 4).

``Meta.indexes``/``Meta.constraints`` below are annotated ``ClassVar`` — ruff's ``RUF012``
otherwise reads a class-level list/tuple literal as a mutable default it can't tell is never
mutated at runtime, exactly the same false positive ``pyproject.toml``'s own migrations
``per-file-ignores`` already works around for generated migration files; ``ClassVar`` is the
fix ruff's own message recommends, so it's applied here instead of a blanket ignore.

Two ``DJ001`` (`null=True` on a `CharField`) findings are accepted, not "fixed": one for
``OtpChallenge.link_token_hash`` and one for ``AuthSession.revoked_reason`` — ``docs/CONTRACT.md``
§1 specifies both nullable exactly because ``None`` (the value never applies) must stay
distinguishable from an empty string (the value applies and happens to be empty), and
``revoked_reason``'s own ``choices`` list has no blank option to serve that role instead.

``DJ008`` (no ``__str__``) is accepted for all seven models too — ``docs/CONTRACT.md`` §1 is a
frozen field-by-field spec with no ``__str__`` listed on any of them, and every admin registration
in ``admin.py`` sets an explicit ``list_display`` rather than relying on ``__str__`` for display.
"""

from __future__ import annotations

import uuid
from typing import ClassVar

from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _


class OtpChallenge(models.Model):  # noqa: DJ008 -- see module docstring
    """A single OTP/magic-link challenge. For a method NOT in
    ``USER_FIELDS.AUTO_PROVISION_METHODS``, an unresolved identifier is a decoy — nothing is ever
    persisted, see §5's enumeration-resistance note. For a method IN that list, an unresolved
    identifier persists a REAL row with user=None — the account doesn't exist yet, but the
    challenge is genuine and may create one at verify time (services.UserProvisioningService,
    docs/CONTRACT.md §11 item 19). Either way user=None never means "decoy"; it means "not yet
    resolved to an account", and OtpService.verify() treats a decoy and a real-but-expired
    challenge identically (§10) regardless of which reason produced the null.
    """

    challenge_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, verbose_name=_("challenge ID")
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        related_name="otp_challenges",
        verbose_name=_("user"),
    )
    channel = models.CharField(
        max_length=8,
        choices=[("email", _("Email")), ("phone", _("Phone"))],
        verbose_name=_("channel"),
    )
    purpose = models.CharField(
        max_length=16,
        choices=[
            ("login", _("Login")),
            ("password_reset", _("Password reset")),
            ("verify_contact", _("Verify contact")),
            ("two_factor", _("Two-factor")),
        ],
        verbose_name=_("purpose"),
    )
    destination = models.CharField(
        max_length=255,
        verbose_name=_("destination"),
        help_text=_("The actual email address or phone number the code was sent to."),
    )
    code_hash = models.CharField(
        max_length=64, verbose_name=_("code hash")
    )  # written only by otp.hash_secret via OtpService
    link_token_hash = models.CharField(  # noqa: DJ001 -- None vs "" must stay distinguishable, see module docstring
        max_length=64,
        null=True,
        blank=True,
        verbose_name=_("link token hash"),
    )  # ditto, written only by otp.hash_secret via OtpService, EMIT_LINK_TOKEN only
    attempts = models.PositiveSmallIntegerField(default=0, verbose_name=_("attempts"))
    max_attempts = models.PositiveSmallIntegerField(
        verbose_name=_("max attempts"),
        help_text=_("Snapshotted from configuration when the challenge was created."),
    )
    resend_count = models.PositiveSmallIntegerField(default=0, verbose_name=_("resend count"))
    max_resends = models.PositiveSmallIntegerField(
        verbose_name=_("max resends"),
        help_text=_("Snapshotted from configuration when the challenge was created."),
    )
    last_sent_at = models.DateTimeField(
        verbose_name=_("last sent at"),
        help_text=_("Updated on every resend; drives the resend cooldown."),
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("created at"))
    expires_at = models.DateTimeField(verbose_name=_("expires at"))
    consumed_at = models.DateTimeField(null=True, blank=True, verbose_name=_("consumed at"))

    class Meta:
        verbose_name = _("OTP challenge")
        verbose_name_plural = _("OTP challenges")
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["user", "purpose", "consumed_at"]),
            models.Index(fields=["expires_at"]),
        ]


class AuthSession(models.Model):  # noqa: DJ008 -- see module docstring
    """One row per logical login session. current_jti is replaced on every successful refresh
    (rotation); a superseded jti being presented again is reuse — see TokenService.rotate_refresh
    (§4). revoked_reason is set only when revoked_at is.

    last_used_at uses auto_now_add=True, not auto_now=True — this is intentional, not a mistake
    to "fix": auto_now_add only governs the INSERT value, and TokenService.rotate_refresh (Phase
    3) is expected to bump this field via an explicit .save(update_fields=[...]) on every use,
    same as TrustedDevice.last_used_at below.
    """

    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, verbose_name=_("session ID")
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="auth_sessions",
        verbose_name=_("user"),
    )
    current_jti = models.CharField(  # written only by TokenService
        max_length=64,
        unique=True,
        verbose_name=_("current JTI"),
        help_text=_("The refresh token's current JWT ID; replaced on every rotation."),
    )
    rotation_count = models.PositiveIntegerField(default=0, verbose_name=_("rotation count"))
    device_label = models.CharField(max_length=255, blank=True, verbose_name=_("device label"))
    ip_address = models.GenericIPAddressField(verbose_name=_("IP address"))
    user_agent = models.CharField(max_length=512, blank=True, verbose_name=_("user agent"))
    remember_me = models.BooleanField(
        default=False,
        verbose_name=_("remember me"),
        help_text=_("Whether this session was issued a long-lived refresh token."),
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("created at"))
    last_used_at = models.DateTimeField(auto_now_add=True, verbose_name=_("last used at"))
    expires_at = models.DateTimeField(verbose_name=_("expires at"))
    revoked_at = models.DateTimeField(null=True, blank=True, verbose_name=_("revoked at"))
    revoked_reason = models.CharField(  # noqa: DJ001 -- None vs "" must stay distinguishable, see module docstring
        max_length=32,
        null=True,
        blank=True,
        choices=[
            ("user_logout", _("User logout")),
            ("admin_revoked", _("Admin revoked")),
            ("reuse_detected", _("Reuse detected")),
            ("password_changed", _("Password changed")),
            ("expired", _("Expired")),
        ],
        verbose_name=_("revoked reason"),
    )

    class Meta:
        verbose_name = _("auth session")
        verbose_name_plural = _("auth sessions")
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["user", "revoked_at"]),
            models.Index(fields=["expires_at"]),
        ]


class TwoFactorDevice(models.Model):  # noqa: DJ008 -- see module docstring
    """method is currently only 'totp' — the field exists so a future method needing persistent
    enrollment state doesn't need a new model. confirmed_at is None for a pending enrollment; an
    unconfirmed device is never counted as eligible (see TwoFactorService.eligible_methods, §4).
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="two_factor_devices",
        verbose_name=_("user"),
    )
    method = models.CharField(
        max_length=16, choices=[("totp", _("TOTP"))], verbose_name=_("method")
    )
    secret_encrypted = models.TextField(  # written only by TwoFactorService.enroll_totp (Fernet)
        verbose_name=_("encrypted secret")
    )
    last_used_step = models.BigIntegerField(
        default=0,
        verbose_name=_("last used step"),
        help_text=_("TOTP replay guard — the last time-step value that was accepted."),
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("created at"))
    confirmed_at = models.DateTimeField(null=True, blank=True, verbose_name=_("confirmed at"))
    disabled_at = models.DateTimeField(null=True, blank=True, verbose_name=_("disabled at"))

    class Meta:
        verbose_name = _("two-factor device")
        verbose_name_plural = _("two-factor devices")
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=["user", "method"], name="unique_user_method_2fa_device")
        ]


class RecoveryCode(models.Model):  # noqa: DJ008 -- see module docstring
    """One row per unused/used recovery code. TwoFactorService.generate_recovery_codes (§4)
    invalidates prior unused codes by deleting them, not by marking used_at — a regenerated batch
    must not leave stale live codes behind.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="recovery_codes",
        verbose_name=_("user"),
    )
    code_hash = models.CharField(  # written only by otp.hash_secret, TwoFactorService
        max_length=64, verbose_name=_("code hash")
    )
    used_at = models.DateTimeField(null=True, blank=True, verbose_name=_("used at"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("created at"))

    class Meta:
        verbose_name = _("recovery code")
        verbose_name_plural = _("recovery codes")
        indexes: ClassVar[list[models.Index]] = [models.Index(fields=["user", "used_at"])]


class VerifiedContact(models.Model):  # noqa: DJ008 -- see module docstring
    """value is the exact value that was verified — NOT hashed, since it is compared against the
    user model's own live field value, which is already plaintext PII on the user model itself.
    Resolution rule (stated explicitly, per §0 item 1 of the guide's Phase 0 prompt): if the
    user's live field value no longer matches ANY VerifiedContact row for that field, the field is
    effectively unverified again — VerificationService and TwoFactorService.eligible_methods both
    look up VerifiedContact by the user's CURRENT field value, never by user+field alone.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="verified_contacts",
        verbose_name=_("user"),
    )
    field = models.CharField(
        max_length=8,
        choices=[("email", _("Email")), ("phone", _("Phone"))],
        verbose_name=_("field"),
    )
    value = models.CharField(
        max_length=255,
        verbose_name=_("value"),
        help_text=_("The exact contact value that was verified."),
    )
    verified_at = models.DateTimeField(auto_now_add=True, verbose_name=_("verified at"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("created at"))

    class Meta:
        verbose_name = _("verified contact")
        verbose_name_plural = _("verified contacts")
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["user", "field", "value"], name="unique_user_field_value_verified"
            )
        ]


class LoginAttempt(models.Model):  # noqa: DJ008 -- see module docstring
    """identifier is PLAINTEXT deliberately — not a secret by rule 4, and an admin needs to search
    it. user is null when the identifier never resolved to a real account — this is the one model
    where that distinction is recorded at all, and only here.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="login_attempts",
        verbose_name=_("user"),
    )
    identifier = models.CharField(
        max_length=255,
        verbose_name=_("identifier"),
        help_text=_("Stored in plaintext, deliberately, so an admin can search it."),
    )
    method = models.CharField(
        max_length=16,
        choices=[
            ("password", _("Password")),
            ("email_otp", _("Email OTP")),
            ("phone_otp", _("Phone OTP")),
        ],
        verbose_name=_("method"),
    )
    ip_address = models.GenericIPAddressField(verbose_name=_("IP address"))
    user_agent = models.CharField(max_length=512, blank=True, verbose_name=_("user agent"))
    success = models.BooleanField(verbose_name=_("success"))
    failure_reason = models.CharField(  # noqa: DJ001 -- None vs "" must stay distinguishable, see module docstring
        max_length=32,
        null=True,
        blank=True,
        choices=[
            ("no_such_identifier", _("No such identifier")),
            ("wrong_credential", _("Wrong credential")),
            ("locked", _("Locked")),
            ("two_factor_unavailable", _("Two-factor unavailable")),
        ],
        verbose_name=_("failure reason"),
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("created at"))

    class Meta:
        verbose_name = _("login attempt")
        verbose_name_plural = _("login attempts")
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["identifier", "created_at"]),
            models.Index(fields=["ip_address", "created_at"]),
            models.Index(fields=["user", "created_at"]),
        ]


class TrustedDevice(models.Model):  # noqa: DJ008 -- see module docstring
    """A real, hashed bearer secret controlling a skip-2FA decision — hashed exactly like a
    refresh token, never stored plaintext. Issued as a second cookie alongside the refresh cookie,
    checked at login BEFORE 2FA is even evaluated (§10 "no-token-before-2FA"), and independently
    revocable per-device from both surfaces (§5, §11 item 2).

    last_used_at uses auto_now_add=True — same reasoning as AuthSession.last_used_at above: an
    explicit .save() on use is what actually bumps it, not the field itself.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="trusted_devices",
        verbose_name=_("user"),
    )
    # written only by otp.hash_secret, via TwoFactorService
    token_hash = models.CharField(max_length=64, unique=True, verbose_name=_("token hash"))
    device_label = models.CharField(max_length=255, blank=True, verbose_name=_("device label"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("created at"))
    last_used_at = models.DateTimeField(auto_now_add=True, verbose_name=_("last used at"))
    expires_at = models.DateTimeField(verbose_name=_("expires at"))
    revoked_at = models.DateTimeField(null=True, blank=True, verbose_name=_("revoked at"))

    class Meta:
        verbose_name = _("trusted device")
        verbose_name_plural = _("trusted devices")
        indexes: ClassVar[list[models.Index]] = [models.Index(fields=["user", "revoked_at"])]
