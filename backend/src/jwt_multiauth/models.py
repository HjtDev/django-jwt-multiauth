"""Data models: ``OtpChallenge``, ``AuthSession``, ``TwoFactorDevice``, ``RecoveryCode``,
``VerifiedContact``, ``LoginAttempt``, ``TrustedDevice``.

Phase 2 implements all seven exactly as ``docs/CONTRACT.md`` §1 specifies, with
``Meta.indexes`` on every field used in a frequent filter/ordering/lookup
(``APP-DESIGN.md`` §2's baseline query-optimization note).

Every FK/O2O-shaped reference anywhere in this module is ``settings.AUTH_USER_MODEL`` — never a
concrete user-model import (this repo's ``CLAUDE.md`` rule 1). ``OtpChallenge.user`` is nullable
in the schema but never actually written as ``None`` in v1.0.0 (``docs/CONTRACT.md`` §11 item 11)
— the field allows it structurally so a future purpose needing an unresolved-user row isn't
blocked at the schema level, but no code path in this app writes a decoy row; the decoy-challenge
behavior (rule 5, enumeration resistance) is implemented without ever persisting one.

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


class OtpChallenge(models.Model):  # noqa: DJ008 -- see module docstring
    """A single OTP/magic-link challenge. Real challenges (identifier resolved) are persisted;
    decoy challenges (identifier did not resolve) are NEVER persisted — see §5's enumeration-
    resistance note and §11 item 11. user is nullable in the schema for that reason alone: a real
    row always has a user, and no code path in this app ever creates a row with user=None.
    """

    challenge_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        related_name="otp_challenges",
    )
    channel = models.CharField(max_length=8, choices=[("email", "email"), ("phone", "phone")])
    purpose = models.CharField(
        max_length=16,
        choices=[
            ("login", "login"),
            ("password_reset", "password_reset"),
            ("verify_contact", "verify_contact"),
            ("two_factor", "two_factor"),
        ],
    )
    destination = models.CharField(max_length=255)  # the actual email/phone the code targeted
    code_hash = models.CharField(max_length=64)  # written only by otp.hash_secret via OtpService
    link_token_hash = models.CharField(  # noqa: DJ001 -- None vs "" must stay distinguishable, see module docstring
        max_length=64, null=True, blank=True
    )  # ditto, written only by otp.hash_secret via OtpService, EMIT_LINK_TOKEN only
    attempts = models.PositiveSmallIntegerField(default=0)
    max_attempts = models.PositiveSmallIntegerField()  # snapshotted from conf at creation time
    resend_count = models.PositiveSmallIntegerField(default=0)
    max_resends = models.PositiveSmallIntegerField()  # snapshotted from conf at creation time
    last_sent_at = models.DateTimeField()  # updated by OtpService.resend; drives resend cooldown
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
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

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="auth_sessions"
    )
    current_jti = models.CharField(max_length=64, unique=True)  # written only by TokenService
    rotation_count = models.PositiveIntegerField(default=0)
    device_label = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.CharField(max_length=512, blank=True)
    remember_me = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(  # noqa: DJ001 -- None vs "" must stay distinguishable, see module docstring
        max_length=32,
        null=True,
        blank=True,
        choices=[
            ("user_logout", "user_logout"),
            ("admin_revoked", "admin_revoked"),
            ("reuse_detected", "reuse_detected"),
            ("password_changed", "password_changed"),
            ("expired", "expired"),
        ],
    )

    class Meta:
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
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="two_factor_devices"
    )
    method = models.CharField(max_length=16, choices=[("totp", "totp")])
    secret_encrypted = models.TextField()  # written only by TwoFactorService.enroll_totp (Fernet)
    last_used_step = models.BigIntegerField(default=0)  # TOTP replay guard
    created_at = models.DateTimeField(auto_now_add=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    disabled_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=["user", "method"], name="unique_user_method_2fa_device")
        ]


class RecoveryCode(models.Model):  # noqa: DJ008 -- see module docstring
    """One row per unused/used recovery code. TwoFactorService.generate_recovery_codes (§4)
    invalidates prior unused codes by deleting them, not by marking used_at — a regenerated batch
    must not leave stale live codes behind.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="recovery_codes"
    )
    code_hash = models.CharField(max_length=64)  # written only by otp.hash_secret, TwoFactorService
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
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
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="verified_contacts"
    )
    field = models.CharField(max_length=8, choices=[("email", "email"), ("phone", "phone")])
    value = models.CharField(max_length=255)
    verified_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
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
    )
    identifier = models.CharField(max_length=255)
    method = models.CharField(
        max_length=16,
        choices=[("password", "password"), ("email_otp", "email_otp"), ("phone_otp", "phone_otp")],
    )
    ip_address = models.GenericIPAddressField()
    user_agent = models.CharField(max_length=512, blank=True)
    success = models.BooleanField()
    failure_reason = models.CharField(  # noqa: DJ001 -- None vs "" must stay distinguishable, see module docstring
        max_length=32,
        null=True,
        blank=True,
        choices=[
            ("no_such_identifier", "no_such_identifier"),
            ("wrong_credential", "wrong_credential"),
            ("locked", "locked"),
            ("two_factor_unavailable", "two_factor_unavailable"),
        ],
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
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
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="trusted_devices"
    )
    # written only by otp.hash_secret, via TwoFactorService
    token_hash = models.CharField(max_length=64, unique=True)
    device_label = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [models.Index(fields=["user", "revoked_at"])]
