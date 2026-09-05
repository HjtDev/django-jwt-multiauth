# CONTRACT.md — django-jwt-multiauth

The frozen public contract for `django-jwt-multiauth` (module: `jwt_multiauth`). Every later build
phase (`docs/CLAUDE-CODE-GUIDE-APP-JWT-MULTIAUTH.md` §2) implements exactly what's written here —
it does not re-derive model shapes, signal payloads, service signatures, endpoints, settings, or
hooks. If code and this file ever disagree, that disagreement is a bug in one of them, not a
license to improvise (`docs/APP-DESIGN.md` §11).

**Sources checked while writing this**, not assumed from the guide's prose: `hjtdev-appkit`
2.0.2's actual installed source (`appkit/backend/src/appkit/{crypto,net,permissions,pagination,
mixins,exceptions}.py`, `appkit/backend/pyproject.toml`'s `[project.optional-dependencies]`,
`appkit/frontend/src/{client,provider,errors,index}.ts`), `appkit/docs/CONTRACT.md` §§1, 2.5–2.7,
2.10, 13–16, J, `django-dynamic-user/docs/CONTRACT.md` as the shape precedent for this document
(numbered `§`-sections, a deviations register, an explicit "Requires another app package" line
closing each model/logic section), and this app's own
`docs/CLAUDE-CODE-GUIDE-APP-JWT-MULTIAUTH.md` §§0–1 and every Phase prompt in §2 in full — every
appkit symbol and extra named below was read from that source, not recalled from documentation.
Two findings from that reading changed or added to what the guide states as settled; see §11
items 1, 3, and 9.

This app is **the JWT authentication layer only** — no profile, no settings, no avatar, no
account-deletion flow. Those belong to `django-dynamic-user` (app package #3), reached only
through `settings.AUTH_USER_MODEL` / `get_user_model()`.

---

## §0. Identity & boundary

| | |
|---|---|
| Importable module | `jwt_multiauth` |
| PyPI distribution | `django-jwt-multiauth` |
| npm package | `@hjtdev/django-jwt-multiauth` |
| GitHub repo | `HjtDev/django-jwt-multiauth` |
| Declared dependencies (not app packages, `APP-DESIGN.md` §1.1's named exception) | `hjtdev-appkit>=2.0,<3.0` (backend), `@hjtdev/appkit` peer (frontend) — both halves |
| JWT layer | **PyJWT directly** (`pyjwt>=2.9,<3.0`), not `djangorestframework-simplejwt`. `tokens.py` owns claim construction/verification; `AuthSession` (this app's own model) supersedes simplejwt's `token_blacklist` app |
| Scope | Authentication only: password/phone-OTP/email-OTP login (+ magic-link variant), password reset, optional 2FA, sessions, lockout, audit log. No profile/settings/avatar/deletion — `django-dynamic-user`'s job. No delivery of anything — this app emits `phone_otp_requested`/`email_otp_requested` and a host wires them to Twilio/SES/whatever |
| Model strategy | Every user-referencing field is `settings.AUTH_USER_MODEL`. No `resolution.py` — this app never defines or swaps the user model itself, so there is only one indirection to get right, not two |
| Two frontend basePath keys | `jwt_multiauth` → `/api/v1/auth` (self-service), `jwt_multiauth_admin` → `/api/v1/admin/auth` (admin) |
| Admin gating | `appkit.permissions.IsAppAdmin` (`is_staff`) by default. `JWT_MULTIAUTH["ADMIN_REQUIRES_SUPERUSER"]` (default `False`) tightens every admin gate to `is_superuser` — **except** force-disable-2FA, which is `is_superuser`-only unconditionally, regardless of this setting |
| Jazzmin | **Not a dependency.** This app registers plain `django.contrib.admin.ModelAdmin` classes; a suggested icon per model lives in the README (§8 of `APP-DESIGN.md`), never in this package's own code |

**The five rails every phase from here on is checked against** (`CLAUDE.md`'s "rules that define
this package", restated with their reasoning):

1. Every model reference is indirect: `settings.AUTH_USER_MODEL` / `get_user_model()` — never
   `from django.contrib.auth.models import User` or any other concrete import, not even inside
   this package's own `admin.py` or `services.py`.
2. The user model is validated per *enabled* method, never assumed — `checks.py` fails
   `manage.py check` when an enabled method needs a field the resolved user model doesn't have. A
   method never turned on imposes no requirement at all.
3. Fail closed, everywhere, permanently — an unresolvable second factor, an unconfigured delivery
   channel, a missing required key, an ambiguous identifier: every one of these rejects the
   request. There is no "if 2FA can't be satisfied, log them in anyway" path, ever, under any
   settings combination.
4. No secret is ever stored recoverably; every comparison is constant-time; every generator is
   `secrets`, never `random`. `JWT_MULTIAUTH_ENCRYPTION_KEY` is never derived from `SECRET_KEY`. A
   login identifier is **not** a secret by this rule's own definition and is stored plaintext in
   `LoginAttempt` deliberately, so an admin can search it.
5. Every failure path is enumeration-resistant — unknown identifier and known-wrong-credential
   produce the same status, the same body shape, and near-identical timing, for every
   identifier-taking endpoint, without exception.

---

## §1. Models

All FKs via `settings.AUTH_USER_MODEL` and `migrations.swappable_dependency(settings.AUTH_USER_MODEL)`
in the initial migration. **Requires another app package: No** for every model below.

Fields that hold a secret are declared as plain `CharField`/`TextField` here — hashing/encryption
happens in `services.py` (§4), never as a custom field descriptor that hides what's actually being
stored. Each such field carries a comment naming the one function responsible for ever writing it.

```python
# jwt_multiauth/models.py
import uuid

from django.conf import settings
from django.db import models


class OtpChallenge(models.Model):
    """A single OTP/magic-link challenge. Real challenges (identifier resolved) are persisted;
    decoy challenges (identifier did not resolve) are NEVER persisted — see §5's enumeration-
    resistance note and §11 item 11. user is nullable in the schema for that reason alone: a real
    row always has a user, and no code path in this app ever creates a row with user=None."""

    challenge_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, related_name="otp_challenges"
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
    link_token_hash = models.CharField(max_length=64, null=True, blank=True)  # ditto, EMIT_LINK_TOKEN only
    attempts = models.PositiveSmallIntegerField(default=0)
    max_attempts = models.PositiveSmallIntegerField()  # snapshotted from conf at creation time
    resend_count = models.PositiveSmallIntegerField(default=0)
    max_resends = models.PositiveSmallIntegerField()  # snapshotted from conf at creation time
    last_sent_at = models.DateTimeField()  # updated by OtpService.resend; drives RESEND_COOLDOWN_SECONDS
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "purpose", "consumed_at"]),
            models.Index(fields=["expires_at"]),
        ]


class AuthSession(models.Model):
    """One row per logical login session. current_jti is replaced on every successful refresh
    (rotation); a superseded jti being presented again is reuse — see TokenService.rotate_refresh
    (§4). revoked_reason is set only when revoked_at is."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="auth_sessions")
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
    revoked_reason = models.CharField(
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
        indexes = [
            models.Index(fields=["user", "revoked_at"]),
            models.Index(fields=["expires_at"]),
        ]


class TwoFactorDevice(models.Model):
    """method is currently only 'totp' — the field exists so a future method needing persistent
    enrollment state doesn't need a new model. confirmed_at is None for a pending enrollment; an
    unconfirmed device is never counted as eligible (see TwoFactorService.eligible_methods, §4)."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="two_factor_devices")
    method = models.CharField(max_length=16, choices=[("totp", "totp")])
    secret_encrypted = models.TextField()  # written only by TwoFactorService.enroll_totp, via appkit.crypto.Cipher
    last_used_step = models.BigIntegerField(default=0)  # TOTP replay guard
    created_at = models.DateTimeField(auto_now_add=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    disabled_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["user", "method"], name="unique_user_method_2fa_device")]


class RecoveryCode(models.Model):
    """One row per unused/used recovery code. TwoFactorService.generate_recovery_codes (§4)
    invalidates prior unused codes by deleting them, not by marking used_at — a regenerated batch
    must not leave stale live codes behind."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="recovery_codes")
    code_hash = models.CharField(max_length=64)  # written only by otp.hash_secret via TwoFactorService
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["user", "used_at"])]


class VerifiedContact(models.Model):
    """value is the exact value that was verified — NOT hashed, since it is compared against the
    user model's own live field value, which is already plaintext PII on the user model itself.
    Resolution rule (stated explicitly, per §0 item 1 of the guide's Phase 0 prompt): if the
    user's live field value no longer matches ANY VerifiedContact row for that field, the field is
    effectively unverified again — VerificationService and TwoFactorService.eligible_methods both
    look up VerifiedContact by the user's CURRENT field value, never by user+field alone."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="verified_contacts")
    field = models.CharField(max_length=8, choices=[("email", "email"), ("phone", "phone")])
    value = models.CharField(max_length=255)
    verified_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "field", "value"], name="unique_user_field_value_verified")
        ]


class LoginAttempt(models.Model):
    """identifier is PLAINTEXT deliberately — not a secret by rule 4, and an admin needs to search
    it. user is null when the identifier never resolved to a real account — this is the one model
    where that distinction is recorded at all, and only here."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="login_attempts"
    )
    identifier = models.CharField(max_length=255)
    method = models.CharField(
        max_length=16,
        choices=[("password", "password"), ("email_otp", "email_otp"), ("phone_otp", "phone_otp")],
    )
    ip_address = models.GenericIPAddressField()
    user_agent = models.CharField(max_length=512, blank=True)
    success = models.BooleanField()
    failure_reason = models.CharField(
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
        indexes = [
            models.Index(fields=["identifier", "created_at"]),
            models.Index(fields=["ip_address", "created_at"]),
            models.Index(fields=["user", "created_at"]),
        ]


class TrustedDevice(models.Model):
    """A real, hashed bearer secret controlling a skip-2FA decision — hashed exactly like a
    refresh token, never stored plaintext. Issued as a second cookie alongside the refresh cookie,
    checked at login BEFORE 2FA is even evaluated (§10 "no-token-before-2FA"), and independently
    revocable per-device from both surfaces (§5, §11 item 2)."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="trusted_devices")
    token_hash = models.CharField(max_length=64, unique=True)  # written only by otp.hash_secret via TwoFactorService
    device_label = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["user", "revoked_at"])]
```

**Additions to flag against the guide's Phase 0 item 1 (§11 item 4):** `OtpChallenge.resend_count`,
`.max_resends`, `.last_sent_at` are new — the guide's field list has no way to enforce
`RESEND_COOLDOWN_SECONDS`/`MAX_RESENDS` (§2) without them.

---

## §2. `conf.py` — settings access and the OTP resolver

Every OTP-touching file calls `get_otp_setting`, never a raw `settings.JWT_MULTIAUTH["OTP"][...]`
dict walk. Every other setting goes through `get_setting`, the same one-place-with-defaults
pattern `APP-DESIGN.md` §3.5 mandates for every app in this ecosystem.

```python
# jwt_multiauth/conf.py
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def get_setting(key: str) -> Any: ...


def get_otp_setting(key: str, *, channel: str, purpose: str | None = None) -> Any:
    """Resolves purpose-override -> channel-override -> JWT_MULTIAUTH["OTP"]["DEFAULTS"][key].
    Raises ImproperlyConfigured for an unknown key — never a silent None, since a silently-None
    TTL or MAX_ATTEMPTS is exactly the kind of soft failure rule 3 (fail closed) exists to prevent."""
    ...
```

`OTP["DEFAULTS"]` key list, every one resolvable through `get_otp_setting`:

| Key | Meaning |
|---|---|
| `LENGTH` | Code length |
| `ALPHABET` | `"numeric"` \| `"alpha"` \| `"alphanumeric"` \| a literal custom character-set string |
| `EXCLUDE_AMBIGUOUS` | Drops `0`/`O`/`1`/`I`/`l`/`o` from the resulting set when `True` |
| `CASE_SENSITIVE` | Whether `"alpha"`/`"alphanumeric"` include both cases |
| `TTL_SECONDS` | Challenge lifetime |
| `MAX_ATTEMPTS` | Verify attempts before the challenge locks out, regardless of correctness |
| `RESEND_COOLDOWN_SECONDS` | Minimum gap between `resend()` calls |
| `MAX_RESENDS` | Resend budget per challenge, snapshotted at creation |
| `SINGLE_ACTIVE_CHALLENGE` | A new request for the same user+purpose+channel invalidates the prior unconsumed one |
| `EMIT_LINK_TOKEN` | Whether a magic-link token is generated alongside the code |

**The hash algorithm itself (HMAC-SHA256) is NOT configurable** — a deliberate non-setting, stated
here explicitly so a later phase doesn't add a `HASH_ALGORITHM` key "for flexibility."

**Requires another app package: No.**

---

## §3. Signals — `signals.py`

Every payload is primitives/IDs only — never a model instance (checked explicitly in the §review
gate below). Each signal is documented `Sent by X. sender=Y.` / `Payload: …`, matching
`dynamic_user`'s own convention.

```python
# jwt_multiauth/signals.py
import django.dispatch

phone_otp_requested = django.dispatch.Signal()
"""Sent by OtpService.request()/resend() when channel="phone" and the identifier resolved to a
real user. sender=OtpChallenge.
Payload: user_id: int, destination: str, code: str, link_token: str | None, purpose: str,
challenge_id: str, expires_at: datetime"""

email_otp_requested = django.dispatch.Signal()
"""Sent by OtpService.request()/resend() when channel="email" and the identifier resolved to a
real user. sender=OtpChallenge. Same shape as phone_otp_requested — a SEPARATE signal, never one
signal with a channel kwarg, so a host's SMS receiver is never invoked for an email event and vice
versa.
Payload: user_id: int, destination: str, code: str, link_token: str | None, purpose: str,
challenge_id: str, expires_at: datetime"""

otp_verified = django.dispatch.Signal()
"""Sent by OtpService.verify() on a successful code/link-token compare. sender=OtpChallenge. NOT
sent for a totp or recovery_code second-factor verification — those have no OtpChallenge involved.
Payload: user_id: int, challenge_id: str, purpose: str"""

contact_verified = django.dispatch.Signal()
"""Sent by VerificationService.confirm() after the matching VerifiedContact row is created.
sender=VerifiedContact.
Payload: user_id: int, field: str, value: str"""

user_logged_in = django.dispatch.Signal()
"""Sent by TokenService.issue_token_pair() — i.e. once real tokens are actually issued, whether
that happened directly (no 2FA required) or after TwoFactorService.verify_second_factor succeeded.
sender=AuthSession.
Payload: user_id: int, session_id: str, method: str"""

user_logged_out = django.dispatch.Signal()
"""Sent by the logout view after TokenService.revoke_session() succeeds for the CALLER's own
current session. sender=AuthSession.
Payload: user_id: int, session_id: str"""

login_failed = django.dispatch.Signal()
"""Sent by LockoutService.record_attempt() whenever success=False, including on the no-such-
identifier path. sender=LoginAttempt.
Payload: identifier: str, reason: str, ip: str"""

account_locked = django.dispatch.Signal()
"""Sent by LockoutService.record_attempt() the moment MAX_ATTEMPTS is reached within WINDOW_SECONDS
for the active LOCK_SCOPE. sender=LoginAttempt.
Payload: user_id: int | None, identifier: str, until: datetime, scope: str"""

password_changed = django.dispatch.Signal()
"""Sent by PasswordService.change_password() and .confirm_reset(), after the new password is set
and AFTER every other session has been revoked. sender=get_user_model().
Payload: user_id: int"""

two_factor_enabled = django.dispatch.Signal()
"""Sent by TwoFactorService.confirm_totp() (the only enrollment path that requires confirmation;
email_otp/phone_otp/recovery_code have no separate "enabled" step). sender=TwoFactorDevice.
Payload: user_id: int, method: str"""

two_factor_disabled = django.dispatch.Signal()
"""Sent by TwoFactorService.disable() AND .admin_force_disable() — both paths, same signal, so a
host's receiver doesn't need to special-case which caller disabled it. sender=TwoFactorDevice.
Payload: user_id: int, method: str"""

refresh_reuse_detected = django.dispatch.Signal()
"""Sent by TokenService.rotate_refresh() the instant a superseded jti is presented — fired BEFORE
the session's revocation is guaranteed durable is never acceptable; fired only after the revoke
actually commits. sender=AuthSession.
Payload: user_id: int, session_id: str, ip: str"""

session_revoked = django.dispatch.Signal()
"""Sent by TokenService.revoke_session()/revoke_all_sessions() for every row revoked — including
the reuse-detection and password-changed paths, which both call through revoke_session/
revoke_all_sessions rather than duplicating the revoke logic. sender=AuthSession.
Payload: session_id: str, user_id: int, reason: str"""
```

**Minimality argument, per field:**

- `*_otp_requested` carry the PLAINTEXT `code` by design — that is this app's entire delivery
  contract (rule 3's fail-closed principle doesn't apply to a signal a host must act on to deliver
  anything at all). `link_token` is `None` when `EMIT_LINK_TOKEN` is off, never omitted from the
  signature — a receiver branching on presence, not on a missing kwarg, is exactly what a stable
  payload should look like. Nothing beyond what's needed to compose and send a message is present;
  no `OtpChallenge` instance, no `request` object.
- `account_locked` carries both `user_id` (nullable) and `identifier` — an IP-scoped lock, or a
  lock triggered by an identifier that never resolved to a real account, has no `user_id`; without
  `identifier` a host receiver (e.g. an alerting rule) has nothing actionable at all. `scope`
  documents which `LOCK_SCOPE` mode fired it, since a receiver reacting to "IP locked" versus
  "account locked" needs to know which.
- `refresh_reuse_detected` omits the stolen token itself — a host reacting to theft detection
  needs to know *who* and *where from*, never the actual token value, which would just be handing
  the receiver a still-partially-useful secret to mishandle.
- `session_revoked` carries `reason` as the literal `AuthSession.revoked_reason` choice string, so
  a host doesn't have to re-query the row to know why.

**Requires another app package: No.**

---

## §4. `services.py` — the public callable interface

Exception classes are declared first, each docstring naming its raiser and the HTTP status the
views (§5) map it to. Full signatures, fully typed, `...` bodies — implementation is Phase 3–5's
job, not this document's.

```python
# jwt_multiauth/services.py (excerpt — signatures and exceptions only)
from dataclasses import dataclass
from datetime import datetime
from typing import Any


class TwoFactorUnavailable(Exception):
    """Raised by TwoFactorService.eligible_methods()'s caller-side check (the login-response
    helper, §5) when the intersection of enrolled methods, TWO_FACTOR.ALLOWED_METHODS, and the
    different-channel rule is empty. Views map this to 401 with details.code="two_factor_unavailable"
    (appkit's fixed error-code set has no dedicated top-level code for this — see §10)."""


class InvalidPendingToken(Exception):
    """Raised by TokenService.verify_pending_2fa_token() / TwoFactorService.verify_second_factor()
    for an expired, malformed, wrong-typ, or already-consumed pending token. Views map this to 401."""


class RefreshReuseDetected(Exception):
    """Raised by TokenService.rotate_refresh() when a superseded jti is presented. The triggering
    session is already revoked by the time this is raised. Views map this to 401."""


class ChallengeInvalid(Exception):
    """Raised by OtpService.verify() for a challenge_id that doesn't resolve, is expired, is
    already consumed, or has exhausted max_attempts. Deliberately the SAME exception (and the same
    view-level 400) for all four causes — see §10, don't let a decoy challenge_id's "doesn't
    resolve" case read differently from a real-but-expired challenge's case."""


@dataclass(frozen=True)
class TokenPair:
    access: str
    refresh: str
    session_id: str
    expires_at: datetime


@dataclass(frozen=True)
class OtpRequestResult:
    challenge_id: str
    expires_at: datetime
    resend_available_at: datetime


@dataclass(frozen=True)
class OtpVerifyResult:
    user: Any  # AbstractBaseUser — never a concrete import
    purpose: str


@dataclass(frozen=True)
class LockStatus:
    locked: bool
    until: datetime | None


@dataclass(frozen=True)
class TotpEnrollment:
    secret: str  # plaintext — the ONE moment this is ever returned
    otpauth_uri: str


class TokenService:
    @staticmethod
    def issue_token_pair(user: Any, *, request_meta: dict, remember_me: bool = False) -> TokenPair:
        """Creates a new AuthSession row and issues a fresh access+refresh pair. Fires
        user_logged_in with the real session_id. Never raises under normal operation."""
        ...

    @staticmethod
    def rotate_refresh(raw_refresh_token: str, *, request_meta: dict) -> TokenPair:
        """Raises RefreshReuseDetected if the presented jti is not the session's current_jti (the
        session is revoked as part of raising, not after). Raises InvalidPendingToken-shaped
        rejection (session revoked/expired/malformed) otherwise on any non-happy path. On success:
        rotates jti, increments rotation_count, issues a fresh pair, same session_id throughout."""
        ...

    @staticmethod
    def revoke_session(session_id: str, *, reason: str) -> None:
        """Idempotent — revoking an already-revoked session is a no-op, not an error. Fires
        session_revoked."""
        ...

    @staticmethod
    def revoke_all_sessions(user: Any, *, except_session_id: str | None = None, reason: str) -> int:
        """Returns the count revoked. Fires session_revoked once per row."""
        ...

    @staticmethod
    def verify_access_token(raw_token: str) -> dict:
        """Raises on any signature/exp/typ failure — typ must be 'access'. Never a database call
        beyond what claim verification itself needs."""
        ...

    @staticmethod
    def issue_pending_2fa_token(user: Any, *, primary_method: str, request_meta: dict) -> str:
        """typ='pending_2fa', short TTL from TWO_FACTOR.PENDING_TOKEN_TTL_SECONDS. Carries
        primary_method as a claim so verify_second_factor can enforce the different-channel rule
        without a second database round trip."""
        ...

    @staticmethod
    def verify_pending_2fa_token(token: str) -> dict:
        """Raises InvalidPendingToken on any signature/exp/typ failure — typ must be 'pending_2fa'."""
        ...


class OtpService:
    @staticmethod
    def request(identifier: str, *, channel: str, purpose: str) -> OtpRequestResult:
        """If identifier resolves to a real user for the given channel: honors
        SINGLE_ACTIVE_CHALLENGE, persists the row, fires the matching *_otp_requested signal with
        the plaintext code. If identifier does NOT resolve: computes an equivalent HMAC on a
        throwaway value (comparable CPU cost), returns an IDENTICAL OtpRequestResult shape with a
        fresh decoy uuid4 challenge_id — no database row, no signal. Never raises for an unknown
        identifier; the fail-closed rule (§0 item 3) applies to CREDENTIALS, not to whether an
        identifier exists, which is exactly what rule 5 protects."""
        ...

    @staticmethod
    def verify(challenge_id: str, *, code: str | None = None, link_token: str | None = None) -> OtpVerifyResult:
        """Raises ChallengeInvalid for: no such challenge_id (decoy or real-but-gone — identical),
        expired, already consumed, or attempts >= max_attempts (checked BEFORE the compare, so
        attempt max_attempts+1 is rejected even if it would have been correct). Uses
        otp.verify_secret (constant-time) for the actual compare; increments attempts on every
        failed compare. On success: consumed_at=now, fires otp_verified."""
        ...

    @staticmethod
    def resend(challenge_id: str) -> OtpRequestResult:
        """Raises ChallengeInvalid if the cooldown hasn't elapsed or MAX_RESENDS is exhausted.
        Reuses the same challenge_id/destination; generates a fresh code/hash/expires_at."""
        ...


class PasswordService:
    @staticmethod
    def authenticate(identifier: str, password: str) -> Any | None:
        """Resolves identifier against USER_FIELDS.IDENTIFIER_FIELDS in order. On ANY failure to
        resolve OR a resolved-but-wrong password, performs
        django.contrib.auth.hashers.check_password against a fixed dummy hash before returning
        None — this is what makes the unknown-identifier and wrong-password paths take the same
        time. Never raises; returns None on any failure."""
        ...

    @staticmethod
    def change_password(user: Any, old_password: str, new_password: str) -> None:
        """Raises on a wrong old_password or a new_password failing AUTH_PASSWORD_VALIDATORS. On
        success: fires password_changed, then UNCONDITIONALLY calls
        TokenService.revoke_all_sessions(user, reason="password_changed") — no settings flag
        disables this."""
        ...

    @staticmethod
    def request_reset(identifier: str) -> None:
        """Always returns, never raises, for ANY identifier including an unknown one. Delegates to
        OtpService.request(..., purpose="password_reset") and discards the result entirely — the
        view layer (§5) is what turns this into an unconditional 200."""
        ...

    @staticmethod
    def confirm_reset(
        challenge_id: str, *, code: str | None = None, link_token: str | None = None, new_password: str
    ) -> None:
        """Raises ChallengeInvalid (via OtpService.verify, purpose must be password_reset) or a
        password-validator failure. On success: sets the new password, fires password_changed, and
        revokes all sessions — same unconditional rule as change_password."""
        ...


class TwoFactorService:
    @staticmethod
    def eligible_methods(user: Any, *, used_primary_channel: str) -> list[str]:
        """Starts from TWO_FACTOR.ALLOWED_METHODS, intersects with the user's actually-enrolled
        methods (a confirmed TwoFactorDevice for totp; a resolvable VerifiedContact for
        email_otp/phone_otp). recovery_code is eligible only when the user has >=1 unused
        RecoveryCode AND at least one OTHER method is also eligible — recovery codes alone must
        never be the only offered second factor, since that would make them a second password
        rather than a true second factor. If TWO_FACTOR.REQUIRE_DIFFERENT_CHANNEL, removes
        used_primary_channel from the result — password counts as its own channel, distinct from
        email/phone, so email/phone 2FA is fully eligible after a password login. Never raises;
        an empty list is a valid, meaningful return — the CALLER (the login-response helper, §5)
        is what raises TwoFactorUnavailable on empty."""
        ...

    @staticmethod
    def enroll_totp(user: Any) -> TotpEnrollment:
        """Generates a fresh secret, encrypts it via appkit.crypto.Cipher before it ever touches
        the database, stores a TwoFactorDevice row with confirmed_at=None. Returns the PLAINTEXT
        secret and an otpauth:// URI — the only moment the plaintext secret is ever returned.
        Raises nothing under normal operation; a prior unconfirmed enrollment is silently replaced."""
        ...

    @staticmethod
    def confirm_totp(user: Any, *, code: str) -> None:
        """Raises if there is no pending (unconfirmed) enrollment, or if the device is already
        confirmed, or if the code doesn't verify against the decrypted secret within the
        configured drift window. On success: sets confirmed_at, fires two_factor_enabled."""
        ...

    @staticmethod
    def disable(user: Any, *, method: str) -> None:
        """Caller must already have passed the view-layer re-auth step (§5). Raises if no
        confirmed device/eligible method exists for that method. Fires two_factor_disabled."""
        ...

    @staticmethod
    def admin_force_disable(user: Any) -> None:
        """No re-auth requirement — the caller is a superuser acting on someone else's account.
        View-layer (§5) restricts this to an actual superuser regardless of
        ADMIN_REQUIRES_SUPERUSER. Fires two_factor_disabled."""
        ...

    @staticmethod
    def generate_recovery_codes(user: Any) -> list[str]:
        """Deletes any prior unused codes, generates TWO_FACTOR.RECOVERY_CODE_COUNT fresh codes via
        secrets, stores only their hashes. Returns the PLAINTEXT list once — never retrievable
        again, same rule as the TOTP secret."""
        ...

    @staticmethod
    def verify_second_factor(
        pending_token: str,
        *,
        method: str,
        code: str | None = None,
        link_token: str | None = None,
        trust_device: bool = False,
    ) -> TokenPair:
        """Raises InvalidPendingToken if the pending token itself doesn't verify. Re-derives
        eligible_methods for that same user/primary_method and raises TwoFactorUnavailable if the
        requested method is not in that FRESH set — this, not eligible_methods alone, is the actual
        enforcement point for the different-channel rule; a client-supplied method is NEVER
        trusted blindly. Verifies per-method (totp via pyotp with replay guard; email_otp/phone_otp
        via OtpService.verify(purpose="two_factor"); recovery_code via constant-time hash lookup
        iterating every unused candidate). On success: issues a TrustedDevice row+cookie if
        trust_device; calls TokenService.issue_token_pair for the real tokens; fires otp_verified
        only for the OTP-based methods."""
        ...


class VerificationService:
    @staticmethod
    def request_contact_verification(user: Any, *, field: str) -> OtpRequestResult:
        """Delegates to OtpService.request with purpose="verify_contact", destination = the user's
        CURRENT value for that field. No decoy path applies — the caller is already authenticated,
        so the identifier always resolves."""
        ...

    @staticmethod
    def confirm(user: Any, challenge_id: str, *, code: str) -> None:
        """Raises ChallengeInvalid (via OtpService.verify, purpose must be verify_contact). On
        success: get_or_creates a VerifiedContact row for (user, field, destination), fires
        contact_verified."""
        ...


class LockoutService:
    @staticmethod
    def record_attempt(identifier: str, *, ip: str, success: bool, reason: str | None = None) -> None:
        """Always writes a LoginAttempt row, success or not. On failure: increments an
        appkit.cache-backed counter keyed by LOCKOUT.LOCK_SCOPE within LOCKOUT.WINDOW_SECONDS, and
        fires account_locked the moment MAX_ATTEMPTS is reached for the active scope. Fires
        login_failed on every failure regardless of lock state."""
        ...

    @staticmethod
    def is_locked(identifier: str, *, ip: str) -> LockStatus:
        """Checked BEFORE PasswordService.authenticate/OtpService.verify are ever called, so a
        locked-out caller never reaches the dummy-hash path either. This does not reintroduce a
        timing side-channel: locked-vs-not-locked is not a secret about a SPECIFIC identifier's
        validity the way "which password is right" is."""
        ...

    @staticmethod
    def unlock(identifier: str) -> None:
        """Admin-only caller (§5). Resets the counter early. Idempotent."""
        ...
```

**Recovery-codes-alone rule, restated as a hard constraint (§11 item 14):** `eligible_methods`
never returns `["recovery_code"]` alone — verified by a dedicated test in Phase 7, not just stated
in the docstring above.

**Requires another app package: No** (`appkit.crypto.Cipher`/`generate_key` are the declared
dependency, `APP-DESIGN.md` §1.1's named exception).

---

## §5. Endpoints

Every view: a namespaced `throttle_scope` (literal string constants in `throttling.py` — see §11
item 1 for why `appkit.throttling.throttle_scope()` cannot be used), a complete `@extend_schema`,
`tags=["jwt-multiauth"]` (self-service) or `["jwt-multiauth-admin"]` (admin). No serializer ever
uses `fields = "__all__"`; no response ever exposes a password, a code, a `code_hash`, a
`token_hash`, or `secret_encrypted`.

**Enumeration resistance, stated once here and referenced by row:** every identifier-taking
endpoint below returns byte-for-byte the same status and body shape for "identifier doesn't
resolve" and "identifier resolves but the credential is wrong." The **Enum-resistant** column
states the mechanism, not just "yes."

### Self-service — `views_password.py`, `views_otp.py`, `views_token.py`, `views_twofactor.py`,
`views_session.py`, `views_account.py`. basePath `/api/v1/auth`.

| Method | Path | Permission | Throttle scope | Enum-resistant | Request → Response |
|---|---|---|---|---|---|
| `POST` | `/login/` | `AllowAny` | `jwt_multiauth_login` | Yes — `LockoutService.is_locked` checked first (reject before touching credentials at all if locked); otherwise `PasswordService.authenticate`'s dummy-hash path makes unknown-identifier and wrong-password identical. `401` either way, same body | `{identifier, password, remember_me?}` → `200 {access, session_id}` (no 2FA) or `200 {pending_token, eligible_methods}` (2FA required) — **never wrapped in appkit's error envelope**, this is not an error response |
| `POST` | `/password/change/` | `IsAuthenticated` | `jwt_multiauth_password_change` | N/A (authenticated) | `{old_password, new_password}` → `204`, or `400` (wrong old_password / validator failure) |
| `POST` | `/password/reset/request/` | `AllowAny` | `jwt_multiauth_password_reset_request` | Yes — `PasswordService.request_reset` always returns; view always responds `200` | `{identifier}` → `200 {}` unconditionally |
| `POST` | `/password/reset/confirm/` | `AllowAny` | `jwt_multiauth_password_reset_confirm` | Yes — an unresolved/expired/decoy `challenge_id` all produce the identical `ChallengeInvalid` → `400` | `{challenge_id, code? or link_token?, new_password}` → `204`, or `400` |
| `POST` | `/otp/request/` | `AllowAny` | `jwt_multiauth_otp_request` | Yes — `OtpService.request`'s identical-shape decoy path (§4); also rejects (`400`, not 401/404) a channel not in `ALLOWED_AUTH_METHODS` for purpose="login" | `{identifier, channel}` → `200 {challenge_id, expires_at, resend_available_at}` (real or decoy, indistinguishable), or `400` (channel not allowed) |
| `POST` | `/otp/verify/` | `AllowAny` | `jwt_multiauth_otp_verify` | Yes — same `ChallengeInvalid` shape for decoy/expired/wrong-code | `{challenge_id, code? or link_token?}` (exactly one required, magic-link lives here, not a separate view) → same login-response shape as `/login/`, or `400` |
| `POST` | `/otp/resend/` | `AllowAny` | `jwt_multiauth_otp_resend` | Yes — same `ChallengeInvalid` shape whether the challenge is real, decoy, or cooldown-blocked | `{challenge_id}` → `200 {challenge_id, expires_at, resend_available_at}`, or `400` |
| `POST` | `/token/refresh/` | `AllowAny` (reads the refresh cookie/body) | `jwt_multiauth_token_refresh` | N/A | — → `200 {access, session_id}`, re-sets cookie; `401` on reuse/expired/revoked (`refresh_reuse_detected` fires on reuse) |
| `POST` | `/token/verify/` | `AllowAny` (token is a body param — lets another service validate a token it received) | `jwt_multiauth_token_verify` | N/A | `{token}` → `200 {valid: true, claims}` or `200 {valid: false}` |
| `POST` | `/logout/` | `IsAuthenticated` | `jwt_multiauth_logout` | N/A | — → `204`, revokes the CALLER's current session only, clears cookies, fires `user_logged_out` |
| `POST` | `/logout/all/` | `IsAuthenticated` | `jwt_multiauth_logout_all` | N/A | — → `200 {revoked_count}` |
| `GET` | `/2fa/status/` | `IsAuthenticated` | `jwt_multiauth_2fa_status` | N/A | — → `200 {policy, enrolled_methods, eligible_methods}` |
| `POST` | `/2fa/totp/enroll/` | `IsAuthenticated` | `jwt_multiauth_2fa_totp_enroll` | N/A | — → `200 {secret, otpauth_uri}` |
| `POST` | `/2fa/totp/confirm/` | `IsAuthenticated` | `jwt_multiauth_2fa_totp_confirm` | N/A | `{code}` → `204`, or `400` |
| `POST` | `/2fa/disable/` | `IsAuthenticated`, re-auth required (password OR current 2FA code, decided and documented once here: **password re-entry**, since it's available regardless of which method is being disabled) | `jwt_multiauth_2fa_disable` | N/A | `{method, password}` → `204`, or `400`/`403` |
| `POST` | `/2fa/recovery-codes/regenerate/` | `IsAuthenticated`, re-auth required (password, same reasoning) | `jwt_multiauth_2fa_recovery_regenerate` | N/A | `{password}` → `200 {codes: [...]}` (plaintext, once) |
| `POST` | `/2fa/verify/` | `AllowAny` (gated by the pending token itself — intentionally reachable pre-full-login) | `jwt_multiauth_2fa_verify` | N/A (pending-token scoped, not identifier-scoped) | `{pending_token, method, code? or link_token?, trust_device?}` → `200 {access, session_id}`, or `401` (`TwoFactorUnavailable`/`InvalidPendingToken`) |
| `GET` | `/sessions/` | `IsAuthenticated` | `jwt_multiauth_sessions_list` | N/A | — → `200` paginated (`appkit.pagination.DefaultPagination`), CALLER's own `AuthSession` rows only, filtered at the queryset level |
| `DELETE` | `/sessions/{id}/` | `IsAuthenticated` + ownership check (own row only) | `jwt_multiauth_sessions_revoke` | N/A | — → `204`, or `404` if the session id doesn't belong to the caller (chosen over `403` — see §5 review note below) |
| `GET` | `/trusted-devices/` | `IsAuthenticated` | `jwt_multiauth_trusted_devices_list` | N/A | — → `200` paginated, CALLER's own `TrustedDevice` rows only |
| `DELETE` | `/trusted-devices/{id}/` | `IsAuthenticated` + ownership check | `jwt_multiauth_trusted_devices_revoke` | N/A | — → `204`, or `404` if not owned |
| `POST` | `/account/verify-contact/request/` | `IsAuthenticated` | `jwt_multiauth_verify_contact_request` | N/A (authenticated, no decoy needed) | `{field}` → `200 {challenge_id, expires_at, resend_available_at}` |
| `POST` | `/account/verify-contact/confirm/` | `IsAuthenticated` | `jwt_multiauth_verify_contact_confirm` | N/A | `{challenge_id, code}` → `204`, or `400` |
| `GET` | `/methods/` | `AllowAny` (unauthenticated discovery) | `jwt_multiauth_methods` — generous default rate, cached via `appkit.mixins.CachedListMixin` (static per deployment) | N/A | — → `200 {allowed_auth_methods, two_factor: {policy, allowed_methods}}` |

**Session/trusted-device ownership: `404`, not `403`, chosen and justified.** A `403` on another
user's session id confirms that id exists at all — a `404` (this app's choice) leaks nothing about
whether the id is valid, just revoked, or someone else's, matching rule 5's spirit even though this
is not an identifier-taking endpoint in the login sense.

### Admin — `admin_views.py`. basePath `/api/v1/admin/auth`.

| Method | Path | Extra gate | Throttle scope | Request → Response |
|---|---|---|---|---|
| `GET` | `/admin/sessions/` | admin gate (§0) | `jwt_multiauth_admin_sessions_list` | — → `200` paginated, filterable by `user` via `appkit.validation.validate_query_params`/`safe_filter_kwargs` |
| `DELETE` | `/admin/sessions/{id}/` | admin gate | `jwt_multiauth_admin_sessions_revoke` | — → `204`, any user's session |
| `GET` | `/admin/trusted-devices/` | admin gate | `jwt_multiauth_admin_trusted_devices_list` | — → `200` paginated, filterable by `user` |
| `DELETE` | `/admin/trusted-devices/{id}/` | admin gate | `jwt_multiauth_admin_trusted_devices_revoke` | — → `204`, any user's device |
| `GET` | `/admin/login-attempts/` | admin gate | `jwt_multiauth_admin_login_attempts_list` | — → `200` paginated, filterable by `identifier`/`ip_address`/`user`/`success` |
| `GET` | `/admin/users/{id}/security/` | admin gate | `jwt_multiauth_admin_user_security` | — → `200 {two_factor_status, active_session_count, lock_status}` — read-only aggregate, no model of its own |
| `POST` | `/admin/users/{id}/unlock/` | admin gate | `jwt_multiauth_admin_user_unlock` | — → `204` |
| `POST` | `/admin/users/{id}/2fa/force-disable/` | **`is_superuser`-only, UNCONDITIONALLY** — never gated by `ADMIN_REQUIRES_SUPERUSER`, never satisfied by plain `is_staff` even when that setting is `False` | `jwt_multiauth_admin_2fa_force_disable` | — → `204` |

**The admin gate**, resolved once from `JWT_MULTIAUTH["ADMIN_REQUIRES_SUPERUSER"]` in
`permissions.py`, is a single callable/class every `admin_views.py` view imports — never a
conditional repeated per view. **The force-disable-2FA gate is a SEPARATE, always-`is_superuser`
check**, never reusing the configurable admin gate, so that setting can never loosen this one
route no matter its value.

**Requires another app package: No.**

---

## §6. Settings

The full `JWT_MULTIAUTH` dict. Sub-dict names are frozen (`CLAUDE.md`'s semver-trigger list):
`TOKENS`, `REFRESH_COOKIE`, `OTP`, `TWO_FACTOR`, `LOCKOUT`, `PASSWORD`, `USER_FIELDS`. Plus
top-level `ALLOWED_AUTH_METHODS`, `ADMIN_REQUIRES_SUPERUSER`, `LOGIN_ATTEMPT_RETENTION_DAYS`.

**`TWO_FACTOR["POLICY"]` replaces the guide's `TWO_FACTOR["ENABLED"]` — see §11 item 1.** Every
later phase implements `POLICY`, not `ENABLED`; there is no `ENABLED` key in this app at all.

| Key | Default | Meaning |
|---|---|---|
| `ALLOWED_AUTH_METHODS` (top-level) | `["password"]` | The one method that works against any user model with zero delivery wiring. `checks.py` errors if `"phone_otp"`/`"email_otp"` is added but the matching `USER_FIELDS` entry doesn't resolve |
| `ADMIN_REQUIRES_SUPERUSER` (top-level) | `False` | `True` tightens every admin gate (except force-disable-2FA, always superuser-only) from `is_staff` to `is_superuser` |
| `LOGIN_ATTEMPT_RETENTION_DAYS` (top-level) | `90` | How long `tasks.purge_login_attempts` keeps `LoginAttempt` rows |
| `TOKENS.ACCESS_TTL_SECONDS` | `900` | Access token lifetime |
| `TOKENS.REFRESH_TTL_SECONDS` | `1209600` | Refresh/session lifetime when `remember_me=False` |
| `TOKENS.REMEMBER_ME_TTL_SECONDS` | `2592000` | Session lifetime when `remember_me=True` |
| `TOKENS.ALGORITHM` | `"HS256"` | JWT signing algorithm; `"RS256"`-ready via `JWT_MULTIAUTH_SIGNING_KEY` holding a private key |
| `REFRESH_COOKIE.TRANSPORT` | `"cookie"` | `"cookie"` (HttpOnly/Secure/SameSite, default) or `"body"` for native/non-browser clients |
| `REFRESH_COOKIE.NAME` | `"jwt_multiauth_refresh"` | Cookie name |
| `REFRESH_COOKIE.SAMESITE` | `"Lax"` | `SameSite` attribute |
| `REFRESH_COOKIE.SECURE` | `True` | `Secure` attribute — never `False` in this app's own default |
| `OTP.DEFAULTS.*` | see §2 | Purpose/channel-resolved via `get_otp_setting` |
| `TWO_FACTOR.POLICY` | `"off"` | `"off"` \| `"opt_in"` \| `"required"` \| `"staff_only"`. `"off"` — no 2FA is ever offered or required, regardless of `ALLOWED_METHODS`/enrollment |
| `TWO_FACTOR.ALLOWED_METHODS` | `["totp"]` | Subset of `totp`/`email_otp`/`phone_otp`/`recovery_code` |
| `TWO_FACTOR.REQUIRE_DIFFERENT_CHANNEL` | `True` | Never loosened silently — a `False` override must be an explicit host choice, documented as weakening enumeration/replay resistance |
| `TWO_FACTOR.PENDING_TOKEN_TTL_SECONDS` | `300` | Pending-2FA token lifetime |
| `TWO_FACTOR.RECOVERY_CODE_COUNT` | `10` | Codes generated per `generate_recovery_codes` call |
| `TWO_FACTOR.TOTP_DRIFT_WINDOW` | `1` | `pyotp` step-drift tolerance |
| `TWO_FACTOR.TRUSTED_DEVICE.ENABLED` | `False` | Master on/off for the skip-2FA cookie (§11 item 3 — nested here, not a new top-level sub-dict) |
| `TWO_FACTOR.TRUSTED_DEVICE.TTL_SECONDS` | `2592000` | Trusted-device cookie/row lifetime |
| `TWO_FACTOR.TRUSTED_DEVICE.COOKIE_NAME` | `"jwt_multiauth_td"` | Cookie name |
| `LOCKOUT.MAX_ATTEMPTS` | `5` | Failures within `WINDOW_SECONDS` before locking |
| `LOCKOUT.WINDOW_SECONDS` | `900` | Rolling window for `MAX_ATTEMPTS` |
| `LOCKOUT.LOCK_DURATION_SECONDS` | `900` | How long a lock lasts once triggered |
| `LOCKOUT.LOCK_SCOPE` | `"identifier_and_ip"` | `"identifier"` \| `"ip"` \| `"identifier_and_ip"` — see §10 for the trade-off (§11 item 10) |
| `PASSWORD.RESET_CHANNEL_PREFERENCE` | `["email", "phone"]` | Which `USER_FIELDS` channel `request_reset` prefers when both resolve (§11 item 8 — newly specified, guide left `PASSWORD` unspecified) |
| `PASSWORD.REQUIRE_OLD_PASSWORD_ON_CHANGE` | `True` | Never disableable by a host — documented as a rail, not a toggle (§11 item 8) |
| `PASSWORD.REVOKE_SESSIONS_ON_CHANGE` | `True` | Never disableable by a host — `PasswordService.change_password`/`confirm_reset` call `revoke_all_sessions` unconditionally regardless of this key's presence; the key exists to be *read* for README clarity, not to gate the behavior |
| `USER_FIELDS.EMAIL_FIELD` | `None` | Required (checks.py error) iff `"email_otp"` is in `ALLOWED_AUTH_METHODS` or `TWO_FACTOR.ALLOWED_METHODS` |
| `USER_FIELDS.PHONE_FIELD` | `None` | Required (checks.py error) iff `"phone_otp"` is in either list above |
| `USER_FIELDS.IDENTIFIER_FIELDS` | `["username", "email"]` | Order `PasswordService.authenticate` tries when resolving a login identifier (§11 item 5 — named by the guide's Phase 5, missing from its settings list) |

**Interactions:**

- `ALLOWED_AUTH_METHODS` includes `"phone_otp"` but `USER_FIELDS.PHONE_FIELD` doesn't resolve on
  `get_user_model()` → `checks.py` error at `manage.py check` time, never a runtime `500` (rule 2).
- `TWO_FACTOR.REQUIRE_DIFFERENT_CHANNEL` leaves a user with zero eligible methods →
  `TwoFactorUnavailable`, login fails outright — never degrades to single-factor (rule 3).
- `TWO_FACTOR.POLICY != "off"` and `"totp"` in `ALLOWED_METHODS` but `JWT_MULTIAUTH_ENCRYPTION_KEY`
  is unset → `checks.py` error (guide Phase 1 step 6).

`.env` keys: **one conditionally required**, `JWT_MULTIAUTH_ENCRYPTION_KEY` (Fernet key via
`appkit.crypto.generate_key()`) — required only when `TWO_FACTOR.POLICY != "off"` and `"totp"` is
in `TWO_FACTOR.ALLOWED_METHODS`, and **never** derived from `SECRET_KEY` even as a convenience
default. Two optional, HKDF-derived from `SECRET_KEY` when unset: `JWT_MULTIAUTH_SIGNING_KEY`,
`JWT_MULTIAUTH_OTP_PEPPER` (distinct HKDF `info` strings, so the two derived values are
cryptographically independent of each other despite sharing a root secret).

**Requires another app package: No.**

---

## §7. Frontend hooks + the token-manager trio

Two config hooks, two managers, two key-factory roots — one per basePath (`jwt_multiauth`,
`jwt_multiauth_admin`) — neither manager nor either config hook exported from `index.ts`.

### Self-service

| Hook | Wraps | Query key | Invalidation |
|---|---|---|---|
| `useLogin()` | `POST /login/` | — (mutation, **never fires on mount**) | — |
| `useOtpRequest()` | `POST /otp/request/` | — (mutation, never fires on mount) | — |
| `useOtpVerify()` | `POST /otp/verify/` | — (mutation, never fires on mount) | — |
| `useOtpResend()` | `POST /otp/resend/` | — (mutation, never fires on mount) | — |
| `usePasswordChange()` | `POST /password/change/` | — (mutation, never fires on mount) | — |
| `usePasswordResetRequest()` | `POST /password/reset/request/` | — (mutation, never fires on mount) | — |
| `usePasswordResetConfirm()` | `POST /password/reset/confirm/` | — (mutation, never fires on mount) | — |
| `useLogout()` | `POST /logout/` | — (mutation, never fires on mount) | `jwtMultiauthKeys.sessions()` |
| `useLogoutAll()` | `POST /logout/all/` | — (mutation, never fires on mount) | `jwtMultiauthKeys.sessions()` |
| `useSessions()` | `GET /sessions/` | `jwtMultiauthKeys.sessions()` | — (query) |
| `useRevokeSession()` | `DELETE /sessions/{id}/` | — (mutation, **never fires on mount**) | `jwtMultiauthKeys.sessions()` |
| `useTrustedDevices()` | `GET /trusted-devices/` | `jwtMultiauthKeys.trustedDevices()` | — (query) |
| `useRevokeTrustedDevice()` | `DELETE /trusted-devices/{id}/` | — (mutation, never fires on mount) | `jwtMultiauthKeys.trustedDevices()` |
| `useAuthMethods()` | `GET /methods/` | `jwtMultiauthKeys.methods()` | — (query) |
| `useTwoFactorStatus()` | `GET /2fa/status/` | `jwtMultiauthKeys.twoFactorStatus()` | — (query) |
| `useEnrollTotp()` | `POST /2fa/totp/enroll/` | — (mutation, never fires on mount) | — |
| `useConfirmTotp()` | `POST /2fa/totp/confirm/` | — (mutation, never fires on mount) | `jwtMultiauthKeys.twoFactorStatus()` |
| `useDisableTwoFactor()` | `POST /2fa/disable/` | — (mutation, never fires on mount) | `jwtMultiauthKeys.twoFactorStatus()` |
| `useRegenerateRecoveryCodes()` | `POST /2fa/recovery-codes/regenerate/` | — (mutation, never fires on mount) | — |
| `useVerifyTwoFactor()` | `POST /2fa/verify/` | — (mutation, never fires on mount) | — |
| `useRequestContactVerification()` | `POST /account/verify-contact/request/` | — (mutation, never fires on mount) | — |
| `useConfirmContactVerification()` | `POST /account/verify-contact/confirm/` | — (mutation, never fires on mount) | — |

### Admin

| Hook | Wraps | Query key | Invalidation |
|---|---|---|---|
| `useAdminSessions(params?)` | `GET /admin/sessions/` | `jwtMultiauthAdminKeys.sessions(params)` | — (query) |
| `useAdminRevokeSession()` | `DELETE /admin/sessions/{id}/` | — (mutation, never fires on mount) | `jwtMultiauthAdminKeys.sessions()` |
| `useAdminTrustedDevices(params?)` | `GET /admin/trusted-devices/` | `jwtMultiauthAdminKeys.trustedDevices(params)` | — (query) |
| `useAdminRevokeTrustedDevice()` | `DELETE /admin/trusted-devices/{id}/` | — (mutation, never fires on mount) | `jwtMultiauthAdminKeys.trustedDevices()` |
| `useAdminLoginAttempts(params?)` | `GET /admin/login-attempts/` | `jwtMultiauthAdminKeys.loginAttempts(params)` | — (query) |
| `useAdminUserSecurity(userId)` | `GET /admin/users/{id}/security/` | `jwtMultiauthAdminKeys.userSecurity(userId)` | — (query) |
| `useAdminUnlockUser()` | `POST /admin/users/{id}/unlock/` | — (mutation, never fires on mount) | `jwtMultiauthAdminKeys.userSecurity()` |
| `useAdminForceDisableTwoFactor()` | `POST /admin/users/{id}/2fa/force-disable/` | — (mutation, **never fires on mount**) | `jwtMultiauthAdminKeys.userSecurity()` |

`useTrustedDevices`/`useRevokeTrustedDevice` and their admin equivalents are added beyond the
guide's item 7 list (§11 item 2 — dedicated endpoints, decided with the user). `useAuthState` is
added beyond the guide's list too (§11 item 13 — Phase 10 mandates it, item 7 omitted it).

### The manager/hook two-layer split

`api/manager.ts` exports `JwtMultiauthManager`/`JwtMultiauthAdminManager` — plain, instance-based,
constructor takes `HttpClient` + `basePath`, never exported from `index.ts`. Hooks are thin
`@tanstack/react-query` wrappers, per `APP-DESIGN.md` §12's "Manager & hook conventions" —
identical shape to every other app in this ecosystem.

### The token-manager trio's contract

- **`authStore.ts`** — a **module singleton**, not a hook or context (must be readable from
  `authHeaderSource`, which runs outside React). Public shape: `getAccessToken(): string | null`,
  `setAccessToken(token: string | null, expiresAt: number | null): void`,
  `subscribe(listener: () => void): () => void`, `clear(): void`. Token lives in a closure
  variable — **never** `localStorage`/`sessionStorage`, never a cookie the frontend itself sets
  (the refresh cookie is HttpOnly, backend-set only). Cross-tab awareness via `BroadcastChannel`,
  broadcasting **events** (`"logged-out"`, `"token-refreshed"`) never the token itself — every tab
  re-derives its own access token by calling refresh against the shared HttpOnly cookie.
  `useAuthState()` wraps `subscribe()` via `useSyncExternalStore`.
- **`authHeaderSource.ts`** — a stable, module-scope value of appkit's own `HeaderSource` type,
  **verbatim**: `export type HeaderSource = () => HeadersInit | Promise<HeadersInit>;`
  (`appkit/frontend/src/client.ts`). Reads `authStore`'s current token; if missing or inside the
  configured skew window, calls the refresh manager **before** returning headers — per appkit
  CONTRACT §16 rule 5's "a source doing a synchronous refresh-if-expired check before returning" —
  with single-flight deduplication (one module-level in-flight promise; N concurrent callers during
  a refresh trigger exactly one network call). Returns `{}` (no `Authorization` header) rather
  than throwing when there is genuinely no session — appkit CONTRACT §16 rule 4 requires a header
  source to fail **loudly** on a real bug, and "not logged in" is explicitly not a bug; the two are
  distinguished in the implementation, not conflated.
- **`withAuthRetry.ts`** — `withAuthRetry(client: HttpClient): HttpClient`, an `HttpClient`
  decorator: a `401` triggers exactly one refresh attempt and one retry of the original call; a
  second `401` (refresh itself failed, or the retry also `401`s) propagates the error and calls
  `authStore.clear()` + broadcasts `"logged-out"`. **This is the concrete satisfaction of appkit
  CONTRACT §J's explicit assignment of retry-on-401 to the host's concrete client** — appkit itself
  contains no retry-on-401 mechanism anywhere (§16 rule 6), and this app's own README (Phase 12)
  states that fact so a host never expects appkit to provide it.

`index.ts` exports the hooks, both key factories, this app's own types, **and** — the deliberate,
documented exception to "never export the manager/config hook" — `useAuthState`,
`authHeaderSource`, and `withAuthRetry`: host wiring a host cannot construct itself, unlike the
managers, which stay internal.

**Requires another app package: No** (`appkit`'s `HttpClient`/`HeaderSource`/`ApiClientProvider`/
`useApiClient` are the declared peer-dependency exception).

---

## §8. `tasks.py` (celery extra only)

```python
# jwt_multiauth/tasks.py (excerpt — signatures only; behind the celery extra)
from celery import shared_task


@shared_task(name="jwt_multiauth.tasks.purge_expired_otp_challenges")
def purge_expired_otp_challenges() -> int:
    """Deletes OtpChallenge rows well past expires_at. Continues past a single row's failure
    rather than aborting the batch. Returns the count purged."""
    ...


@shared_task(name="jwt_multiauth.tasks.purge_expired_sessions")
def purge_expired_sessions() -> int:
    """Deletes AuthSession rows well past expires_at ONLY — never a merely-revoked-but-not-yet-
    expired row, since an admin/support agent may still want to see it. Returns the count purged."""
    ...


@shared_task(name="jwt_multiauth.tasks.purge_login_attempts")
def purge_login_attempts() -> int:
    """Deletes LoginAttempt rows older than LOGIN_ATTEMPT_RETENTION_DAYS. Returns the count purged."""
    ...


@shared_task(name="jwt_multiauth.tasks.purge_expired_trusted_devices")
def purge_expired_trusted_devices() -> int:
    """Deletes TrustedDevice rows well past expires_at. Returns the count purged."""
    ...
```

Recommended schedule: `purge_expired_otp_challenges` — every 15 minutes; `purge_expired_sessions` —
daily at 03:00; `purge_login_attempts` — daily at 03:15; `purge_expired_trusted_devices` — daily at
03:30. Each has a matching `management/commands/` entry (`purge_expired_otp_challenges`,
`purge_expired_sessions`, `purge_login_attempts`, `purge_expired_trusted_devices`) calling the same
underlying query the task calls, never duplicating it, for a host running no Celery worker.

**Requires another app package: No.**

---

## §9. Dependencies

```toml
# backend/pyproject.toml (excerpt)
[project]
dependencies = [
    "django>=5.2,<7.0",
    "djangorestframework>=3.15,<4.0",
    "drf-spectacular>=0.27,<1.0",
    "hjtdev-appkit>=2.0,<3.0",
    "pyjwt>=2.9,<3.0",
]

[project.optional-dependencies]
totp = ["pyotp>=2.9,<3.0", "hjtdev-appkit[crypto]>=2.0,<3.0"]
channels = ["channels>=4.1,<5.0"]
celery = ["celery[redis]>=5.4,<6.0", "django-celery-beat>=2.7,<3.0"]
```

`hjtdev-appkit[crypto]` **verified against real installed source** (§11 item 12): appkit
2.0.2's `pyproject.toml` declares exactly two extras, `crypto` (`cryptography>=42,<51`) and
`images` (`pillow>=11.3,<13`) — `crypto` is confirmed correct, not assumed. `django`/`djangorestframework`/
`drf-spectacular` are wide ranges per `APP-DESIGN.md` §1.1 (shared-platform dependencies); `pyjwt`
and `pyotp` are app-private but still ranged, never `==`, per the same rule.

```json
// frontend/package.json (excerpt)
{
  "peerDependencies": {
    "react": ">=18",
    "@tanstack/react-query": ">=5",
    "@hjtdev/appkit": ">=2.0.0 <3.0.0"
  },
  "devDependencies": {
    "openapi-typescript": "^7.13.0"
  }
}
```

**Requires another app package: No** for either half.

---

## §10. Security invariants

This section consolidates the app-wide proofs `docs/CLAUDE-CODE-GUIDE-APP-JWT-MULTIAUTH.md`'s
review gates and definition-of-done demand, so a later phase (and Phase 13's
`docs/SECURITY-CHECKLIST.md`) checks against one place rather than re-deriving each from scratch.

**No token before 2FA completes, under any settings combination.** The only code path issuing a
real `TokenPair` when `TWO_FACTOR.POLICY != "off"` and `TwoFactorService.eligible_methods` returns
non-empty is `TwoFactorService.verify_second_factor`, which **re-derives** `eligible_methods`
server-side and rejects (`TwoFactorUnavailable`) a client-claimed `method` not in that freshly
computed set — a client is never trusted to self-report which method it satisfied.
`TrustedDevice` is the one documented, intentional bypass: its cookie is checked **before** 2FA is
even offered, and it is itself a hashed bearer secret with its own revocation surface (§1, §5) —
not a silent downgrade, a deliberate, revocable, auditable skip.

**Enumeration resistance is proven per identifier-taking endpoint** (§5's Enum-resistant column),
via one of two mechanisms: (a) a dummy constant-time hash computation on the no-such-identifier
path (`PasswordService.authenticate`), or (b) an identical-shape decoy response with zero
persistence and zero signal dispatch (`OtpService.request`). `OtpService.verify` collapses "no such
challenge_id" (real or decoy) and "expired" and "already consumed" into the single `ChallengeInvalid`
exception, so a client can never distinguish "this was a decoy" from "this expired."

**`LOCKOUT.LOCK_SCOPE`'s trade-off, stated explicitly (§11 item 10):** `"identifier"` alone lets
one malicious IP lock out an arbitrary victim account by repeatedly failing their username from
many source IPs — a pure denial-of-service against a specific person, requiring no knowledge
beyond their username. `"ip"` alone doesn't protect a single high-value account under distributed
credential stuffing (many IPs, one target). The default, `"identifier_and_ip"`, requires the
*same* IP to fail the *same* identifier repeatedly, closing the first attack while still limiting
the second per-source. All three modes are implemented and independently tested (Phase 5); a host
choosing `"identifier"` alone is knowingly accepting the single-victim DoS risk above.

**No secret is ever stored recoverably; every comparison is constant-time; every generator is
`secrets`.** `otp.hash_secret`/`otp.verify_secret` (HMAC-SHA256 via `hmac.compare_digest`) is the
ONE hashing scheme for every OTP code, link token, recovery code, and trusted-device token in this
app — no second scheme anywhere. `appkit.crypto.Cipher` (Fernet) encrypts TOTP secrets, keyed by
`JWT_MULTIAUTH_ENCRYPTION_KEY`, never `SECRET_KEY`-derived. Proven per Phase 13's definition of
done by an actual database-row inspection, not by reading the model/service code that claims it.

**Refresh rotation is family-based and reuse detection is unconditional.** `AuthSession.current_jti`
is replaced on every successful refresh; presenting an already-superseded `jti` revokes the
**entire session** immediately (`refresh_reuse_detected` fires) — never just the offending token.
There is no settings flag that disables this.

**appkit's error-code set is a fixed ten** (`appkit/backend/src/appkit/exceptions.py`,
`ERROR_CODES`) and this app never adds an eleventh. `two_factor_unavailable`,
`refresh_reuse_detected` (as a client-visible reason), `otp_challenge_invalid`, and any other
app-specific failure identity are **`details.code`** values under one of appkit's existing
top-level codes (typically `"authentication_failed"` or `"validation_error"` — the exact mapping
is a `views_*.py` concern, not a new top-level code ever) — envelope shape
`{"error": {"code", "message", "details", "request_id"}}`, unchanged from appkit's own contract
(§11 item 9).

**A password change/reset revokes every OTHER session, unconditionally.**
`PasswordService.change_password`/`.confirm_reset` both call
`TokenService.revoke_all_sessions(..., reason="password_changed")` — `PASSWORD.REVOKE_SESSIONS_ON_CHANGE`
exists for README clarity, not as a disable switch (§6).

**Requires another app package: No** — this section is prose consolidating rules already stated
against this app's own models/services above.

---

## §11. Deviations register

Everything not listed here is unchanged from
`docs/CLAUDE-CODE-GUIDE-APP-JWT-MULTIAUTH.md`'s Phase 0 prompt.

1. **`TWO_FACTOR["POLICY"]` replaces `TWO_FACTOR["ENABLED"]` entirely — confirmed with the user.**
   The guide's own §1 table specifies a four-value policy string
   (`off`/`opt_in`/`required`/`staff_only`), but Phase 1 step 6, Phase 7's test-override
   instructions, and Phase 11's playground spec all literally say `TWO_FACTOR["ENABLED"] = True`.
   Two settings that can disagree (`ENABLED=True` + `POLICY="off"`) is exactly the class of config
   rule 3 (fail closed, no ambiguity) exists to avoid. `POLICY` alone, with `"off"` meaning
   disabled, is the single source of truth; there is no `ENABLED` key anywhere in this app.
2. **Trusted devices get dedicated endpoints and hooks — confirmed with the user.** The guide's
   §1 "design facts" state `TrustedDevice` "is itself revocable per-device from both the
   self-service and admin session surfaces," but Phase 0 item 5's endpoint list and item 7's hook
   list name none. Added: `GET/DELETE /trusted-devices/[{id}/]` and the admin pair (§5), plus
   `useTrustedDevices`/`useRevokeTrustedDevice`/`useAdminTrustedDevices`/
   `useAdminRevokeTrustedDevice` (§7).
3. **`TWO_FACTOR["TRUSTED_DEVICE"]` is a sub-dict nested inside `TWO_FACTOR`, not a new top-level
   sub-dict — confirmed with the user.** Keeps `CLAUDE.md`'s frozen semver-trigger sub-dict list
   (`TOKENS`/`REFRESH_COOKIE`/`OTP`/`TWO_FACTOR`/`LOCKOUT`/`PASSWORD`/`USER_FIELDS`) accurate with
   no edit required to `CLAUDE.md` itself.
4. **`OtpChallenge` gains `resend_count`, `last_sent_at`, `max_resends`.** The guide's item 2
   (`RESEND_COOLDOWN_SECONDS`/`MAX_RESENDS`) and Phase 4's `OtpService.resend` are unenforceable
   against the guide's item-1 field list as written — `created_at` alone cannot express "cooldown
   since the *second* send." `max_resends` is snapshotted at creation for the same reason
   `max_attempts` already was in the guide.
5. **`USER_FIELDS["IDENTIFIER_FIELDS"]` added**, default `["username", "email"]` — named by the
   guide's Phase 5 (`PasswordService.authenticate` "resolves identifier against
   USER_FIELDS.IDENTIFIER_FIELDS in order") but absent from item 6's `USER_FIELDS` list.
6. **`LOGIN_ATTEMPT_RETENTION_DAYS` added as a third top-level key**, alongside
   `ALLOWED_AUTH_METHODS` and `ADMIN_REQUIRES_SUPERUSER` — named by the guide's item 8
   (`purge_login_attempts` "respecting `JWT_MULTIAUTH["LOGIN_ATTEMPT_RETENTION_DAYS"]`") but
   absent from item 6's settings list.
7. **`account_locked` payload refined** to `user_id: int | None, identifier: str, until: datetime,
   scope: str` from the guide's `account_locked(user_id, until, scope)`. An IP-scoped lock, or a
   lock triggered by an identifier that never resolved, has no `user_id` at all; without
   `identifier` a host receiver has nothing to act on.
8. **`PASSWORD` sub-dict newly specified — the guide's item 6 left it entirely unstated.** Added
   `RESET_CHANNEL_PREFERENCE`, `REQUIRE_OLD_PASSWORD_ON_CHANGE` (documented as non-loosenable),
   `REVOKE_SESSIONS_ON_CHANGE` (documented as non-disableable, per the guide's Phase 5 hard
   requirement that `change_password`/`confirm_reset` always revoke other sessions).
9. **appkit's error-`code` set is a fixed ten, and this app never adds an eleventh** — read from
   `appkit/backend/src/appkit/exceptions.py:ERROR_CODES` (mirrored in `frontend/src/errors.ts`),
   confirmed against appkit's own `CONTRACT.md` §1's "domain-specific error identities belong in
   `details`, never a new top-level `code`." This changes an implicit assumption in the guide's
   phase prompts (which speak of e.g. `two_factor_unavailable` as if it might be a `code`) — see
   §10 for the corrected mapping.
10. **`LOCKOUT["LOCK_SCOPE"]` defaults to `"identifier_and_ip"`, with the single-victim-DoS
    trade-off of `"identifier"`-alone stated explicitly** — directly answering this guide's own
    Phase 0 review gate about `LOCK_SCOPE`. See §10 for the full argument. All three modes
    (`"identifier"`, `"ip"`, `"identifier_and_ip"`) are implemented; none is silently dropped.
11. **`OtpChallenge.user` is nullable in the schema but never actually null in v1.0.0.** The
    guide's item 1 specifies nullable *and* that nothing ever persists a decoy row — both are true
    simultaneously: the field allows it structurally (so a future purpose needing an unresolved-
    user row isn't blocked at the schema level) but no code path in this app ever writes
    `user=None`. Recorded explicitly so a later phase doesn't "helpfully" start writing decoy rows,
    which would defeat the whole point of the decoy design (§4, §10).
12. **appkit's `crypto` extra name verified as literally `crypto`, not assumed** — read directly
    from `appkit/backend/pyproject.toml`'s `[project.optional-dependencies]` (`crypto`, `images`
    are the only two). appkit is at 2.0.2 on both halves as of this writing.
13. **`useAuthState()` added to the frontend hook list** — the guide's Phase 10 mandates a
    `useSyncExternalStore`-based hook over `authStore.subscribe()`, but the guide's item 7 hook
    enumeration omits it.
14. **Recovery codes are never the only offered second factor — restated as a hard constraint in
    `services.py`'s docstring, not just the guide's prose** (§4). A dedicated test (Phase 7) proves
    `eligible_methods` never returns `["recovery_code"]` alone.
15. **Guide typo noted, not corrected here:** `ALLOWED_METHODDS` at
    `docs/CLAUDE-CODE-GUIDE-APP-JWT-MULTIAUTH.md:59` (a local file to this repo, not a symlink into
    `ecosystem-docs`) — fixable directly in a later phase without touching the shared docs.

---

## §12. Semver triggers (restated against this file's own frozen names)

Per `CLAUDE.md`'s own list, restated against §0–§9's exact names — every one needs a **Host
action:** line in `CHANGELOG.md`, per `CLAUDE.md`:

- Removing/renaming any signal in §3, a `services.py` method signature in §4, an exported hook in
  §7, or a field on any model in §1 a host might query.
- Renaming a `JWT_MULTIAUTH` key — top-level (`ALLOWED_AUTH_METHODS`, `ADMIN_REQUIRES_SUPERUSER`,
  `LOGIN_ATTEMPT_RETENTION_DAYS`) or inside any sub-dict (`TOKENS`/`REFRESH_COOKIE`/`OTP`/
  `TWO_FACTOR`/`LOCKOUT`/`PASSWORD`/`USER_FIELDS`, including `TWO_FACTOR.TRUSTED_DEVICE`'s own
  keys, per §11 item 3).
- Adding to or removing from the closed `ALLOWED_AUTH_METHODS` / `TWO_FACTOR.ALLOWED_METHODS`
  string sets.
- Changing a token's claim shape, `TOKENS.ALGORITHM`'s default, `REFRESH_COOKIE`'s default
  attributes, or what a `details.*` key means for any existing appkit `code` (§10).
- Weakening a default safety rail — `TWO_FACTOR.REQUIRE_DIFFERENT_CHANNEL`'s default,
  `LOCKOUT`'s default thresholds or `LOCK_SCOPE`, `OTP.DEFAULTS.TTL_SECONDS` downward-implicitly-
  permissively, `ADMIN_REQUIRES_SUPERUSER`'s default, or `PASSWORD.REQUIRE_OLD_PASSWORD_ON_CHANGE`/
  `.REVOKE_SESSIONS_ON_CHANGE` ever becoming an actual disable switch.
- Renaming the published distribution names (`django-jwt-multiauth` / `@hjtdev/django-jwt-multiauth`).

### Open items — deliberately not resolved in Phase 0

- **`TWO_FACTOR.TOTP_DRIFT_WINDOW`'s exact default (`1`)** — a reasonable starting value; revisit
  once a real playground device (Phase 11) proves whether clock drift in practice needs more.
- **Whether `PASSWORD.RESET_CHANNEL_PREFERENCE` should be per-user configurable** rather than a
  single host-wide default — not added here; revisit if a real host asks for it.
- **Rate-limit numeric defaults throughout §5/§6** are starting points, not load-tested — revisit
  once the playground (Phase 11) exercises them under something resembling real traffic.

---

Per §0–§10: **Requires another app package: No** for every one, `hjtdev-appkit` named as the single
declared exception (`APP-DESIGN.md` §1.1), exactly as this guide's five rails and
`APP-DESIGN.md` §6 require.
