"""This app's public callable interface — the ONLY place a token is issued/rotated, an OTP
challenge is created/verified, a password is changed/reset, a 2FA method is enrolled/verified/
disabled, or a lockout is checked/recorded.

``docs/CONTRACT.md`` §4 specifies this module in full: ``TokenService`` (Phase 3, implemented in
full below), ``OtpService`` (Phase 4), ``PasswordService``/``TwoFactorService``/
``VerificationService``/``LockoutService`` (Phase 5) — plus every exception class this module
raises and the frozen dataclasses it returns.

Every model reference is resolved through ``settings.AUTH_USER_MODEL``/``get_user_model()`` at
call time, never a concrete import (this repo's ``CLAUDE.md`` rule 1). Recovery codes are never
the only offered second factor — ``eligible_methods`` never returns ``["recovery_code"]`` alone,
a hard constraint restated here per ``docs/CONTRACT.md`` §11 item 14, proven by a dedicated
Phase 7 test.

A ``services.py`` method signature is frozen the moment it ships — changing one is a MAJOR
version bump with a ``Host action:`` line in ``CHANGELOG.md`` (this repo's ``CLAUDE.md``
semver-trigger list).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final, TypedDict, cast

from appkit.cache import build_cache_key, invalidate_namespace
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.password_validation import validate_password
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.module_loading import import_string

from jwt_multiauth import conf, keys, otp, tokens
from jwt_multiauth.models import AuthSession, LoginAttempt, OtpChallenge, VerifiedContact
from jwt_multiauth.signals import (
    account_locked,
    contact_verified,
    email_otp_requested,
    login_failed,
    otp_verified,
    password_changed,
    phone_otp_requested,
    refresh_reuse_detected,
    session_revoked,
    user_logged_in,
    user_provisioned,
)

#: Mirrors AuthSession.revoked_reason's choices (models.py) — kept as a literal here rather than
#: introspected off the field, since this app's own model shape is not the kind of arbitrary,
#: host-defined thing checks.py has to introspect for the user model.
_VALID_REVOKE_REASONS = frozenset(
    {"user_logout", "admin_revoked", "reuse_detected", "password_changed", "expired"}
)


class RequestMeta(TypedDict, total=False):
    """Per-request metadata TokenService needs for AuthSession bookkeeping and audit signals.
    ``ip`` and ``method`` are required in practice by :func:`_require` wherever a method actually
    uses them — ``total=False`` only reflects that not every TokenService method needs every key
    (``issue_pending_2fa_token`` accepts this shape but reads none of it yet).
    """

    ip: str
    user_agent: str
    device_label: str
    method: str


def _require(request_meta: RequestMeta, key: str) -> str:
    """A missing required ``request_meta`` key is a caller bug, not a host-facing failure —
    rule 3 (fail closed) applied to this module's own callers rather than an end user's request.
    """
    # request_meta.get(key) with a non-literal `key` erases to `object` under mypy strict — every
    # RequestMeta value is a str by construction, so this cast just states that back explicitly.
    value = cast("str | None", request_meta.get(key))
    if not value:
        raise ValueError(f"request_meta[{key!r}] is required.")
    return value


@dataclass(frozen=True)
class TokenPair:
    access: str
    refresh: str
    session_id: str
    expires_at: datetime


class InvalidPendingToken(Exception):
    """Raised by TokenService.verify_pending_2fa_token() / TwoFactorService.verify_second_factor()
    for an expired, malformed, wrong-typ, or already-consumed pending token. Views map this to 401.
    """


class RefreshReuseDetected(Exception):
    """Raised by TokenService.rotate_refresh() when a superseded jti is presented. The triggering
    session is already revoked by the time this is raised. Views map this to 401.
    """


class InvalidRefreshToken(Exception):
    """Raised by TokenService.rotate_refresh() for a malformed/expired/wrong-typ refresh token, or
    a session that is revoked or expired. Views map this to 401. NOT raised for reuse — see
    RefreshReuseDetected.
    """


class ChallengeInvalid(Exception):
    """Raised by OtpService.verify()/resend() for a challenge_id that doesn't resolve, is
    expired, is already consumed, has exhausted max_attempts, or (resend only) hasn't cleared its
    resend cooldown or has exhausted max_resends. Deliberately the SAME exception (and the same
    view-level 400, details.code="otp_challenge_invalid") for every one of these causes — a decoy
    challenge_id's "doesn't resolve" case must read identically to a real-but-expired challenge's
    case (docs/CONTRACT.md §10).
    """


@dataclass(frozen=True)
class OtpRequestResult:
    challenge_id: str
    expires_at: datetime
    resend_available_at: datetime


@dataclass(frozen=True)
class OtpVerifyResult:
    user: Any  # AbstractBaseUser — never a concrete import
    purpose: str
    created: bool  # True only when THIS call provisioned the user (docs/CONTRACT.md §11 item
    # 19) — the shared login-response helper (Phase 6) reads this to apply the 2FA-bootstrap
    # carve-out and to set the response's own created field. False on every non-auto-provisioning
    # path.


@dataclass(frozen=True)
class LockStatus:
    locked: bool
    until: datetime | None


class TokenService:
    """Token issuance, refresh rotation, and session revocation — ``docs/CONTRACT.md`` §4, fully
    implemented in Phase 3. Built on ``tokens.py`` (pure PyJWT) plus ``AuthSession`` (Phase 2).
    """

    @staticmethod
    def issue_token_pair(
        user: Any, *, request_meta: RequestMeta, remember_me: bool = False
    ) -> TokenPair:
        """Creates a new AuthSession row and issues a fresh access+refresh pair. Fires
        user_logged_in with the real session_id. Never raises under normal operation.
        """
        ip = _require(request_meta, "ip")
        method = _require(request_meta, "method")

        tokens_conf = conf.get_setting("TOKENS")
        ttl_seconds = (
            tokens_conf["REMEMBER_ME_TTL_SECONDS"]
            if remember_me
            else tokens_conf["REFRESH_TTL_SECONDS"]
        )
        session = AuthSession.objects.create(
            user=user,
            current_jti=tokens.generate_jti(),
            ip_address=ip,
            user_agent=request_meta.get("user_agent", "")[:512],
            device_label=request_meta.get("device_label", "")[:255],
            remember_me=remember_me,
            expires_at=timezone.now() + timedelta(seconds=ttl_seconds),
        )

        pair = TokenService._issue_pair(session)
        user_logged_in.send(
            sender=AuthSession, user_id=user.pk, session_id=str(session.id), method=method
        )
        return pair

    @staticmethod
    def _issue_pair(session: AuthSession) -> TokenPair:
        """Issues an access+refresh pair for an EXISTING session row — shared by
        issue_token_pair (a brand-new session) and rotate_refresh (an existing one). Never
        creates a row, never fires user_logged_in — callers own that. The refresh token's TTL is
        clamped to the session's own remaining lifetime, so rotating never extends how long the
        underlying session may live.
        """
        tokens_conf = conf.get_setting("TOKENS")
        now = timezone.now()
        access_ttl = tokens_conf["ACCESS_TTL_SECONDS"]
        refresh_ttl = max(int((session.expires_at - now).total_seconds()), 0)

        access = tokens.issue(
            {"sub": str(session.user_id), "sid": str(session.id)},
            typ=tokens.TYP_ACCESS,
            ttl_seconds=access_ttl,
        )
        refresh = tokens.issue(
            {"sub": str(session.user_id), "sid": str(session.id), "jti": session.current_jti},
            typ=tokens.TYP_REFRESH,
            ttl_seconds=refresh_ttl,
        )
        return TokenPair(
            access=access,
            refresh=refresh,
            session_id=str(session.id),
            expires_at=now + timedelta(seconds=access_ttl),
        )

    @staticmethod
    def rotate_refresh(raw_refresh_token: str, *, request_meta: RequestMeta) -> TokenPair:
        """Raises RefreshReuseDetected if the presented jti is not the session's current_jti (the
        session is revoked as part of raising, not after). Raises InvalidRefreshToken for a
        malformed/expired/wrong-typ token, or a revoked/expired session. On success: rotates jti,
        increments rotation_count, issues a fresh pair, same session_id throughout.

        Revoked/expired is checked BEFORE the jti comparison: a stale token replayed against a
        session that a prior reuse already killed returns the ordinary InvalidRefreshToken rather
        than re-firing refresh_reuse_detected on every retry. The first reuse still detects
        correctly, since the session is live at that point.
        """
        ip = _require(request_meta, "ip")

        try:
            claims = tokens.decode(raw_refresh_token, expected_typ=tokens.TYP_REFRESH)
        except tokens.TokenError as exc:
            raise InvalidRefreshToken(str(exc)) from exc

        session_id = claims.get("sid")
        if not session_id:
            raise InvalidRefreshToken("Refresh token is missing its 'sid' claim.")
        presented_jti = claims["jti"]

        with transaction.atomic():
            try:
                session = AuthSession.objects.select_for_update().get(pk=session_id)
            except (AuthSession.DoesNotExist, ValidationError, ValueError) as exc:
                raise InvalidRefreshToken("Session does not exist.") from exc

            if session.revoked_at is not None or session.expires_at <= timezone.now():
                raise InvalidRefreshToken("Session is revoked or expired.")

            if not hmac.compare_digest(presented_jti, session.current_jti):
                # revoke_session opens its own atomic block, commits, and fires session_revoked
                # before this nested block exits. Nothing else writes after it in this block, so
                # the outer commit follows immediately — refresh_reuse_detected, fired only once
                # we're back outside this whole `with`, is never observable ahead of the revoke
                # it describes.
                TokenService.revoke_session(session_id, reason="reuse_detected")
                reuse_user_id = session.user_id
            else:
                session.current_jti = tokens.generate_jti()
                session.rotation_count += 1
                session.last_used_at = timezone.now()
                session.save(update_fields=["current_jti", "rotation_count", "last_used_at"])
                return TokenService._issue_pair(session)

        refresh_reuse_detected.send(
            sender=AuthSession, user_id=reuse_user_id, session_id=session_id, ip=ip
        )
        raise RefreshReuseDetected("Refresh token reuse detected; session revoked.")

    @staticmethod
    def revoke_session(session_id: str, *, reason: str) -> None:
        """Idempotent — revoking an already-revoked session is a no-op, not an error. Fires
        session_revoked.
        """
        if reason not in _VALID_REVOKE_REASONS:
            raise ValueError(f"Unknown AuthSession.revoked_reason {reason!r}.")

        with transaction.atomic():
            try:
                session = AuthSession.objects.select_for_update().get(pk=session_id)
            except (AuthSession.DoesNotExist, ValidationError, ValueError):
                return
            if session.revoked_at is not None:
                return
            session.revoked_at = timezone.now()
            session.revoked_reason = reason
            session.save(update_fields=["revoked_at", "revoked_reason"])
            user_id, sid = session.user_id, str(session.id)

        session_revoked.send(sender=AuthSession, session_id=sid, user_id=user_id, reason=reason)

    @staticmethod
    def revoke_all_sessions(user: Any, *, except_session_id: str | None = None, reason: str) -> int:
        """Returns the count revoked. Fires session_revoked once per row."""
        queryset = AuthSession.objects.filter(user=user, revoked_at__isnull=True)
        if except_session_id is not None:
            queryset = queryset.exclude(pk=except_session_id)

        session_ids = list(queryset.values_list("id", flat=True))
        for session_id in session_ids:
            TokenService.revoke_session(str(session_id), reason=reason)
        return len(session_ids)

    @staticmethod
    def verify_access_token(raw_token: str) -> dict[str, Any]:
        """Raises on any signature/exp/typ failure — typ must be 'access'. Never a database call
        beyond what claim verification itself needs.
        """
        return tokens.decode(raw_token, expected_typ=tokens.TYP_ACCESS)

    @staticmethod
    def issue_pending_2fa_token(
        user: Any, *, primary_method: str, request_meta: RequestMeta
    ) -> str:
        """typ='pending_2fa', short TTL from TWO_FACTOR.PENDING_TOKEN_TTL_SECONDS. Carries
        primary_method as a claim so verify_second_factor can enforce the different-channel rule
        without a second database round trip. request_meta is accepted per the frozen signature
        but unread this phase — kept rather than dropped so a later phase can start reading it
        without a signature change.
        """
        ttl_seconds = conf.get_setting("TWO_FACTOR")["PENDING_TOKEN_TTL_SECONDS"]
        return tokens.issue(
            {"sub": str(user.pk), "primary_method": primary_method},
            typ=tokens.TYP_PENDING_2FA,
            ttl_seconds=ttl_seconds,
        )

    @staticmethod
    def verify_pending_2fa_token(token: str) -> dict[str, Any]:
        """Raises InvalidPendingToken on any signature/exp/typ failure — typ must be
        'pending_2fa'.
        """
        try:
            return tokens.decode(token, expected_typ=tokens.TYP_PENDING_2FA)
        except tokens.TokenError as exc:
            raise InvalidPendingToken(str(exc)) from exc


def _resolve_user_for_channel(identifier: str, *, channel: str) -> Any | None:
    """Resolve ``identifier`` against the ONE ``USER_FIELDS`` field this channel maps to —
    ``EMAIL_FIELD`` for ``"email"``, ``PHONE_FIELD`` for ``"phone"``. Deliberately NOT
    ``USER_FIELDS.IDENTIFIER_FIELDS``, which is ``PasswordService.authenticate``'s password-login
    resolution order (docs/CONTRACT.md §4) and has no bearing on an OTP channel. Returns ``None``
    when the field isn't configured at all (an unresolvable channel behaves exactly like an
    unresolvable identifier — the decoy/auto-provision fork in ``OtpService.request`` doesn't
    care which produced the miss) or when no user has that value.

    ``.filter(...).first()`` rather than ``.get()``: ``checks.py``'s E003 already guarantees this
    field is unique for any *enabled* method in production, but this helper doesn't re-verify that
    itself — a duplicate value should degrade to "pick one" rather than raise
    ``MultipleObjectsReturned`` and turn a config gap into a 500.
    """
    user_fields = conf.get_setting("USER_FIELDS")
    field_name = user_fields["EMAIL_FIELD"] if channel == "email" else user_fields["PHONE_FIELD"]
    if not field_name:
        return None
    return get_user_model().objects.filter(**{field_name: identifier}).first()


def _resolve_user_by_identifier_fields(identifier: str) -> Any | None:
    """Resolve ``identifier`` against ``USER_FIELDS.IDENTIFIER_FIELDS`` in order — the password
    login resolution order (docs/CONTRACT.md §4/§11 item 5), the first field with a match wins.
    Used by ``PasswordService.authenticate``/``.request_reset`` and by
    ``LockoutService.record_attempt`` for ``method="password"`` attempts.
    """
    model = get_user_model()
    for field_name in conf.get_setting("USER_FIELDS")["IDENTIFIER_FIELDS"]:
        user = model.objects.filter(**{field_name: identifier}).first()
        if user is not None:
            return user
    return None


def _resolve_user_for_login_attempt(identifier: str, *, method: str) -> Any | None:
    """Resolve ``identifier`` -> user for ``LockoutService.record_attempt``'s ``LoginAttempt.user``
    FK, using the resolution rule that matches how ``method`` actually authenticates: the
    password-login order for ``"password"``, the single OTP-channel field otherwise.
    """
    if method == "password":
        return _resolve_user_by_identifier_fields(identifier)
    channel = "phone" if method == "phone_otp" else "email"
    return _resolve_user_for_channel(identifier, channel=channel)


class UserProvisioningService:
    """docs/CONTRACT.md §11 item 19 — account creation for a phone/email-OTP identifier nobody
    has seen before, opt-in per method via ``USER_FIELDS.AUTO_PROVISION_METHODS``. Called only
    from ``OtpService.verify()``. Never imports a concrete user model; every field write goes
    through ``get_user_model()``/``USER_FIELDS`` resolution, same as every other service here.
    """

    @staticmethod
    def get_or_create(identifier: str, *, field: str) -> tuple[Any, bool]:
        """``field`` is ``"phone"`` or ``"email"`` — whichever ``USER_FIELDS`` entry
        ``identifier`` was resolved against (the OtpChallenge.channel vocabulary, not the
        ALLOWED_AUTH_METHODS "email_otp"/"phone_otp" vocabulary).

        Resolution order: (1) ``USER_FIELDS.PROVISION_CALLBACK``, a dotted path to a host
        callable, if set — the host owns every field, and its return value is passed straight
        through as this method's own return value. (2) else the built-in default: set the field
        named by ``PHONE_FIELD``/``EMAIL_FIELD`` to ``identifier``, set the model's
        ``USERNAME_FIELD`` to ``identifier`` too if it's a different, still-empty field (this is
        what makes stock ``django.contrib.auth.User`` work, since ``username`` is its
        ``USERNAME_FIELD`` and a phone number/email is a valid unique value for it), then
        ``set_unusable_password()`` — the provisioned account must be unreachable via password
        login until a deliberate reset. Never touches a field this app doesn't itself own — no
        name, no avatar, no profile anything.

        An unimportable or non-callable ``PROVISION_CALLBACK`` raises ``ImproperlyConfigured``
        naming the setting — it never silently falls through to the built-in default, which would
        provision with app defaults when the host meant to own creation entirely (fail loudly,
        not silently).

        Fires ``user_provisioned`` only when a new row was actually created, never for an
        existing one.
        """
        user_fields = conf.get_setting("USER_FIELDS")
        callback_path = user_fields["PROVISION_CALLBACK"]

        if callback_path:
            try:
                callback = import_string(callback_path)
            except ImportError as exc:
                raise ImproperlyConfigured(
                    f"JWT_MULTIAUTH['USER_FIELDS']['PROVISION_CALLBACK'] = {callback_path!r} "
                    f"could not be imported: {exc}."
                ) from exc
            if not callable(callback):
                raise ImproperlyConfigured(
                    f"JWT_MULTIAUTH['USER_FIELDS']['PROVISION_CALLBACK'] = {callback_path!r} "
                    f"is not callable."
                )
            # The host owns every field on the created user, including whether a new row was
            # actually created and whether user_provisioned is this call's responsibility to
            # fire — "calls it and returns whatever it returns" (docs/CONTRACT.md §4).
            result: tuple[Any, bool] = callback(identifier, field=field)
            return result

        model = get_user_model()
        field_name = user_fields["PHONE_FIELD"] if field == "phone" else user_fields["EMAIL_FIELD"]

        with transaction.atomic():
            existing = model.objects.select_for_update().filter(**{field_name: identifier}).first()
            if existing is not None:
                return existing, False

            user = model(**{field_name: identifier})
            username_field = model.USERNAME_FIELD
            if username_field != field_name and not getattr(user, username_field, None):
                setattr(user, username_field, identifier)
            user.set_unusable_password()
            user.save()

        # Fired after the atomic block above commits (mirrors TokenService.revoke_session, whose
        # own comment explains why a signal fired from a nested atomic call is safe here: nothing
        # else in this method writes after it).
        user_provisioned.send(sender=model, user_id=user.pk, field=field, value=identifier)
        return user, True


class OtpService:
    """OTP challenge lifecycle — docs/CONTRACT.md §4, implemented in Phase 4. Built on ``otp.py``
    (pure hashing/generation) plus ``OtpChallenge`` (Phase 2).
    """

    @staticmethod
    def request(identifier: str, *, channel: str, purpose: str) -> OtpRequestResult:
        """Resolves ``identifier`` -> user via the channel's single ``USER_FIELDS`` field. Three
        outcomes, all returning an IDENTICALLY-shaped ``OtpRequestResult``:

        - Resolves to a real user: honors ``SINGLE_ACTIVE_CHALLENGE`` (invalidates any prior
          unconsumed challenge for the same user+purpose+channel), persists the row, fires the
          matching ``*_otp_requested`` signal with the plaintext code.
        - Does NOT resolve, and the channel's method is NOT in
          ``USER_FIELDS.AUTO_PROVISION_METHODS``: no database row, no signal — the decoy path.
          The code is still generated and hashed (comparable CPU cost to the real path), just
          never persisted or sent.
        - Does NOT resolve, and the channel's method IS in ``AUTO_PROVISION_METHODS``: persists a
          REAL row with ``user=None`` and fires the signal with ``user_id=None`` — the identifier
          may become a real account at ``verify()`` time (docs/CONTRACT.md §11 item 19).

        Never raises for an unknown identifier — the fail-closed rule applies to CREDENTIALS, not
        to whether an identifier exists, which is exactly what enumeration resistance protects.
        """
        method = otp.method_for_channel(channel)
        auto_provision_methods = conf.get_setting("USER_FIELDS")["AUTO_PROVISION_METHODS"]
        user = _resolve_user_for_channel(identifier, channel=channel)

        pepper = keys.get_otp_pepper()
        length = conf.get_otp_setting("LENGTH", channel=channel, purpose=purpose)
        alphabet = conf.get_otp_setting("ALPHABET", channel=channel, purpose=purpose)
        exclude_ambiguous = conf.get_otp_setting(
            "EXCLUDE_AMBIGUOUS", channel=channel, purpose=purpose
        )
        case_sensitive = conf.get_otp_setting("CASE_SENSITIVE", channel=channel, purpose=purpose)
        ttl_seconds = conf.get_otp_setting("TTL_SECONDS", channel=channel, purpose=purpose)
        max_attempts = conf.get_otp_setting("MAX_ATTEMPTS", channel=channel, purpose=purpose)
        max_resends = conf.get_otp_setting("MAX_RESENDS", channel=channel, purpose=purpose)
        resend_cooldown = conf.get_otp_setting(
            "RESEND_COOLDOWN_SECONDS", channel=channel, purpose=purpose
        )
        single_active = conf.get_otp_setting(
            "SINGLE_ACTIVE_CHALLENGE", channel=channel, purpose=purpose
        )
        emit_link_token = conf.get_otp_setting("EMIT_LINK_TOKEN", channel=channel, purpose=purpose)

        # Generated identically on every branch, decoy included, so the decoy path's CPU cost is
        # comparable to the real path's — never skip straight to "no work needed" for a miss.
        code = otp.generate_code(
            length=length,
            alphabet=alphabet,
            exclude_ambiguous=exclude_ambiguous,
            case_sensitive=case_sensitive,
        )
        now = timezone.now()

        if user is None and method not in auto_provision_methods:
            otp.hash_secret(code, pepper=pepper)  # throwaway — comparable CPU cost, nothing kept
            return OtpRequestResult(
                challenge_id=str(uuid.uuid4()),
                expires_at=now + timedelta(seconds=ttl_seconds),
                resend_available_at=now + timedelta(seconds=resend_cooldown),
            )

        link_token = otp.generate_link_token() if emit_link_token else None

        with transaction.atomic():
            if single_active and user is not None:
                # Must actually invalidate server-side — two valid codes must never coexist for
                # the same user+purpose+channel. Skipped for user=None rows: there is no user to
                # scope the query by, and an auto-provision challenge is the only live one for
                # that never-yet-resolved identifier anyway.
                OtpChallenge.objects.filter(
                    user=user, purpose=purpose, channel=channel, consumed_at__isnull=True
                ).update(consumed_at=now)

            challenge = OtpChallenge.objects.create(
                user=user,
                channel=channel,
                purpose=purpose,
                destination=identifier,
                code_hash=otp.hash_secret(code, pepper=pepper),
                link_token_hash=otp.hash_secret(link_token, pepper=pepper) if link_token else None,
                max_attempts=max_attempts,
                max_resends=max_resends,
                last_sent_at=now,
                expires_at=now + timedelta(seconds=ttl_seconds),
            )

        channel_signal = phone_otp_requested if channel == "phone" else email_otp_requested
        channel_signal.send(
            sender=OtpChallenge,
            user_id=user.pk if user is not None else None,
            destination=identifier,
            code=code,
            link_token=link_token,
            purpose=purpose,
            challenge_id=str(challenge.challenge_id),
            expires_at=challenge.expires_at,
        )
        return OtpRequestResult(
            challenge_id=str(challenge.challenge_id),
            expires_at=challenge.expires_at,
            resend_available_at=now + timedelta(seconds=resend_cooldown),
        )

    @staticmethod
    def verify(
        challenge_id: str, *, code: str | None = None, link_token: str | None = None
    ) -> OtpVerifyResult:
        """Raises ChallengeInvalid for: no such challenge_id (decoy or real-but-gone —
        identical), expired, already consumed, or attempts >= max_attempts — checked BEFORE the
        compare, so attempt max_attempts+1 is rejected even if it would have been correct. Uses
        otp.verify_secret (constant-time) for the actual compare; increments attempts on every
        failed compare.

        On success, for a row whose user IS NOT None: consumed_at=now, fires otp_verified,
        returns OtpVerifyResult(user, purpose, created=False). On success, for a row whose user
        IS None (an auto-provisioned method's previously-unresolved identifier,
        docs/CONTRACT.md §11 item 19): calls UserProvisioningService.get_or_create, records a
        VerifiedContact for the field just proven (the OTP was the proof — NOT via
        VerificationService.confirm(), so contact_verified does not fire for this row), attaches
        the new user to this OtpChallenge, THEN consumed_at=now, fires otp_verified, returns
        OtpVerifyResult(user, purpose, created=True).

        Takes no ``purpose`` argument — every caller (PasswordService.confirm_reset,
        TwoFactorService.verify_second_factor, ...) asserts on the returned ``purpose`` itself.
        """
        pepper = keys.get_otp_pepper()

        try:
            challenge = OtpChallenge.objects.get(pk=challenge_id)
        except (OtpChallenge.DoesNotExist, ValidationError, ValueError) as exc:
            # Fast-fail before any cryptographic work or lock: a challenge_id that doesn't
            # resolve at all (decoy or real-but-deleted) needs no further work to reject, and
            # nothing has been written yet, so raising directly here (rather than deferring past
            # an atomic block) is safe.
            raise ChallengeInvalid("No such OTP challenge.") from exc

        provided = link_token if link_token is not None else code
        expected_hash = challenge.link_token_hash if link_token is not None else challenge.code_hash

        user: Any = None
        created = False
        valid = False
        purpose = challenge.purpose

        with transaction.atomic():
            # Re-fetch under lock: the check above is an optimistic fast-fail; this lock is what
            # makes the actual state transition (attempts increment / consumption) race-safe.
            challenge = OtpChallenge.objects.select_for_update().get(pk=challenge_id)

            if (
                challenge.consumed_at is not None
                or challenge.expires_at <= timezone.now()
                or challenge.attempts >= challenge.max_attempts
            ):
                pass  # valid stays False; nothing to write
            elif (
                provided is None
                or expected_hash is None
                or not otp.verify_secret(provided, expected_hash, pepper=pepper)
            ):
                challenge.attempts += 1
                challenge.save(update_fields=["attempts"])
            else:
                valid = True
                if challenge.user_id is None:
                    user, created = UserProvisioningService.get_or_create(
                        challenge.destination, field=challenge.channel
                    )
                    VerifiedContact.objects.get_or_create(
                        user=user, field=challenge.channel, value=challenge.destination
                    )
                    challenge.user = user
                else:
                    user = challenge.user
                challenge.consumed_at = timezone.now()
                challenge.save(update_fields=["user", "consumed_at"])

        if not valid:
            raise ChallengeInvalid(
                "OTP challenge is invalid, expired, consumed, or attempts exhausted."
            )

        otp_verified.send(
            sender=OtpChallenge,
            user_id=user.pk,
            challenge_id=str(challenge.challenge_id),
            purpose=purpose,
        )
        return OtpVerifyResult(user=user, purpose=purpose, created=created)

    @staticmethod
    def resend(challenge_id: str) -> OtpRequestResult:
        """Raises ChallengeInvalid if the challenge doesn't resolve, is already consumed, the
        resend cooldown hasn't elapsed, or MAX_RESENDS is exhausted. Reuses the same
        challenge_id/destination; generates a fresh code/hash/expires_at. Does NOT reset
        ``attempts`` — the attempts budget bounds total guesses against a given challenge_id
        regardless of how many times its code has been resent, the more conservative reading
        where the contract is silent.
        """
        pepper = keys.get_otp_pepper()

        try:
            challenge = OtpChallenge.objects.get(pk=challenge_id)
        except (OtpChallenge.DoesNotExist, ValidationError, ValueError) as exc:
            raise ChallengeInvalid("No such OTP challenge.") from exc

        channel, purpose = challenge.channel, challenge.purpose
        cooldown = conf.get_otp_setting("RESEND_COOLDOWN_SECONDS", channel=channel, purpose=purpose)

        valid = False
        code = ""
        link_token: str | None = None

        with transaction.atomic():
            challenge = OtpChallenge.objects.select_for_update().get(pk=challenge_id)
            now = timezone.now()

            if (
                challenge.consumed_at is not None
                or now < challenge.last_sent_at + timedelta(seconds=cooldown)
                or challenge.resend_count >= challenge.max_resends
            ):
                pass  # valid stays False; nothing to write
            else:
                length = conf.get_otp_setting("LENGTH", channel=channel, purpose=purpose)
                alphabet = conf.get_otp_setting("ALPHABET", channel=channel, purpose=purpose)
                exclude_ambiguous = conf.get_otp_setting(
                    "EXCLUDE_AMBIGUOUS", channel=channel, purpose=purpose
                )
                case_sensitive = conf.get_otp_setting(
                    "CASE_SENSITIVE", channel=channel, purpose=purpose
                )
                ttl_seconds = conf.get_otp_setting("TTL_SECONDS", channel=channel, purpose=purpose)
                emit_link_token = conf.get_otp_setting(
                    "EMIT_LINK_TOKEN", channel=channel, purpose=purpose
                )

                code = otp.generate_code(
                    length=length,
                    alphabet=alphabet,
                    exclude_ambiguous=exclude_ambiguous,
                    case_sensitive=case_sensitive,
                )
                link_token = otp.generate_link_token() if emit_link_token else None

                challenge.code_hash = otp.hash_secret(code, pepper=pepper)
                challenge.link_token_hash = (
                    otp.hash_secret(link_token, pepper=pepper) if link_token else None
                )
                challenge.expires_at = now + timedelta(seconds=ttl_seconds)
                challenge.last_sent_at = now
                challenge.resend_count += 1
                challenge.save(
                    update_fields=[
                        "code_hash",
                        "link_token_hash",
                        "expires_at",
                        "last_sent_at",
                        "resend_count",
                    ]
                )
                valid = True

        if not valid:
            raise ChallengeInvalid(
                "OTP resend is unavailable: challenge is consumed, cooldown hasn't elapsed, or "
                "resend budget is exhausted."
            )

        channel_signal = phone_otp_requested if channel == "phone" else email_otp_requested
        channel_signal.send(
            sender=OtpChallenge,
            user_id=challenge.user_id,
            destination=challenge.destination,
            code=code,
            link_token=link_token,
            purpose=purpose,
            challenge_id=str(challenge.challenge_id),
            expires_at=challenge.expires_at,
        )
        return OtpRequestResult(
            challenge_id=str(challenge.challenge_id),
            expires_at=challenge.expires_at,
            resend_available_at=timezone.now() + timedelta(seconds=cooldown),
        )


#: A real hash under whatever hasher the host has configured (PASSWORD_HASHERS[0]) — computed
#: once at import time from a random, unusable value, never a hardcoded literal. A literal would
#: run under a fixed, possibly-wrong algorithm/cost and defeat the entire point of comparing
#: apples to apples against a real user's own check_password() call.
_DUMMY_PASSWORD_HASH: Final[str] = make_password(secrets.token_urlsafe(32))


def _finish_password_reset_or_change(user: Any, new_password: str) -> None:
    """Shared tail of ``PasswordService.change_password``/``.confirm_reset`` — validates the new
    password against ``AUTH_PASSWORD_VALIDATORS``, sets it, then UNCONDITIONALLY revokes every
    session for ``user`` (no ``except_session_id`` — docs/CONTRACT.md §4/§10 both call
    ``revoke_all_sessions`` with no exception; the caller's own session dies too, and the view
    layer, Phase 6, is what re-issues a fresh pair for them), and only THEN fires
    ``password_changed`` — after revocation actually commits, per docs/CONTRACT.md §3 (§11 item
    20 resolves a wording mismatch against an earlier draft of §4's own docstring, which read
    "fires password_changed, then... revokes", in §3's favor: a receiver observing the signal can
    rely on every session already being dead).
    """
    validate_password(new_password, user=user)
    user.set_password(new_password)
    user.save(update_fields=["password"])
    TokenService.revoke_all_sessions(user, reason="password_changed")
    password_changed.send(sender=get_user_model(), user_id=user.pk)


class PasswordService:
    """Password authentication, change, and OTP-mediated reset — docs/CONTRACT.md §4, Phase 5.
    Built on ``OtpService`` (reset is just a ``purpose="password_reset"`` OTP challenge) and
    ``TokenService.revoke_all_sessions`` (a change/reset always kills every session, §10).
    """

    @staticmethod
    def authenticate(identifier: str, password: str) -> Any | None:
        """Resolves ``identifier`` against ``USER_FIELDS.IDENTIFIER_FIELDS`` in order. Exactly one
        password-hash comparison happens on any failure path — a real ``user.check_password()``
        call when ``identifier`` resolves to a wrong password, a dummy ``check_password()``
        against a FIXED, pre-computed hash when it resolves to no one at all — so the
        no-such-identifier and wrong-password paths cost the same instead of the former looking
        suspiciously cheap. Mirrors ``django.contrib.auth.backends.ModelBackend``'s own
        ``DoesNotExist`` branch, which solves the identical problem via
        ``UserModel().set_password(password)`` rather than an extra hash comparison stacked on
        top of the real one. Never raises; returns ``None`` on any failure.
        """
        user = _resolve_user_by_identifier_fields(identifier)
        if user is None:
            check_password(password, _DUMMY_PASSWORD_HASH)
            return None
        if not user.check_password(password):
            return None
        return user

    @staticmethod
    def change_password(user: Any, old_password: str, new_password: str) -> None:
        """Raises ``django.core.exceptions.ValidationError`` — ``code="invalid_old_password"`` for
        a wrong ``old_password`` (checked unconditionally;
        ``PASSWORD.REQUIRE_OLD_PASSWORD_ON_CHANGE`` is a documented rail, not a toggle,
        docs/CONTRACT.md §6), or Django's own ``AUTH_PASSWORD_VALIDATORS`` messages for a
        ``new_password`` that fails validation. On success: see
        ``_finish_password_reset_or_change``.
        """
        if not user.check_password(old_password):
            raise ValidationError("The old password is incorrect.", code="invalid_old_password")
        _finish_password_reset_or_change(user, new_password)

    @staticmethod
    def request_reset(identifier: str) -> None:
        """Always returns, never raises, for ANY identifier — including one that doesn't resolve
        at all. Resolves ``identifier`` against ``IDENTIFIER_FIELDS``; if it resolves, picks the
        first channel in ``PASSWORD.RESET_CHANNEL_PREFERENCE`` for which the user actually has a
        non-empty value, and delegates to ``OtpService.request`` with THAT value as the
        destination. If it doesn't resolve (or resolves to a user with no usable contact value on
        any preferred channel), delegates with the raw ``identifier`` on the first *configured*
        preference channel instead — landing on ``OtpService.request``'s own enumeration-resistant
        decoy/auto-provision fork, never a branch distinguishable from here. The result is
        discarded entirely; the view layer (Phase 6) is what turns this into an unconditional 200.

        Raises ``ImproperlyConfigured`` only for a configuration gap independent of
        ``identifier`` — neither ``USER_FIELDS.EMAIL_FIELD`` nor ``.PHONE_FIELD`` set for any
        entry in ``RESET_CHANNEL_PREFERENCE`` at all — since that reveals nothing about any
        specific identifier and is rule 3's fail-closed rule applied to configuration, not
        credentials.
        """
        user_fields = conf.get_setting("USER_FIELDS")
        preference = conf.get_setting("PASSWORD")["RESET_CHANNEL_PREFERENCE"]

        def field_for(channel: str) -> str | None:
            key = "EMAIL_FIELD" if channel == "email" else "PHONE_FIELD"
            return cast("str | None", user_fields[key])

        configured = [channel for channel in preference if field_for(channel)]
        if not configured:
            raise ImproperlyConfigured(
                "jwt_multiauth: PasswordService.request_reset() has no usable delivery channel — "
                "neither USER_FIELDS['EMAIL_FIELD'] nor USER_FIELDS['PHONE_FIELD'] is set for any "
                "entry in PASSWORD['RESET_CHANNEL_PREFERENCE']."
            )

        user = _resolve_user_by_identifier_fields(identifier)
        channel = configured[0]
        destination = identifier
        if user is not None:
            for candidate in configured:
                value = getattr(user, cast("str", field_for(candidate)), "") or ""
                if value:
                    channel, destination = candidate, value
                    break

        OtpService.request(destination, channel=channel, purpose="password_reset")

    @staticmethod
    def confirm_reset(
        challenge_id: str,
        *,
        code: str | None = None,
        link_token: str | None = None,
        new_password: str,
    ) -> None:
        """Raises ``ChallengeInvalid`` (via ``OtpService.verify``) for a challenge that doesn't
        resolve/expired/consumed/exhausted, whose ``purpose`` isn't ``"password_reset"``, or whose
        verify just auto-provisioned a brand-new user (``result.created``). ``OtpService.verify``
        itself provisions unconditionally whenever a ``user=None`` row's code checks out,
        regardless of ``purpose`` — this method cannot and does not prevent that row from existing
        afterward. What it refuses is to ALSO set a password for that just-minted, still-unproven
        identity: acting on it here would make password reset a second, undocumented way to turn
        an unresolved identifier into a real account, when auto-provisioning is documented as an
        OTP *login* side effect only (docs/CONTRACT.md's own scope boundary). On success: see
        ``_finish_password_reset_or_change``.
        """
        result = OtpService.verify(challenge_id, code=code, link_token=link_token)
        if result.purpose != "password_reset" or result.created:
            raise ChallengeInvalid("OTP challenge is not a valid password_reset challenge.")
        _finish_password_reset_or_change(result.user, new_password)


_VALID_LOGIN_METHODS: Final[frozenset[str]] = frozenset({"password", "email_otp", "phone_otp"})
_VALID_FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {"no_such_identifier", "wrong_credential", "locked", "two_factor_unavailable"}
)
_VALID_LOCK_SCOPES: Final[frozenset[str]] = frozenset({"identifier", "ip", "identifier_and_ip"})

#: Global namespace for LOCK_SCOPE="ip" — a lock/counter under this scope has no per-identifier
#: component at all, which is exactly why LockoutService.unlock(identifier) can never reach it
#: (see its own docstring).
_LOCKOUT_IP_NAMESPACE: Final[str] = "jwt_multiauth.lockout.ip"


def _lockout_identifier_namespace(identifier: str) -> str:
    """A per-identifier cache namespace, keyed by a hash rather than the raw identifier — mirrors
    ``appkit.cache.build_cache_key``'s own reasoning for hashing long/unsafe parts, except here
    the identifier itself (an email, a phone number, PII) must never appear verbatim in a cache
    backend's key listing.
    """
    digest = hashlib.sha256(identifier.encode()).hexdigest()[:32]
    return f"jwt_multiauth.lockout.id.{digest}"


def _lockout_keys(identifier: str, *, ip: str) -> tuple[str, str]:
    """Resolve the ``(attempts_key, lock_key)`` pair for the currently-configured
    ``LOCKOUT.LOCK_SCOPE``. Raises ``ImproperlyConfigured`` for an unrecognized scope — fail
    closed, never silently default to one of the three (docs/CONTRACT.md §10's own trade-off
    discussion assumes all three are actually implemented, not two-plus-a-fallback).
    """
    scope = conf.get_setting("LOCKOUT")["LOCK_SCOPE"]
    if scope not in _VALID_LOCK_SCOPES:
        raise ImproperlyConfigured(
            f"JWT_MULTIAUTH['LOCKOUT']['LOCK_SCOPE'] = {scope!r} is invalid — must be one of "
            f"{sorted(_VALID_LOCK_SCOPES)}."
        )
    parts: tuple[str, ...]
    if scope == "identifier":
        namespace, parts = _lockout_identifier_namespace(identifier), ()
    elif scope == "identifier_and_ip":
        namespace, parts = _lockout_identifier_namespace(identifier), (ip,)
    else:  # "ip"
        namespace, parts = _LOCKOUT_IP_NAMESPACE, (ip,)
    return (
        build_cache_key(namespace, "attempts", *parts),
        build_cache_key(namespace, "lock", *parts),
    )


class LockoutService:
    """Login-attempt auditing and cache-backed lockout — docs/CONTRACT.md §4, Phase 5. Writes a
    ``LoginAttempt`` row on every call, success or not; failures additionally drive a
    ``LOCKOUT.LOCK_SCOPE``-keyed counter via ``django.core.cache`` (``appkit.cache`` builds the
    versioned keys, but exposes no atomic increment of its own, so the counter itself is a direct
    ``cache.add``/``cache.incr`` pair — Django's own cache API contract for a race-safe counter).
    """

    @staticmethod
    def record_attempt(
        identifier: str,
        *,
        ip: str,
        success: bool,
        method: str = "password",
        reason: str | None = None,
        user_agent: str = "",
    ) -> None:
        """Always writes a ``LoginAttempt`` row. ``method`` — defaulted to ``"password"`` rather
        than added as a new required positional, docs/CONTRACT.md §11 item 21, since
        ``LoginAttempt.method`` has no value to write from the frozen §4 signature otherwise — must
        be one of ``LoginAttempt.method``'s choices. ``reason`` is REQUIRED (one of
        ``LoginAttempt.failure_reason``'s choices) when ``success=False``; ignored (forced to
        ``None``) when ``success=True``.

        On failure: fires ``login_failed`` unconditionally, then increments the active
        ``LOCK_SCOPE``'s counter within ``LOCKOUT.WINDOW_SECONDS``, firing ``account_locked``
        exactly once — via ``cache.add`` on the lock key itself, not a separate "first time"
        flag — the instant the count reaches ``LOCKOUT.MAX_ATTEMPTS``.
        """
        if method not in _VALID_LOGIN_METHODS:
            raise ValueError(f"Unknown LoginAttempt.method {method!r}.")
        if success:
            reason = None
        elif reason not in _VALID_FAILURE_REASONS:
            raise ValueError(
                f"LockoutService.record_attempt(success=False) requires reason to be one of "
                f"{sorted(_VALID_FAILURE_REASONS)}, got {reason!r}."
            )

        user = _resolve_user_for_login_attempt(identifier, method=method)
        LoginAttempt.objects.create(
            user=user,
            identifier=identifier,
            method=method,
            ip_address=ip,
            user_agent=user_agent[:512],
            success=success,
            failure_reason=reason,
        )

        if success:
            return

        login_failed.send(sender=LoginAttempt, identifier=identifier, reason=reason, ip=ip)

        lockout = conf.get_setting("LOCKOUT")
        attempts_key, lock_key = _lockout_keys(identifier, ip=ip)
        cache.add(attempts_key, 0, timeout=lockout["WINDOW_SECONDS"])
        try:
            count = cache.incr(attempts_key)
        except ValueError:
            # The key expired between the `add` above and this `incr` (a WINDOW_SECONDS race,
            # not a bug) — reseed at 1 rather than letting incr raise past this method's own
            # never-raises-on-a-failed-attempt contract.
            cache.set(attempts_key, 1, timeout=lockout["WINDOW_SECONDS"])
            count = 1

        if count >= lockout["MAX_ATTEMPTS"]:
            until = timezone.now() + timedelta(seconds=lockout["LOCK_DURATION_SECONDS"])
            # `add`, not `set`: only the call that actually WINS the race to create the lock key
            # fires account_locked — every subsequent failing attempt against an already-locked
            # identifier/ip sees `add` return False and stays silent.
            if cache.add(lock_key, until.isoformat(), timeout=lockout["LOCK_DURATION_SECONDS"]):
                account_locked.send(
                    sender=LoginAttempt,
                    user_id=user.pk if user is not None else None,
                    identifier=identifier,
                    until=until,
                    scope=lockout["LOCK_SCOPE"],
                )

    @staticmethod
    def is_locked(identifier: str, *, ip: str) -> LockStatus:
        """Checked BEFORE ``PasswordService.authenticate``/``OtpService.verify`` are ever called
        at every real call site (Phase 6), so a locked-out caller never even reaches the
        dummy-hash path. This does not reintroduce a timing side-channel: locked-vs-not-locked is
        not a secret about a SPECIFIC identifier's validity the way "which password is right" is
        — it is a rate-limit state, not a credential, so a fast-path cache read here leaks
        nothing rule 5 protects. One cache read; never raises beyond the same
        ``ImproperlyConfigured`` an unrecognized ``LOCK_SCOPE`` already raises from
        ``_lockout_keys``.
        """
        _, lock_key = _lockout_keys(identifier, ip=ip)
        until_raw = cache.get(lock_key)
        if until_raw is None:
            return LockStatus(locked=False, until=None)
        until = datetime.fromisoformat(until_raw)
        if until <= timezone.now():
            return LockStatus(locked=False, until=None)
        return LockStatus(locked=True, until=until)

    @staticmethod
    def unlock(identifier: str) -> None:
        """Admin-only caller (Phase 8). Bumps the per-identifier cache namespace's version,
        which resets BOTH the attempt counter and any active lock for ``identifier`` in one call
        — idempotent, and effective across every IP that namespace's keys were ever built with
        (covers ``"identifier"`` and ``"identifier_and_ip"`` scopes). Under
        ``LOCKOUT.LOCK_SCOPE="ip"`` a lock has no per-identifier component to invalidate at all
        (see ``_lockout_keys``) — this call is then a harmless no-op for that configuration; an
        IP-scoped lock must be lifted at the infrastructure layer instead.
        """
        invalidate_namespace(_lockout_identifier_namespace(identifier))


class VerificationService:
    """Contact-field (email/phone) verification for an ALREADY-authenticated user —
    docs/CONTRACT.md §4, Phase 5. Distinct from OTP *login*: the caller's identity is never in
    question here, so no decoy path applies at all (docs/CONTRACT.md §4).
    """

    @staticmethod
    def request_contact_verification(user: Any, *, field: str) -> OtpRequestResult:
        """Delegates to ``OtpService.request`` with ``purpose="verify_contact"``, destination =
        the user's CURRENT value for ``field``. Raises ``ValueError`` for a ``field`` other than
        ``"email"``/``"phone"``, ``ImproperlyConfigured`` if the matching ``USER_FIELDS`` entry
        isn't configured at all, and ``django.core.exceptions.ValidationError`` if the user's own
        value for that field is currently empty — nothing to verify. No decoy path applies: the
        caller is already authenticated, so the identifier always resolves (to themselves).
        """
        if field not in ("email", "phone"):
            raise ValueError(
                f"VerificationService field must be 'email' or 'phone', got {field!r}."
            )

        user_fields = conf.get_setting("USER_FIELDS")
        field_key = "EMAIL_FIELD" if field == "email" else "PHONE_FIELD"
        field_name = user_fields[field_key]
        if not field_name:
            raise ImproperlyConfigured(
                f"USER_FIELDS[{field_key!r}] is not configured; "
                f"VerificationService.request_contact_verification() has no field to verify."
            )

        value = getattr(user, field_name, "") or ""
        if not value:
            raise ValidationError(
                f"The user has no value set for the {field!r} field to verify.",
                code="no_contact_value",
            )
        return OtpService.request(value, channel=field, purpose="verify_contact")

    @staticmethod
    def confirm(user: Any, challenge_id: str, *, code: str) -> None:
        """Raises ``ChallengeInvalid`` (via ``OtpService.verify``) for a challenge that doesn't
        resolve/expired/consumed/exhausted, whose ``purpose`` isn't ``"verify_contact"``, whose
        verify just auto-provisioned a brand-new user (``result.created`` — same reasoning as
        ``PasswordService.confirm_reset``: ``OtpService.verify`` provisions unconditionally
        whenever a ``user=None`` row's code checks out regardless of ``purpose``, so this method
        cannot prevent that row from existing; it only refuses to ALSO record a ``VerifiedContact``
        for that just-minted, still-unproven identity), or whose verified user doesn't match the
        caller — an
        IDOR guard only possible because this method takes ``user`` in the first place
        (docs/CONTRACT.md §4's frozen signature, distinguishing it from the guide prompt's own
        ``(challenge_id, *, code)`` draft, docs/CONTRACT.md §11 item 23). On success:
        ``get_or_create``s a ``VerifiedContact`` row for (user, field, destination) — read off the
        challenge row, never off the request — and fires ``contact_verified``.
        """
        result = OtpService.verify(challenge_id, code=code)
        if result.purpose != "verify_contact" or result.created or result.user.pk != user.pk:
            raise ChallengeInvalid(
                "OTP challenge is not a valid verify_contact challenge for this user."
            )

        challenge = OtpChallenge.objects.get(pk=challenge_id)
        VerifiedContact.objects.get_or_create(
            user=user, field=challenge.channel, value=challenge.destination
        )
        contact_verified.send(
            sender=VerifiedContact,
            user_id=user.pk,
            field=challenge.channel,
            value=challenge.destination,
        )
