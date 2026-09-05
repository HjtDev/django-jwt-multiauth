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

import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, TypedDict, cast

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from jwt_multiauth import conf, tokens
from jwt_multiauth.models import AuthSession
from jwt_multiauth.signals import refresh_reuse_detected, session_revoked, user_logged_in

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
