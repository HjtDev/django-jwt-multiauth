"""This app's own emitted events — ``phone_otp_requested``, ``email_otp_requested``,
``otp_verified``, ``contact_verified``, ``user_logged_in``, ``user_logged_out``,
``login_failed``, ``account_locked``, ``password_changed``, ``two_factor_enabled``,
``two_factor_disabled``, ``refresh_reuse_detected``, ``session_revoked``.

Populated incrementally as the services that emit each signal land: Phase 3 (token/session
signals — ``user_logged_in``, ``refresh_reuse_detected``, ``session_revoked``), Phase 4 (OTP
signals — ``phone_otp_requested``, ``email_otp_requested``, ``otp_verified``), and completed in
Phase 5 (the remaining login/lockout/password/2FA signals), per ``docs/CONTRACT.md`` §3.

Every payload is primitives/IDs only — never a model instance, checked explicitly at review time
per phase. ``account_locked``'s payload is ``user_id: int | None, identifier: str, until:
datetime, scope: str`` (``docs/CONTRACT.md`` §11 item 7) — an IP-scoped lock, or a lock triggered
by an identifier that never resolved to a user, has no ``user_id`` at all.

Renaming or removing any signal here, or changing a payload shape, is a MAJOR version bump with a
``Host action:`` line in ``CHANGELOG.md`` (this repo's ``CLAUDE.md`` semver-trigger list).
"""

from __future__ import annotations

import django.dispatch

user_logged_in = django.dispatch.Signal()
"""Sent by TokenService.issue_token_pair() — i.e. once real tokens are actually issued, whether
that happened directly (no 2FA required) or after TwoFactorService.verify_second_factor succeeded.
sender=AuthSession.
Payload: user_id: int, session_id: str, method: str"""

refresh_reuse_detected = django.dispatch.Signal()
"""Sent by TokenService.rotate_refresh() the instant a superseded jti is presented — fired only
after the triggering session's revocation actually commits, never before. sender=AuthSession.
Payload: user_id: int, session_id: str, ip: str"""

session_revoked = django.dispatch.Signal()
"""Sent by TokenService.revoke_session()/revoke_all_sessions() for every row revoked — including
the reuse-detection and password-changed paths, which both call through revoke_session/
revoke_all_sessions rather than duplicating the revoke logic. sender=AuthSession.
Payload: session_id: str, user_id: int, reason: str"""
