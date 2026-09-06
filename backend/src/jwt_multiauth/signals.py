"""This app's own emitted events — ``phone_otp_requested``, ``email_otp_requested``,
``otp_verified``, ``user_provisioned``, ``contact_verified``, ``user_logged_in``,
``user_logged_out``, ``login_failed``, ``account_locked``, ``password_changed``,
``two_factor_enabled``, ``two_factor_disabled``, ``refresh_reuse_detected``, ``session_revoked``.

Populated incrementally as the services that emit each signal land: Phase 3 (token/session
signals — ``user_logged_in``, ``refresh_reuse_detected``, ``session_revoked``), Phase 4 (OTP and
auto-provisioning signals — ``phone_otp_requested``, ``email_otp_requested``, ``otp_verified``,
``user_provisioned``), and completed in Phase 5 (the remaining login/lockout/password/2FA
signals), per ``docs/CONTRACT.md`` §3.

Every payload is primitives/IDs only — never a model instance, checked explicitly at review time
per phase. ``account_locked``'s payload is ``user_id: int | None, identifier: str, until:
datetime, scope: str`` (``docs/CONTRACT.md`` §11 item 7) — an IP-scoped lock, or a lock triggered
by an identifier that never resolved to a user, has no ``user_id`` at all. Similarly,
``phone_otp_requested``/``email_otp_requested``'s ``user_id`` is ``int | None``: ``None`` on the
``USER_FIELDS.AUTO_PROVISION_METHODS`` path, where the identifier hasn't resolved to an account
yet (``docs/CONTRACT.md`` §11 item 19) — this widens §3's originally-declared ``int``, decided
during Phase 4 since the signal had not shipped and not firing here would mean the OTP code never
reaches the host's delivery receiver at all.

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

phone_otp_requested = django.dispatch.Signal()
"""Sent by OtpService.request()/resend() when channel="phone" and the identifier resolved to a
real user OR to a real, newly-persisted user=None challenge on a USER_FIELDS.AUTO_PROVISION_METHODS
method (docs/CONTRACT.md §11 item 19) — never for the decoy path, which fires no signal at all.
sender=OtpChallenge.
Payload: user_id: int | None, destination: str, code: str, link_token: str | None, purpose: str,
challenge_id: str, expires_at: datetime"""

email_otp_requested = django.dispatch.Signal()
"""Sent by OtpService.request()/resend() when channel="email" — same conditions and payload shape
as phone_otp_requested, a SEPARATE signal so a host's SMS receiver is never invoked for an email
event and vice versa (never one signal with a channel kwarg). sender=OtpChallenge.
Payload: user_id: int | None, destination: str, code: str, link_token: str | None, purpose: str,
challenge_id: str, expires_at: datetime"""

otp_verified = django.dispatch.Signal()
"""Sent by OtpService.verify() on a successful code/link-token compare. sender=OtpChallenge. NOT
sent for a totp or recovery_code second-factor verification — those have no OtpChallenge involved.
Payload: user_id: int, challenge_id: str, purpose: str"""

user_provisioned = django.dispatch.Signal()
"""Sent by UserProvisioningService.get_or_create() the moment it creates a NEW user — never for
an existing one. sender=get_user_model().
Payload: user_id: int, field: str, value: str"""
