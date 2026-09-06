"""Proves the 7 signals ``signals.py`` gained in Phase 5 match ``docs/CONTRACT.md`` §3's payload
shape exactly — the payload key SET, not just individual values, so a stray extra kwarg fails.
``contact_verified``, ``login_failed``, ``account_locked``, ``password_changed`` are already
emitted by real Phase 5 service calls, exercised here via a real call (not a bare ``.send()``).
``user_logged_out`` (Phase 6), ``two_factor_enabled``/``two_factor_disabled`` (Phase 7) have no
emitting code yet — proven here only as a documentation-matching contract check: connecting a
receiver and sending the exact documented payload shape round-trips cleanly.

``phone_otp_requested``/``email_otp_requested``/``otp_verified``/``user_provisioned`` (Phase 4) and
``user_logged_in``/``refresh_reuse_detected``/``session_revoked`` (Phase 3) already have per-value
coverage in ``test_otp_service.py``/``test_token_service.py`` — not duplicated here.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.utils import timezone

from jwt_multiauth.factories import UserFactory
from jwt_multiauth.models import LoginAttempt, VerifiedContact
from jwt_multiauth.services import (
    LockoutService,
    PasswordService,
    TokenService,
    VerificationService,
)
from jwt_multiauth.signals import (
    account_locked,
    contact_verified,
    login_failed,
    password_changed,
    two_factor_disabled,
    two_factor_enabled,
    user_logged_out,
)
from tests.backend.conftest import captured

pytestmark = pytest.mark.django_db


def _request_meta() -> dict[str, str]:
    return {"ip": "203.0.113.5", "method": "password"}


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_contact_verified_payload_matches_contract_exactly() -> None:
    from jwt_multiauth.signals import email_otp_requested

    user = UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        request_result = VerificationService.request_contact_verification(user, field="email")
    code = received[0]["code"]

    with captured(contact_verified) as payloads:
        VerificationService.confirm(user, request_result.challenge_id, code=code)

    assert len(payloads) == 1
    payload = payloads[0]
    assert set(payload) == {"sender", "user_id", "field", "value"}
    assert payload["sender"] is VerifiedContact
    assert isinstance(payload["user_id"], int)
    assert payload["field"] == "email"
    assert payload["value"] == "alice@example.com"


@override_settings(
    JWT_MULTIAUTH={"LOCKOUT": {"MAX_ATTEMPTS": 3, "LOCK_SCOPE": "identifier_and_ip"}}
)
def test_login_failed_payload_matches_contract_exactly() -> None:
    with captured(login_failed) as payloads:
        LockoutService.record_attempt(
            "alice", ip="203.0.113.1", success=False, reason="wrong_credential"
        )

    assert len(payloads) == 1
    payload = payloads[0]
    assert set(payload) == {"sender", "identifier", "reason", "ip"}
    assert payload["sender"] is LoginAttempt
    assert payload["identifier"] == "alice"
    assert payload["reason"] == "wrong_credential"
    assert payload["ip"] == "203.0.113.1"


@override_settings(
    JWT_MULTIAUTH={"LOCKOUT": {"MAX_ATTEMPTS": 1, "LOCK_SCOPE": "identifier_and_ip"}}
)
def test_account_locked_payload_matches_contract_exactly() -> None:
    user = UserFactory(username="alice")
    with captured(account_locked) as payloads:
        LockoutService.record_attempt(
            "alice", ip="203.0.113.1", success=False, reason="wrong_credential"
        )

    assert len(payloads) == 1
    payload = payloads[0]
    assert set(payload) == {"sender", "user_id", "identifier", "until", "scope"}
    assert payload["sender"] is LoginAttempt
    assert payload["user_id"] == user.pk
    assert payload["identifier"] == "alice"
    assert payload["until"] > timezone.now()
    assert payload["scope"] == "identifier_and_ip"


def test_password_changed_payload_matches_contract_exactly() -> None:
    user = get_user_model().objects.create_user(username="alice", password="original-password")
    TokenService.issue_token_pair(user, request_meta=_request_meta())

    with captured(password_changed) as payloads:
        PasswordService.change_password(user, "original-password", "a-new-strong-password-99")

    assert len(payloads) == 1
    payload = payloads[0]
    assert set(payload) == {"sender", "user_id"}
    assert payload["sender"] == get_user_model()
    assert payload["user_id"] == user.pk


# --------------------------------------------------------------------- not-yet-emitting signals


def test_user_logged_out_contract_shape() -> None:
    received: list[dict[str, object]] = []

    def receiver(**kwargs: object) -> None:
        kwargs.pop("signal", None)
        received.append(kwargs)

    user_logged_out.connect(receiver, weak=False)
    try:
        user_logged_out.send(
            sender=object, user_id=1, session_id="11111111-1111-1111-1111-111111111111"
        )
    finally:
        user_logged_out.disconnect(receiver)

    assert received == [
        {"sender": object, "user_id": 1, "session_id": "11111111-1111-1111-1111-111111111111"}
    ]


def test_two_factor_enabled_contract_shape() -> None:
    received: list[dict[str, object]] = []

    def receiver(**kwargs: object) -> None:
        kwargs.pop("signal", None)
        received.append(kwargs)

    two_factor_enabled.connect(receiver, weak=False)
    try:
        two_factor_enabled.send(sender=object, user_id=1, method="totp")
    finally:
        two_factor_enabled.disconnect(receiver)

    assert received == [{"sender": object, "user_id": 1, "method": "totp"}]


def test_two_factor_disabled_contract_shape() -> None:
    received: list[dict[str, object]] = []

    def receiver(**kwargs: object) -> None:
        kwargs.pop("signal", None)
        received.append(kwargs)

    two_factor_disabled.connect(receiver, weak=False)
    try:
        two_factor_disabled.send(sender=object, user_id=1, method="totp")
    finally:
        two_factor_disabled.disconnect(receiver)

    assert received == [{"sender": object, "user_id": 1, "method": "totp"}]
