"""Proves ``services.PasswordService``: ``authenticate`` resolves against
``USER_FIELDS.IDENTIFIER_FIELDS`` in order and performs exactly one password-hash comparison per
failure path — a dummy ``check_password`` against a fixed hash for an identifier that resolves to
no one, the user's own real ``check_password`` for a resolved-but-wrong password — so the two
failure paths cost the same instead of the former looking suspiciously cheap;
``change_password``/``confirm_reset`` both validate the new password, set it, revoke every other
session, and fire ``password_changed`` only AFTER every ``session_revoked`` has already fired;
``request_reset`` never raises for any identifier and picks the user's own contact value over the
raw identifier when one is available; ``confirm_reset`` rejects a wrong-purpose or
auto-provisioned challenge.
"""

from __future__ import annotations

import statistics
import time
from contextlib import contextmanager
from typing import Any

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.test import override_settings

from jwt_multiauth import services
from jwt_multiauth.factories import UserFactory
from jwt_multiauth.models import AuthSession, OtpChallenge
from jwt_multiauth.services import (
    ChallengeInvalid,
    OtpService,
    PasswordService,
    RequestMeta,
    TokenService,
)
from jwt_multiauth.signals import password_changed, session_revoked
from tests.backend.conftest import captured

pytestmark = pytest.mark.django_db


def _request_meta(**overrides: str) -> RequestMeta:
    meta: RequestMeta = {"ip": "203.0.113.5", "method": "password"}
    meta.update(overrides)  # type: ignore[typeddict-item]
    return meta


@contextmanager
def captured_ordered(*signals: Any):
    """Like ``conftest.captured`` but tracks MULTIPLE signals in a single, order-preserving list
    of ``(signal, payload)`` pairs — needed to prove ``password_changed`` fires strictly after
    every ``session_revoked`` it triggered, not the two independently.
    """
    order: list[tuple[Any, dict[str, Any]]] = []

    def make_receiver(signal: Any):
        def _receiver(**kwargs: Any) -> None:
            kwargs.pop("signal", None)
            order.append((signal, kwargs))

        return _receiver

    connections = [(signal, make_receiver(signal)) for signal in signals]
    for signal, receiver in connections:
        signal.connect(receiver, weak=False)
    try:
        yield order
    finally:
        for signal, receiver in connections:
            signal.disconnect(receiver)


# --------------------------------------------------------------------- authenticate


def test_authenticate_resolves_via_identifier_fields_in_order_and_returns_the_user() -> None:
    user = get_user_model().objects.create_user(
        username="alice", email="alice@example.com", password="correct-horse-battery"
    )
    assert PasswordService.authenticate("alice", "correct-horse-battery") == user
    assert PasswordService.authenticate("alice@example.com", "correct-horse-battery") == user


def test_authenticate_wrong_password_for_a_real_user_returns_none() -> None:
    get_user_model().objects.create_user(username="alice", password="correct-horse-battery")
    assert PasswordService.authenticate("alice", "wrong") is None


def test_authenticate_unknown_identifier_returns_none() -> None:
    assert PasswordService.authenticate("nobody", "whatever") is None


def test_authenticate_dummy_hash_check_is_reached_on_the_no_such_user_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    def fake_check_password(password: str, encoded: str) -> bool:
        calls.append((password, encoded))
        return False

    monkeypatch.setattr(services, "check_password", fake_check_password)

    result = PasswordService.authenticate("nobody-at-all", "whatever")

    assert result is None
    assert calls == [("whatever", services._DUMMY_PASSWORD_HASH)]


def test_authenticate_resolved_wrong_password_never_calls_the_dummy_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Exactly one hash comparison happens on ANY failure path: the resolved-user branch already
    # spent its one comparison inside user.check_password() (which calls Django's own hashers
    # module directly, not through this module's imported binding) — this proves the dummy branch
    # is never ALSO reached for a resolved user, which would make the wrong-password path cost
    # MORE than the no-such-user path instead of the same.
    get_user_model().objects.create_user(username="alice", password="correct-horse-battery")
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        services, "check_password", lambda password, encoded: calls.append((password, encoded))
    )

    result = PasswordService.authenticate("alice", "wrong")

    assert result is None
    assert calls == []


@pytest.mark.slow
def test_authenticate_no_such_user_and_wrong_password_cost_comparable_time() -> None:
    get_user_model().objects.create_user(username="alice", password="correct-horse-battery")

    def timed(identifier: str) -> float:
        start = time.perf_counter()
        PasswordService.authenticate(identifier, "wrong-guess")
        return time.perf_counter() - start

    no_such_user_times = [timed("nobody-at-all") for _ in range(50)]
    wrong_password_times = [timed("alice") for _ in range(50)]

    no_such_user_median = statistics.median(no_such_user_times)
    wrong_password_median = statistics.median(wrong_password_times)
    ratio = max(no_such_user_median, wrong_password_median) / max(
        min(no_such_user_median, wrong_password_median), 1e-9
    )
    assert ratio < 5  # generous tolerance — proving "comparable", not "identical"


# --------------------------------------------------------------------- change_password


def test_change_password_wrong_old_password_raises_validation_error() -> None:
    user = get_user_model().objects.create_user(username="alice", password="original-password")
    with pytest.raises(ValidationError) as excinfo:
        PasswordService.change_password(user, "not-the-old-one", "a-new-strong-password-99")
    assert excinfo.value.code == "invalid_old_password"


@override_settings(
    AUTH_PASSWORD_VALIDATORS=[
        {
            "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
            "OPTIONS": {"min_length": 12},
        }
    ]
)
def test_change_password_weak_new_password_raises_validation_error() -> None:
    # tests.backend.settings never sets AUTH_PASSWORD_VALIDATORS (Django's true default is an
    # EMPTY list, not the four-validator set a fresh `startproject` template adds) — this test
    # proves change_password actually calls validate_password() with whatever the host
    # configures, not that any specific weak password universally fails.
    user = get_user_model().objects.create_user(username="alice", password="original-password")
    with pytest.raises(ValidationError):
        PasswordService.change_password(user, "original-password", "short")


def test_change_password_success_updates_the_hash() -> None:
    user = get_user_model().objects.create_user(username="alice", password="original-password")
    PasswordService.change_password(user, "original-password", "a-new-strong-password-99")
    user.refresh_from_db()
    assert user.check_password("a-new-strong-password-99")
    assert not user.check_password("original-password")


def test_change_password_revokes_every_session_and_fires_password_changed_after_revocation() -> (
    None
):
    user = get_user_model().objects.create_user(username="alice", password="original-password")
    for _ in range(3):
        TokenService.issue_token_pair(user, request_meta=_request_meta())
    assert AuthSession.objects.filter(user=user, revoked_at__isnull=True).count() == 3

    with captured_ordered(session_revoked, password_changed) as order:
        PasswordService.change_password(user, "original-password", "a-new-strong-password-99")

    assert AuthSession.objects.filter(user=user, revoked_at__isnull=True).count() == 0
    assert AuthSession.objects.filter(user=user, revoked_reason="password_changed").count() == 3

    signal_sequence = [signal for signal, _ in order]
    assert signal_sequence == [session_revoked, session_revoked, session_revoked, password_changed]
    *_, (last_signal, last_payload) = order
    assert last_signal is password_changed
    assert last_payload == {"sender": get_user_model(), "user_id": user.pk}


# --------------------------------------------------------------------- request_reset


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_request_reset_never_raises_for_an_unknown_identifier() -> None:
    before_count = OtpChallenge.objects.count()
    PasswordService.request_reset("nobody-at-all")
    assert OtpChallenge.objects.count() == before_count  # decoy path — no row for an unknown one


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_request_reset_uses_the_users_own_email_value_not_the_identifier() -> None:
    from jwt_multiauth.signals import email_otp_requested

    UserFactory(username="alice", email="alice@example.com")

    with captured(email_otp_requested) as received:
        PasswordService.request_reset("alice")

    assert len(received) == 1
    assert received[0]["destination"] == "alice@example.com"
    assert received[0]["purpose"] == "password_reset"


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_request_reset_resolved_user_with_no_usable_contact_value_falls_back_to_decoy_shape() -> (
    None
):
    UserFactory(username="alice", email="")  # resolves, but nothing to send to
    before_count = OtpChallenge.objects.count()

    PasswordService.request_reset("alice")

    assert OtpChallenge.objects.count() == before_count


def test_request_reset_raises_improperly_configured_with_no_usable_channel_at_all() -> None:
    # Default JWT_MULTIAUTH={} leaves both EMAIL_FIELD/PHONE_FIELD unset — a config gap
    # independent of the identifier, never a silent, useless "200 that sends nothing".
    with pytest.raises(ImproperlyConfigured):
        PasswordService.request_reset("anyone")


# --------------------------------------------------------------------- confirm_reset


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_confirm_reset_happy_path_sets_password_and_revokes_sessions() -> None:
    user = UserFactory(username="alice", email="alice@example.com")
    TokenService.issue_token_pair(user, request_meta=_request_meta())
    from jwt_multiauth.signals import email_otp_requested

    with captured(email_otp_requested) as received:
        request_result = OtpService.request(
            "alice@example.com", channel="email", purpose="password_reset"
        )
    code = received[0]["code"]

    with captured_ordered(session_revoked, password_changed) as order:
        PasswordService.confirm_reset(
            request_result.challenge_id, code=code, new_password="a-new-strong-password-99"
        )

    user.refresh_from_db()
    assert user.check_password("a-new-strong-password-99")
    assert AuthSession.objects.filter(user=user, revoked_at__isnull=True).count() == 0
    assert [signal for signal, _ in order][-1] is password_changed


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_confirm_reset_wrong_purpose_raises_challenge_invalid() -> None:
    UserFactory(username="alice", email="alice@example.com")
    from jwt_multiauth.signals import email_otp_requested

    with captured(email_otp_requested) as received:
        request_result = OtpService.request("alice@example.com", channel="email", purpose="login")
    code = received[0]["code"]

    with pytest.raises(ChallengeInvalid):
        PasswordService.confirm_reset(
            request_result.challenge_id, code=code, new_password="a-new-strong-password-99"
        )


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {"EMAIL_FIELD": "email", "AUTO_PROVISION_METHODS": ["email_otp"]},
    }
)
def test_confirm_reset_rejects_an_auto_provisioned_challenge() -> None:
    # An unresolved identifier on an AUTO_PROVISION_METHODS channel is a real, persisted
    # challenge (docs/CONTRACT.md §11 item 19), and OtpService.verify() provisions the account
    # unconditionally on a successful compare regardless of purpose — that side effect already
    # happened by the time confirm_reset can inspect it. What confirm_reset refuses is to ALSO
    # set a password for that just-minted, still-unproven identity.
    from jwt_multiauth.signals import email_otp_requested

    with captured(email_otp_requested) as received:
        request_result = OtpService.request(
            "brand-new@example.com", channel="email", purpose="password_reset"
        )
    code = received[0]["code"]

    with pytest.raises(ChallengeInvalid):
        PasswordService.confirm_reset(
            request_result.challenge_id, code=code, new_password="a-new-strong-password-99"
        )
    # The account now exists (an inevitable side effect of OtpService.verify()'s own contract)
    # but was never touched by the rejected reset — no usable password was ever set for it.
    provisioned = get_user_model().objects.get(email="brand-new@example.com")
    assert provisioned.has_usable_password() is False
