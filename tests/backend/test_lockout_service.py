"""Proves ``services.LockoutService``: ``record_attempt`` always writes a ``LoginAttempt`` row,
fires ``login_failed`` on every failure, and fires ``account_locked`` EXACTLY once the moment
``LOCKOUT.MAX_ATTEMPTS`` is reached — never again for the same lock. All three ``LOCK_SCOPE``
modes are proven independently: ``"identifier"`` locks across many source IPs, ``"ip"`` locks
across many different identifiers, ``"identifier_and_ip"`` requires both to match. ``unlock``
clears both the counter and the lock, and a post-unlock failure starts counting from one again.
"""

from __future__ import annotations

import pytest
from django.core.cache import cache
from django.test import override_settings

from jwt_multiauth.factories import UserFactory
from jwt_multiauth.models import LoginAttempt
from jwt_multiauth.services import LockoutService, LockStatus
from jwt_multiauth.signals import account_locked, login_failed
from tests.backend.conftest import captured

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    # LocMemCache persists for the process lifetime — every test needs a clean counter/lock
    # namespace, since appkit.cache's own namespace-version seeding otherwise leaks between tests.
    cache.clear()
    yield
    cache.clear()


def _lockout_settings(**overrides: object) -> dict[str, object]:
    return {
        "LOCKOUT": {
            "MAX_ATTEMPTS": 3,
            "WINDOW_SECONDS": 300,
            "LOCK_DURATION_SECONDS": 300,
            "LOCK_SCOPE": "identifier_and_ip",
            **overrides,
        }
    }


# --------------------------------------------------------------------- record_attempt


@override_settings(JWT_MULTIAUTH=_lockout_settings())
def test_record_attempt_always_writes_a_login_attempt_row_on_success_too() -> None:
    user = UserFactory(username="alice")
    LockoutService.record_attempt("alice", ip="203.0.113.1", success=True)

    row = LoginAttempt.objects.get(identifier="alice")
    assert row.success is True
    assert row.failure_reason is None
    assert row.user_id == user.pk


@override_settings(JWT_MULTIAUTH=_lockout_settings())
def test_record_attempt_failure_requires_a_reason() -> None:
    with pytest.raises(ValueError, match="reason"):
        LockoutService.record_attempt("alice", ip="203.0.113.1", success=False)


@override_settings(JWT_MULTIAUTH=_lockout_settings())
def test_record_attempt_rejects_an_unknown_method() -> None:
    with pytest.raises(ValueError, match="method"):
        LockoutService.record_attempt(
            "alice", ip="203.0.113.1", success=True, method="not-a-real-method"
        )


@override_settings(JWT_MULTIAUTH=_lockout_settings())
def test_record_attempt_fires_login_failed_on_every_failure() -> None:
    with captured(login_failed) as received:
        LockoutService.record_attempt(
            "alice", ip="203.0.113.1", success=False, reason="wrong_credential"
        )

    assert received == [
        {
            "sender": LoginAttempt,
            "identifier": "alice",
            "reason": "wrong_credential",
            "ip": "203.0.113.1",
        }
    ]


@override_settings(JWT_MULTIAUTH=_lockout_settings())
def test_record_attempt_fires_account_locked_exactly_once_at_max_attempts() -> None:
    user = UserFactory(username="alice")

    with captured(account_locked) as locked_events:
        for _ in range(3):
            LockoutService.record_attempt(
                "alice", ip="203.0.113.1", success=False, reason="wrong_credential"
            )

    assert len(locked_events) == 1
    assert locked_events[0]["user_id"] == user.pk
    assert locked_events[0]["identifier"] == "alice"
    assert locked_events[0]["scope"] == "identifier_and_ip"
    assert locked_events[0]["until"] is not None


@override_settings(JWT_MULTIAUTH=_lockout_settings())
def test_record_attempt_never_refires_account_locked_for_an_already_locked_identifier() -> None:
    for _ in range(3):
        LockoutService.record_attempt(
            "alice", ip="203.0.113.1", success=False, reason="wrong_credential"
        )

    with captured(account_locked) as locked_events:
        LockoutService.record_attempt(
            "alice", ip="203.0.113.1", success=False, reason="wrong_credential"
        )

    assert locked_events == []


@override_settings(JWT_MULTIAUTH=_lockout_settings())
def test_account_locked_has_no_user_id_for_an_identifier_that_never_resolved() -> None:
    with captured(account_locked) as locked_events:
        for _ in range(3):
            LockoutService.record_attempt(
                "nobody-at-all", ip="203.0.113.1", success=False, reason="no_such_identifier"
            )

    assert locked_events[0]["user_id"] is None


# --------------------------------------------------------------------- is_locked


@override_settings(JWT_MULTIAUTH=_lockout_settings())
def test_is_locked_false_before_max_attempts() -> None:
    LockoutService.record_attempt(
        "alice", ip="203.0.113.1", success=False, reason="wrong_credential"
    )
    assert LockoutService.is_locked("alice", ip="203.0.113.1") == LockStatus(
        locked=False, until=None
    )


# --------------------------------------------------------------------- LOCK_SCOPE modes


@override_settings(JWT_MULTIAUTH=_lockout_settings(LOCK_SCOPE="identifier"))
def test_lock_scope_identifier_locks_across_many_distinct_source_ips() -> None:
    for i in range(3):
        LockoutService.record_attempt(
            "victim", ip=f"203.0.113.{i}", success=False, reason="wrong_credential"
        )

    # Even a brand-new, never-before-seen IP sees the SAME identifier as locked.
    assert LockoutService.is_locked("victim", ip="10.0.0.99").locked is True


@override_settings(JWT_MULTIAUTH=_lockout_settings(LOCK_SCOPE="ip"))
def test_lock_scope_ip_locks_across_many_different_identifiers() -> None:
    for i in range(3):
        LockoutService.record_attempt(
            f"user{i}", ip="203.0.113.9", success=False, reason="wrong_credential"
        )

    # The SAME source IP is locked regardless of which identifier is asked about now.
    assert LockoutService.is_locked("brand-new-identifier", ip="203.0.113.9").locked is True
    assert LockoutService.is_locked("brand-new-identifier", ip="10.0.0.1").locked is False


@override_settings(JWT_MULTIAUTH=_lockout_settings(LOCK_SCOPE="identifier_and_ip"))
def test_lock_scope_identifier_and_ip_requires_both_to_match() -> None:
    for _ in range(3):
        LockoutService.record_attempt(
            "alice", ip="203.0.113.1", success=False, reason="wrong_credential"
        )

    assert LockoutService.is_locked("alice", ip="203.0.113.1").locked is True
    # The SAME identifier failing from a DIFFERENT IP is not locked under this scope.
    assert LockoutService.is_locked("alice", ip="203.0.113.2").locked is False


def test_unknown_lock_scope_raises_improperly_configured() -> None:
    from django.core.exceptions import ImproperlyConfigured

    with override_settings(JWT_MULTIAUTH=_lockout_settings(LOCK_SCOPE="not-a-real-scope")):
        with pytest.raises(ImproperlyConfigured):
            LockoutService.is_locked("alice", ip="203.0.113.1")


# --------------------------------------------------------------------- unlock


@override_settings(JWT_MULTIAUTH=_lockout_settings())
def test_unlock_clears_the_lock_and_resets_the_counter() -> None:
    for _ in range(3):
        LockoutService.record_attempt(
            "alice", ip="203.0.113.1", success=False, reason="wrong_credential"
        )
    assert LockoutService.is_locked("alice", ip="203.0.113.1").locked is True

    LockoutService.unlock("alice")

    assert LockoutService.is_locked("alice", ip="203.0.113.1").locked is False

    # Two more failures (fewer than MAX_ATTEMPTS) must NOT relock — proves the counter itself was
    # reset to zero, not just the lock key cleared while the old count silently survived.
    with captured(account_locked) as locked_events:
        for _ in range(2):
            LockoutService.record_attempt(
                "alice", ip="203.0.113.1", success=False, reason="wrong_credential"
            )
    assert locked_events == []

    LockoutService.record_attempt(
        "alice", ip="203.0.113.1", success=False, reason="wrong_credential"
    )
    assert LockoutService.is_locked("alice", ip="203.0.113.1").locked is True


@override_settings(JWT_MULTIAUTH=_lockout_settings())
def test_unlock_is_idempotent() -> None:
    LockoutService.unlock("never-locked-anyone")
    LockoutService.unlock("never-locked-anyone")  # must not raise
