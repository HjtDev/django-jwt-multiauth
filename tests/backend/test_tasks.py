"""Proves ``tasks.py``'s four purge functions: rows inside the grace window survive, rows past it
are purged, a revoked-but-unexpired ``AuthSession`` is never touched, ``purge_login_attempts``
honors ``LOGIN_ATTEMPT_RETENTION_DAYS``, and a single row's delete failure never aborts the batch.
The ``@shared_task``-wrapped public functions are proven to delegate to the exact same
``_purge_*`` function, marked ``requires_extra`` since they exercise the real ``celery`` import
path; the underlying ``_purge_*`` functions themselves carry no such marker, so the bare-install
leg (no ``celery`` extra) still covers the actual purge logic.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

import pytest
from django.test import override_settings
from django.utils import timezone

from jwt_multiauth import tasks
from jwt_multiauth.factories import (
    AuthSessionFactory,
    LoginAttemptFactory,
    OtpChallengeFactory,
    TrustedDeviceFactory,
)
from jwt_multiauth.models import AuthSession, LoginAttempt, OtpChallenge, TrustedDevice

pytestmark = pytest.mark.django_db


def test_purge_expired_otp_challenges_deletes_only_rows_past_the_grace_window() -> None:
    now = timezone.now()
    survivor = OtpChallengeFactory(expires_at=now - timedelta(hours=1))
    victim = OtpChallengeFactory(expires_at=now - tasks._OTP_GRACE - timedelta(seconds=1))

    purged = tasks._purge_expired_otp_challenges()

    assert purged == 1
    assert OtpChallenge.objects.filter(pk=survivor.pk).exists()
    assert not OtpChallenge.objects.filter(pk=victim.pk).exists()


def test_purge_expired_sessions_never_touches_a_revoked_but_unexpired_session() -> None:
    now = timezone.now()
    revoked_but_live = AuthSessionFactory(expires_at=now + timedelta(days=1))
    revoked_but_live.revoked_at = now
    revoked_but_live.revoked_reason = "user_logout"
    revoked_but_live.save(update_fields=["revoked_at", "revoked_reason"])

    expired = AuthSessionFactory(expires_at=now - tasks._SESSION_GRACE - timedelta(seconds=1))

    purged = tasks._purge_expired_sessions()

    assert purged == 1
    assert AuthSession.objects.filter(pk=revoked_but_live.pk).exists()
    assert not AuthSession.objects.filter(pk=expired.pk).exists()


@override_settings(JWT_MULTIAUTH={"LOGIN_ATTEMPT_RETENTION_DAYS": 30})
def test_purge_login_attempts_honors_the_configured_retention_days() -> None:
    now = timezone.now()
    recent = LoginAttemptFactory()
    old = LoginAttemptFactory()
    LoginAttempt.objects.filter(pk=recent.pk).update(created_at=now - timedelta(days=1))
    LoginAttempt.objects.filter(pk=old.pk).update(created_at=now - timedelta(days=31))

    purged = tasks._purge_login_attempts()

    assert purged == 1
    assert LoginAttempt.objects.filter(pk=recent.pk).exists()
    assert not LoginAttempt.objects.filter(pk=old.pk).exists()


def test_purge_expired_trusted_devices_deletes_only_rows_past_the_grace_window() -> None:
    now = timezone.now()
    survivor = TrustedDeviceFactory(expires_at=now - timedelta(hours=1), token_hash="1" * 64)
    victim = TrustedDeviceFactory(
        expires_at=now - tasks._TRUSTED_DEVICE_GRACE - timedelta(seconds=1),
        token_hash="2" * 64,
    )

    purged = tasks._purge_expired_trusted_devices()

    assert purged == 1
    assert TrustedDevice.objects.filter(pk=survivor.pk).exists()
    assert not TrustedDevice.objects.filter(pk=victim.pk).exists()


def test_purge_by_pks_continues_past_a_single_row_failure() -> None:
    now = timezone.now()
    bad = OtpChallengeFactory(expires_at=now - tasks._OTP_GRACE - timedelta(seconds=1))
    good = OtpChallengeFactory(expires_at=now - tasks._OTP_GRACE - timedelta(seconds=1))

    real_filter = OtpChallenge.objects.filter

    class _FlakyQuerySet:
        def delete(self) -> tuple[int, dict[str, int]]:
            raise RuntimeError("boom")

    def flaky_filter(*args: object, **kwargs: object) -> object:
        if kwargs.get("pk") == bad.pk:
            return _FlakyQuerySet()
        return real_filter(*args, **kwargs)

    with patch("jwt_multiauth.tasks.OtpChallenge.objects.filter", side_effect=flaky_filter):
        purged = tasks._purge_expired_otp_challenges()

    assert purged == 1  # only `good` counted — `bad`'s failure never aborted the batch
    assert not OtpChallenge.objects.filter(pk=good.pk).exists()
    assert OtpChallenge.objects.filter(pk=bad.pk).exists()  # never actually deleted


@pytest.mark.requires_extra
def test_shared_task_wrapper_delegates_to_the_same_underlying_function() -> None:
    now = timezone.now()
    OtpChallengeFactory(expires_at=now - tasks._OTP_GRACE - timedelta(seconds=1))

    assert tasks.purge_expired_otp_challenges() == 1
    assert OtpChallenge.objects.count() == 0
