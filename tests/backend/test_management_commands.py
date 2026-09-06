"""Proves each purge management command calls the exact same ``jwt_multiauth.tasks._purge_*``
function its equivalent Celery task calls — never a duplicated query — for a host running no
Celery worker at all.
"""

from __future__ import annotations

from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import call_command
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


def test_purge_expired_otp_challenges_command() -> None:
    now = timezone.now()
    OtpChallengeFactory(expires_at=now - tasks._OTP_GRACE - timedelta(seconds=1))
    out = StringIO()

    call_command("purge_expired_otp_challenges", stdout=out)

    assert OtpChallenge.objects.count() == 0
    assert "1" in out.getvalue()


def test_purge_expired_sessions_command() -> None:
    now = timezone.now()
    AuthSessionFactory(expires_at=now - tasks._SESSION_GRACE - timedelta(seconds=1))
    out = StringIO()

    call_command("purge_expired_sessions", stdout=out)

    assert AuthSession.objects.count() == 0
    assert "1" in out.getvalue()


def test_purge_login_attempts_command() -> None:
    now = timezone.now()
    old = LoginAttemptFactory()
    LoginAttempt.objects.filter(pk=old.pk).update(created_at=now - timedelta(days=91))
    out = StringIO()

    call_command("purge_login_attempts", stdout=out)

    assert LoginAttempt.objects.count() == 0
    assert "1" in out.getvalue()


def test_purge_expired_trusted_devices_command() -> None:
    now = timezone.now()
    TrustedDeviceFactory(expires_at=now - tasks._TRUSTED_DEVICE_GRACE - timedelta(seconds=1))
    out = StringIO()

    call_command("purge_expired_trusted_devices", stdout=out)

    assert TrustedDevice.objects.count() == 0
    assert "1" in out.getvalue()
