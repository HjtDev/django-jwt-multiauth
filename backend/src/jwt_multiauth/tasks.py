"""Celery tasks, behind the ``celery`` extra only.

Implements ``docs/CONTRACT.md`` §8's four purge tasks: ``purge_expired_otp_challenges``,
``purge_expired_sessions``, ``purge_login_attempts`` (respecting
``JWT_MULTIAUTH["LOGIN_ATTEMPT_RETENTION_DAYS"]``), ``purge_expired_trusted_devices``. Each pairs
with a ``management/commands/`` entry calling the exact same underlying ``_purge_*`` function —
never a duplicated query — for a host running no Celery worker at all; this app is fully
functional without one.

This module must not hard-import ``celery`` at module scope — a host without the ``celery`` extra
installed must be able to import every other part of this package without error. When ``celery``
is not installed, ``shared_task`` degrades to a no-op decorator, mirroring
``django-dynamic-user.tasks``'s own precedent, so the ``@shared_task``-wrapped functions below stay
plain, directly callable functions either way.

Every ``_purge_*`` deletes row-by-row inside its own ``try/except``, continuing past a single row's
failure rather than aborting the batch (docs/CONTRACT.md §8) — a bulk ``queryset.delete()`` cannot
offer that guarantee, since one row raising (e.g. an integrity error from a concurrent write)
would abort the whole statement.

The three purge windows not backed by a settings key (``_OTP_GRACE``, ``_SESSION_GRACE``,
``_TRUSTED_DEVICE_GRACE``) are deliberate non-settings, same precedent as ``otp._AMBIGUOUS`` and
the non-configurable hash algorithm (docs/CONTRACT.md §11 item 22) — a host wanting a different
grace window is expected to run its own equivalent query, not configure this app's purge
scheduling to the day.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import timedelta
from typing import Any, Final, TypeVar

from django.utils import timezone

from jwt_multiauth import conf
from jwt_multiauth.models import AuthSession, LoginAttempt, OtpChallenge, TrustedDevice

logger = logging.getLogger(__name__)

_F = TypeVar("_F", bound=Callable[..., Any])

try:
    from celery import shared_task
except ImportError:  # celery extra not installed

    def shared_task(*args: Any, **kwargs: Any) -> Callable[[_F], _F]:
        """Degrades ``@shared_task(...)`` to a no-op decorator when ``celery`` isn't installed,
        so the functions below stay importable and directly callable either way."""

        def decorator(func: _F) -> _F:
            return func

        return decorator


#: Deliberate non-settings — see module docstring. An ``OtpChallenge`` is short-lived by nature
#: (``OTP.DEFAULTS.TTL_SECONDS`` is minutes, not days), so its grace window is much shorter than
#: the other two, which a support agent may still want to inspect for a while after expiry.
_OTP_GRACE: Final[timedelta] = timedelta(days=1)
_SESSION_GRACE: Final[timedelta] = timedelta(days=7)
_TRUSTED_DEVICE_GRACE: Final[timedelta] = timedelta(days=7)


def _purge_by_pks(queryset: Any, *, batch_size: int = 500, description: str) -> int:
    """Deletes every row in ``queryset`` one primary key at a time, continuing past a single
    row's failure rather than letting one bad row abort the whole batch. Returns the count
    actually deleted. ``queryset`` must already be filtered to exactly the rows that should go —
    this helper adds no filtering of its own.
    """
    model = queryset.model
    pks = list(queryset.values_list("pk", flat=True).iterator(chunk_size=batch_size))

    purged = 0
    for pk in pks:
        try:
            deleted_count, _ = model.objects.filter(pk=pk).delete()
        except Exception:
            logger.exception("%s: failed to delete %s pk=%s", description, model.__name__, pk)
            continue
        purged += deleted_count
    return purged


def _purge_expired_otp_challenges() -> int:
    """Deletes ``OtpChallenge`` rows whose ``expires_at`` is more than ``_OTP_GRACE`` in the
    past — well past expiry, never a row that merely expired a moment ago.
    """
    cutoff = timezone.now() - _OTP_GRACE
    return _purge_by_pks(
        OtpChallenge.objects.filter(expires_at__lt=cutoff),
        description="purge_expired_otp_challenges",
    )


def _purge_expired_sessions() -> int:
    """Deletes ``AuthSession`` rows whose ``expires_at`` is more than ``_SESSION_GRACE`` in the
    past — filtered on ``expires_at`` ONLY, never ``revoked_at``. A session revoked (logout,
    reuse detection, password change) but not yet past its own ``expires_at`` stays visible to an
    admin/support agent, per docs/CONTRACT.md §8's own explicit instruction.
    """
    cutoff = timezone.now() - _SESSION_GRACE
    return _purge_by_pks(
        AuthSession.objects.filter(expires_at__lt=cutoff),
        description="purge_expired_sessions",
    )


def _purge_login_attempts() -> int:
    """Deletes ``LoginAttempt`` rows older than ``JWT_MULTIAUTH["LOGIN_ATTEMPT_RETENTION_DAYS"]``
    — the one purge window that IS a real setting (docs/CONTRACT.md §6/§11 item 6), read fresh on
    every call rather than snapshotted, so a host changing the retention period takes effect on
    the very next run.
    """
    retention_days = conf.get_setting("LOGIN_ATTEMPT_RETENTION_DAYS")
    cutoff = timezone.now() - timedelta(days=retention_days)
    return _purge_by_pks(
        LoginAttempt.objects.filter(created_at__lt=cutoff),
        description="purge_login_attempts",
    )


def _purge_expired_trusted_devices() -> int:
    """Deletes ``TrustedDevice`` rows whose ``expires_at`` is more than ``_TRUSTED_DEVICE_GRACE``
    in the past.
    """
    cutoff = timezone.now() - _TRUSTED_DEVICE_GRACE
    return _purge_by_pks(
        TrustedDevice.objects.filter(expires_at__lt=cutoff),
        description="purge_expired_trusted_devices",
    )


@shared_task(name="jwt_multiauth.tasks.purge_expired_otp_challenges")
def purge_expired_otp_challenges() -> int:
    """Deletes ``OtpChallenge`` rows well past ``expires_at``. Continues past a single row's
    failure rather than aborting the batch. Returns the count purged."""
    return _purge_expired_otp_challenges()


@shared_task(name="jwt_multiauth.tasks.purge_expired_sessions")
def purge_expired_sessions() -> int:
    """Deletes ``AuthSession`` rows well past ``expires_at`` ONLY — never a merely-revoked-but-
    not-yet-expired row, since an admin/support agent may still want to see it. Returns the count
    purged."""
    return _purge_expired_sessions()


@shared_task(name="jwt_multiauth.tasks.purge_login_attempts")
def purge_login_attempts() -> int:
    """Deletes ``LoginAttempt`` rows older than ``LOGIN_ATTEMPT_RETENTION_DAYS``. Returns the
    count purged."""
    return _purge_login_attempts()


@shared_task(name="jwt_multiauth.tasks.purge_expired_trusted_devices")
def purge_expired_trusted_devices() -> int:
    """Deletes ``TrustedDevice`` rows well past ``expires_at``. Returns the count purged."""
    return _purge_expired_trusted_devices()
