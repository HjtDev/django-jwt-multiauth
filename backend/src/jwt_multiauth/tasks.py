"""Celery tasks, behind the ``celery`` extra only.

Phase 5 implements four ``@shared_task``s per ``docs/CONTRACT.md`` §8:
``purge_expired_otp_challenges``, ``purge_expired_sessions``, ``purge_login_attempts``
(respecting ``JWT_MULTIAUTH["LOGIN_ATTEMPT_RETENTION_DAYS"]``), and
``purge_expired_trusted_devices``. Each pairs with a ``management/commands/`` entry calling the
same underlying query, for a host running no Celery worker at all — this app is fully functional
without one.

This module must not hard-import ``celery`` at module scope — a host without the ``celery``
extra installed must be able to import every other part of this package without error. Mirrors
``django-dynamic-user.tasks``'s own no-op-decorator fallback for exactly this reason.
"""
