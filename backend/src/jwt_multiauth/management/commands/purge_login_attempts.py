"""A thin, Celery-free driver for the login-attempt purge — for a host running no Celery worker at
all. Calls ``jwt_multiauth.tasks._purge_login_attempts`` directly (the exact same function the
``purge_login_attempts`` Celery task calls), never a re-implementation of its query, so the two
drivers can never drift apart.

Intended to be run from plain cron daily at 03:15, matching ``docs/CONTRACT.md`` §8's recommended
Celery beat schedule for the same task. Honors ``JWT_MULTIAUTH["LOGIN_ATTEMPT_RETENTION_DAYS"]``.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from jwt_multiauth.tasks import _purge_login_attempts


class Command(BaseCommand):
    help = (
        "Deletes LoginAttempt rows older than LOGIN_ATTEMPT_RETENTION_DAYS. Equivalent to a "
        "single run of the jwt_multiauth.tasks.purge_login_attempts Celery task, for a host "
        "running no worker."
    )

    def handle(self, *args: Any, **options: Any) -> None:
        purged_count = _purge_login_attempts()
        self.stdout.write(self.style.SUCCESS(f"Purged {purged_count} login attempt(s)."))
