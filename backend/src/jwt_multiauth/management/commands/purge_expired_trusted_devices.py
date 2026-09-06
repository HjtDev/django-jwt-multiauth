"""A thin, Celery-free driver for the trusted-device purge — for a host running no Celery worker
at all. Calls ``jwt_multiauth.tasks._purge_expired_trusted_devices`` directly (the exact same
function the ``purge_expired_trusted_devices`` Celery task calls), never a re-implementation of
its query, so the two drivers can never drift apart.

Intended to be run from plain cron daily at 03:30, matching ``docs/CONTRACT.md`` §8's recommended
Celery beat schedule for the same task.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from jwt_multiauth.tasks import _purge_expired_trusted_devices


class Command(BaseCommand):
    help = (
        "Deletes TrustedDevice rows well past expires_at. Equivalent to a single run of the "
        "jwt_multiauth.tasks.purge_expired_trusted_devices Celery task, for a host running no "
        "worker."
    )

    def handle(self, *args: Any, **options: Any) -> None:
        purged_count = _purge_expired_trusted_devices()
        self.stdout.write(self.style.SUCCESS(f"Purged {purged_count} expired trusted device(s)."))
