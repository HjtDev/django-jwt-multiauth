"""``AppConfig`` for the test-only swapped user model (``tests/backend/settings_dynamic_user.py``).

Mirrors the shape a real ``django-dynamic-user`` host would have: its own installed app owning
``AUTH_USER_MODEL``, adding a unique, nullable ``phone`` field — this is what proves
``jwt_multiauth.checks``' field-resolution machinery actually works against a real subclassed
model, not just the one every fresh Django project ships with (``django.contrib.auth.User``,
exercised by the default ``tests/backend/settings.py`` leg).
"""

from __future__ import annotations

from django.apps import AppConfig


class PhoneUserAppConfig(AppConfig):
    name = "tests.backend.phone_user_app"
    label = "phone_user_app"
    default_auto_field = "django.db.models.BigAutoField"
