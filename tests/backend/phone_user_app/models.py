"""A tiny, real ``AbstractUser`` subclass adding a unique, nullable ``phone`` field — the shape a
``django-dynamic-user`` host actually has. Used only by ``tests/backend/settings_dynamic_user.py``
(``AUTH_USER_MODEL = "phone_user_app.User"``), never by the default settings leg.
"""

from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    phone = models.CharField(max_length=32, unique=True, null=True, blank=True)
