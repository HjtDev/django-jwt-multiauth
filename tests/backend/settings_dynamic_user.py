"""The swapped-user leg: ``AUTH_USER_MODEL`` points at ``phone_user_app.User`` (a real
``AbstractUser`` subclass with a unique, nullable ``phone`` field), and ``"phone_otp"`` is enabled
— this is what proves ``jwt_multiauth.checks``' field-resolution machinery, and later phases' OTP
code, actually work against a real non-default user model, not just the one every fresh Django
project ships with.

Imports everything from ``tests.backend.settings`` and overrides only what this leg needs. The
partial ``USER_FIELDS`` override below (``PHONE_FIELD`` only) is a deliberate test of
``conf.py``'s deep-merge behavior — ``EMAIL_FIELD``/``IDENTIFIER_FIELDS`` must resolve to their
documented defaults, not go missing, per ``conf.py``'s own docstring. See
``tests/backend/test_dynamic_user.py``.
"""

from __future__ import annotations

from tests.backend.settings import *  # noqa: F403 -- deliberate wildcard re-export, see module docstring
from tests.backend.settings import INSTALLED_APPS as _INSTALLED_APPS

INSTALLED_APPS = [*_INSTALLED_APPS, "tests.backend.phone_user_app"]

AUTH_USER_MODEL = "phone_user_app.User"

JWT_MULTIAUTH = {
    "ALLOWED_AUTH_METHODS": ["password", "phone_otp"],
    "USER_FIELDS": {"PHONE_FIELD": "phone"},
}
