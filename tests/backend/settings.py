"""Test settings module — the default leg: Django's own ``django.contrib.auth.User``, no swap.

``APP-DESIGN.md`` §7.1's shape, kept minimal (no host-specific app dropped in "just in case") plus
exactly what makes ``django-admin check`` come out clean against ``appkit``'s own registered
system checks (``appkit.E001``/``E002``, ``appkit.W002``) — read directly from the installed
``appkit.checks`` source, not assumed.

``JWT_MULTIAUTH`` is deliberately left at ``{}`` here — this leg proves the zero-config default
path (``ALLOWED_AUTH_METHODS = ["password"]``, ``TWO_FACTOR["POLICY"] = "off"``) is genuinely
clean, with no override masking a check that should fire on a fresh install.
``tests/backend/settings_dynamic_user.py`` imports everything from this module and overrides only
what the swapped-user leg needs.
"""

from __future__ import annotations

import os
from typing import Any

from jwt_multiauth import throttling

SECRET_KEY = "test-only-not-a-secret"
DEBUG = False
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.admin",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "drf_spectacular",
    "appkit",
    "jwt_multiauth",
]

# appkit.request_id.RequestIDMiddleware right after SecurityMiddleware — avoids appkit.E001
# (missing entirely) and appkit.W002 (present but ordered before SecurityMiddleware).
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "appkit.request_id.RequestIDMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "tests.backend.urls"

# The admin needs these four context processors, or admin.E403 fires at check time.
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.debug",
            ],
        },
    },
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "test_jwt_multiauth"),
        "USER": os.environ.get("POSTGRES_USER", "postgres"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "postgres"),
        "HOST": os.environ.get("POSTGRES_HOST", "localhost"),
        "PORT": os.environ.get("POSTGRES_PORT", "55435"),
    }
}

# Every throttling.py constant needs a matching entry here — appkit.checks.check_throttle_scopes
# (appkit.W004) warns at manage.py check time for any that's missing, and test_throttling.py
# asserts this dict's keys are exactly throttling.py's constants, so the two can never drift.
DEFAULT_THROTTLE_RATES = {
    throttling.LOGIN: "20/min",
    throttling.PASSWORD_CHANGE: "10/min",
    throttling.PASSWORD_RESET_REQUEST: "10/min",
    throttling.PASSWORD_RESET_CONFIRM: "10/min",
    throttling.OTP_REQUEST: "10/min",
    throttling.OTP_VERIFY: "20/min",
    throttling.OTP_RESEND: "5/min",
    throttling.TOKEN_REFRESH: "60/min",
    throttling.TOKEN_VERIFY: "60/min",
    throttling.LOGOUT: "30/min",
    throttling.LOGOUT_ALL: "10/min",
    throttling.TWO_FACTOR_OTP_REQUEST: "10/min",
    throttling.TWO_FACTOR_STATUS: "60/min",
    throttling.TWO_FACTOR_TOTP_ENROLL: "10/min",
    throttling.TWO_FACTOR_TOTP_CONFIRM: "10/min",
    throttling.TWO_FACTOR_DISABLE: "10/min",
    throttling.TWO_FACTOR_RECOVERY_REGENERATE: "5/min",
    throttling.TWO_FACTOR_VERIFY: "20/min",
    throttling.SESSIONS_LIST: "60/min",
    throttling.SESSIONS_REVOKE: "20/min",
    throttling.TRUSTED_DEVICES_LIST: "60/min",
    throttling.TRUSTED_DEVICES_REVOKE: "20/min",
    throttling.VERIFY_CONTACT_REQUEST: "10/min",
    throttling.VERIFY_CONTACT_CONFIRM: "10/min",
    throttling.METHODS: "60/min",
    throttling.ADMIN_SESSIONS_LIST: "60/min",
    throttling.ADMIN_SESSIONS_REVOKE: "20/min",
    throttling.ADMIN_TRUSTED_DEVICES_LIST: "60/min",
    throttling.ADMIN_TRUSTED_DEVICES_REVOKE: "20/min",
    throttling.ADMIN_LOGIN_ATTEMPTS_LIST: "60/min",
    throttling.ADMIN_USER_SECURITY: "60/min",
    throttling.ADMIN_USER_UNLOCK: "20/min",
    throttling.ADMIN_TWO_FACTOR_FORCE_DISABLE: "10/min",
}

REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "appkit.exceptions.standard_exception_handler",
    # Matches APPKIT["TRUSTED_PROXY_COUNT"]'s own default (1) — avoids appkit.W006 once a later
    # phase's views declare throttle_classes.
    "NUM_PROXIES": 1,
    "DEFAULT_THROTTLE_RATES": DEFAULT_THROTTLE_RATES,
}

SPECTACULAR_SETTINGS = {
    "TITLE": "jwt_multiauth",
    "VERSION": "0.0.0",  # irrelevant here — the real version lives in pyproject.toml
    "COMPONENT_SPLIT_REQUEST": True,
    # Phase 7 introduces two DIFFERENT "method" fields with different choice sets —
    # TwoFactorDisableSerializer/TwoFactorVerifySerializer.method (all 4 TWO_FACTOR methods) vs
    # TwoFactorOtpRequestSerializer.method (only the two OTP-based ones) — drf-spectacular can't
    # auto-name both "MethodEnum", and --fail-on-warn treats its own auto-resolved collision name
    # as an error. Named explicitly here rather than left to warn-and-mangle.
    "ENUM_NAME_OVERRIDES": {
        "TwoFactorMethodEnum": ["totp", "email_otp", "phone_otp", "recovery_code"],
        "TwoFactorOtpRequestMethodEnum": ["email_otp", "phone_otp"],
        # Phase 8: OtpRequestSerializer.channel and VerifyContactRequestSerializer.field share
        # the identical ["email", "phone"] choice set under two different field names —
        # drf-spectacular's own collision-naming warning ("multiple names for the same choice
        # set"), pinned to one explicit name rather than left to its non-deterministic fallback.
        "OtpChannelEnum": ["email", "phone"],
    },
}

# JWT_MULTIAUTH deliberately absent/empty — see module docstring.
JWT_MULTIAUTH: dict[str, Any] = {}

# Fast hasher — this settings module is test-only, never shipped to a host.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

# A real, fixed Fernet key (`appkit.crypto.generate_key()`'s own output, pinned rather than
# regenerated per test run so a failure is reproducible) — ambient default so every TOTP-touching
# Phase 7 test doesn't need its own override_settings just to get keys.get_encryption_key() past
# ImproperlyConfigured. test_checks.py's own E004 test still explicitly overrides this to None to
# prove the unset-key path — an explicit override always wins over this module-level default.
JWT_MULTIAUTH_ENCRYPTION_KEY = "3vY0nq6hFZ8xqQqzQwYV1JGgqgLzZ3n1KxG2y3fQxCk="

STATIC_URL = "/static/"
