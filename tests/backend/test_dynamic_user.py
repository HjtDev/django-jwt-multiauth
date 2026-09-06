"""The dynamic-user leg — proves ``jwt_multiauth.checks``' field-resolution machinery, and the
``conf.py`` deep-merge it depends on, work against a real, non-default, subclassed user model with
a genuine unique ``phone`` field, not just a hand-rolled test double.

Guarded on the *resolved* ``settings.AUTH_USER_MODEL`` rather than the ``DJANGO_SETTINGS_MODULE``
environment variable: the default leg gets its settings module from ``pyproject.toml``'s
``DJANGO_SETTINGS_MODULE`` ini option, not the environment, so an env-var guard would read
``None`` there and skip for the wrong reason. Run with:

    DJANGO_SETTINGS_MODULE=tests.backend.settings_dynamic_user \\
      uv run pytest -k dynamic_user --no-cov
"""

from __future__ import annotations

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command

from jwt_multiauth import checks, conf

pytestmark = pytest.mark.skipif(
    settings.AUTH_USER_MODEL != "phone_user_app.User",
    reason="only meaningful under tests.backend.settings_dynamic_user",
)


def test_phone_field_resolves_unique_and_nullable() -> None:
    model = get_user_model()
    field = model._meta.get_field("phone")
    assert field.unique is True
    assert field.null is True


def test_phone_otp_is_active_and_field_requirement_check_is_clean() -> None:
    assert "phone_otp" in conf.get_setting("ALLOWED_AUTH_METHODS")
    assert checks.check_user_field_requirements(None) == []


def test_manage_py_check_equivalent_passes_cleanly() -> None:
    # call_command("check") raises CommandError on any Error-level system check — a clean run
    # here is the "manage.py check passes cleanly" gate this app's CLAUDE.md working agreement
    # names explicitly for this leg.
    call_command("check")


def test_partial_user_fields_override_leaves_siblings_at_their_defaults() -> None:
    # settings_dynamic_user.py overrides only USER_FIELDS.PHONE_FIELD — conf.py's deep merge
    # (docs/CONTRACT.md §2) must leave EMAIL_FIELD/IDENTIFIER_FIELDS at their documented defaults,
    # not blank them.
    user_fields = conf.get_setting("USER_FIELDS")
    assert user_fields["PHONE_FIELD"] == "phone"
    assert user_fields["EMAIL_FIELD"] is None
    assert user_fields["IDENTIFIER_FIELDS"] == ["username", "email"]
    assert user_fields["AUTO_PROVISION_METHODS"] == []
    assert user_fields["PROVISION_CALLBACK"] is None


@pytest.mark.django_db
def test_password_service_authenticate_works_against_the_swapped_user_model() -> None:
    from jwt_multiauth.services import PasswordService

    user = get_user_model().objects.create_user(username="phoneuser", password="a-strong-password")
    assert PasswordService.authenticate("phoneuser", "a-strong-password") == user
    assert PasswordService.authenticate("phoneuser", "wrong-password") is None
    assert PasswordService.authenticate("nobody-at-all", "whatever") is None


@pytest.mark.django_db
def test_lockout_service_resolves_the_user_for_phone_otp_against_the_swapped_model() -> None:
    from django.core.cache import cache

    from jwt_multiauth.models import LoginAttempt
    from jwt_multiauth.services import LockoutService

    cache.clear()
    user = get_user_model().objects.create_user(username="phoneuser", phone="+15551234567")

    LockoutService.record_attempt(
        "+15551234567",
        ip="203.0.113.1",
        success=False,
        method="phone_otp",
        reason="wrong_credential",
    )

    row = LoginAttempt.objects.get(identifier="+15551234567")
    assert row.user_id == user.pk
    assert row.method == "phone_otp"


@pytest.mark.django_db
def test_every_model_round_trips_a_row_against_the_swapped_user_model() -> None:
    from jwt_multiauth.factories import (
        AuthSessionFactory,
        LoginAttemptFactory,
        OtpChallengeFactory,
        RecoveryCodeFactory,
        TrustedDeviceFactory,
        TwoFactorDeviceFactory,
        VerifiedContactFactory,
    )

    user = get_user_model().objects.create_user(username="phoneuser", phone="+15551234567")

    assert OtpChallengeFactory(user=user).pk is not None
    assert AuthSessionFactory(user=user).pk is not None
    assert TwoFactorDeviceFactory(user=user).pk is not None
    assert RecoveryCodeFactory(user=user).pk is not None
    assert VerifiedContactFactory(user=user).pk is not None
    assert LoginAttemptFactory(user=user).pk is not None
    assert TrustedDeviceFactory(user=user).pk is not None
