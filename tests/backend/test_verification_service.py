"""Proves ``services.VerificationService``: ``request_contact_verification`` delegates to
``OtpService.request`` with the user's CURRENT field value (never a decoy path — the caller is
already authenticated); ``confirm`` records a ``VerifiedContact`` row and fires
``contact_verified`` on success, and rejects a wrong-purpose challenge, a cross-user challenge,
and an auto-provisioned (``created=True``) challenge with the same ``ChallengeInvalid`` every
other rejection uses.
"""

from __future__ import annotations

import pytest
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.test import override_settings

from jwt_multiauth.factories import UserFactory
from jwt_multiauth.models import VerifiedContact
from jwt_multiauth.services import ChallengeInvalid, OtpService, VerificationService
from jwt_multiauth.signals import contact_verified, email_otp_requested
from tests.backend.conftest import captured

pytestmark = pytest.mark.django_db


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_request_contact_verification_uses_the_users_current_value() -> None:
    user = UserFactory(email="alice@example.com")

    with captured(email_otp_requested) as received:
        VerificationService.request_contact_verification(user, field="email")

    assert len(received) == 1
    assert received[0]["destination"] == "alice@example.com"
    assert received[0]["purpose"] == "verify_contact"
    assert received[0]["user_id"] == user.pk


def test_request_contact_verification_rejects_an_invalid_field_name() -> None:
    user = UserFactory()
    with pytest.raises(ValueError, match="'email' or 'phone'"):
        VerificationService.request_contact_verification(user, field="username")


def test_request_contact_verification_raises_when_the_field_is_unconfigured() -> None:
    user = UserFactory()
    with pytest.raises(ImproperlyConfigured):
        VerificationService.request_contact_verification(user, field="email")


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_request_contact_verification_raises_when_the_users_own_value_is_empty() -> None:
    user = UserFactory(email="")
    with pytest.raises(ValidationError):
        VerificationService.request_contact_verification(user, field="email")


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_confirm_happy_path_creates_verified_contact_and_fires_signal() -> None:
    user = UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        request_result = VerificationService.request_contact_verification(user, field="email")
    code = received[0]["code"]
    assert request_result.challenge_id == received[0]["challenge_id"]

    with captured(contact_verified) as verified:
        VerificationService.confirm(user, request_result.challenge_id, code=code)

    assert VerifiedContact.objects.filter(
        user=user, field="email", value="alice@example.com"
    ).exists()
    assert verified == [
        {
            "sender": VerifiedContact,
            "user_id": user.pk,
            "field": "email",
            "value": "alice@example.com",
        }
    ]


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_confirm_wrong_purpose_raises_challenge_invalid() -> None:
    user = UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        request_result = OtpService.request("alice@example.com", channel="email", purpose="login")
    code = received[0]["code"]

    with pytest.raises(ChallengeInvalid):
        VerificationService.confirm(user, request_result.challenge_id, code=code)


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_confirm_cross_user_challenge_raises_challenge_invalid() -> None:
    owner = UserFactory(email="alice@example.com")
    stranger = UserFactory(email="bob@example.com")
    with captured(email_otp_requested) as received:
        request_result = VerificationService.request_contact_verification(owner, field="email")
    code = received[0]["code"]

    with pytest.raises(ChallengeInvalid):
        VerificationService.confirm(stranger, request_result.challenge_id, code=code)


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {"EMAIL_FIELD": "email", "AUTO_PROVISION_METHODS": ["email_otp"]},
    }
)
def test_confirm_rejects_an_auto_provisioned_challenge() -> None:
    # OtpService.verify() itself records a VerifiedContact row AND provisions the user
    # unconditionally on a successful compare, regardless of purpose (docs/CONTRACT.md §4's own
    # OtpService.verify docstring) — both side effects already happened by the time confirm() can
    # inspect result.created. What confirm() refuses is to treat that as ITS OWN successful
    # verify_contact call: it must reject with ChallengeInvalid and never fire contact_verified
    # for a row it never actually processed.
    caller = UserFactory(email="caller@example.com")
    with captured(email_otp_requested) as received:
        request_result = OtpService.request(
            "brand-new@example.com", channel="email", purpose="verify_contact"
        )
    code = received[0]["code"]

    with captured(contact_verified) as verified, pytest.raises(ChallengeInvalid):
        VerificationService.confirm(caller, request_result.challenge_id, code=code)

    assert verified == []

    from django.contrib.auth import get_user_model

    assert get_user_model().objects.filter(email="brand-new@example.com").exists()
    assert VerifiedContact.objects.filter(field="email", value="brand-new@example.com").exists()
