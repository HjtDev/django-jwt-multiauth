"""Proves ``services.OtpService``/``services.UserProvisioningService``: a real request/verify/
resend round trip; the decoy path writes zero DB rows and fires zero signals while returning a
response shape identical to the real path's; the attempts budget locks out a challenge even when
the last attempt would have been correct; ``SINGLE_ACTIVE_CHALLENGE`` genuinely invalidates a
prior unconsumed challenge server-side; resend cooldown/budget enforcement; purpose overrides;
``EMIT_LINK_TOKEN``; and — the ``docs/CONTRACT.md`` §11 item 19 auto-provisioning path — an
unresolved identifier on an ``AUTO_PROVISION_METHODS`` channel persists a real row, and a
successful verify creates exactly one user, attaches it, records a ``VerifiedContact``, and fires
both ``otp_verified`` and ``user_provisioned``.

Also proves the security rails this phase exists for: every secret is hashed (never plaintext) at
rest by actual row inspection, the pepper genuinely keys the hash, no code/hash/pepper ever
reaches a log record or an exception message or a dataclass ``repr``, ``PROVISION_CALLBACK``
fails loudly rather than silently falling back, and a provisioned account is unreachable via
password login.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings
from django.utils import timezone
from freezegun import freeze_time

from jwt_multiauth import keys, otp
from jwt_multiauth.factories import OtpChallengeFactory, UserFactory
from jwt_multiauth.models import OtpChallenge, VerifiedContact
from jwt_multiauth.services import (
    ChallengeInvalid,
    OtpRequestResult,
    OtpService,
    OtpVerifyResult,
    UserProvisioningService,
)
from jwt_multiauth.signals import (
    email_otp_requested,
    otp_verified,
    phone_otp_requested,
    user_provisioned,
)
from tests.backend.conftest import captured

pytestmark = pytest.mark.django_db


def _custom_provision_callback(identifier: str, *, field: str) -> tuple[object, bool]:
    """A working ``PROVISION_CALLBACK`` target — proves ``get_or_create`` passes a working
    callback's return value straight through rather than reinterpreting it.
    """
    from django.contrib.auth import get_user_model

    return get_user_model().objects.get_or_create(
        username=f"callback-{identifier}", defaults={field: identifier}
    )


def _otp_settings(**overrides: object) -> dict[str, object]:
    """A JWT_MULTIAUTH override enabling email_otp against the default leg's stock User model,
    whose "email" field is used as EMAIL_FIELD for these tests. ``overrides`` are merged into
    OTP["DEFAULTS"].
    """
    return {
        "ALLOWED_AUTH_METHODS": ["password", "email_otp"],
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
        "OTP": {"DEFAULTS": overrides} if overrides else {},
    }


# --------------------------------------------------------------------- request


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_request_for_a_resolving_identifier_persists_a_real_row_and_fires_the_signal() -> None:
    user = UserFactory(email="alice@example.com")

    with captured(email_otp_requested) as received:
        result = OtpService.request("alice@example.com", channel="email", purpose="login")

    challenge = OtpChallenge.objects.get(pk=result.challenge_id)
    assert challenge.user_id == user.pk
    assert challenge.destination == "alice@example.com"
    assert len(received) == 1
    payload = received[0]
    assert payload["sender"] is OtpChallenge
    assert payload["user_id"] == user.pk
    assert payload["destination"] == "alice@example.com"
    assert payload["purpose"] == "login"
    assert payload["challenge_id"] == result.challenge_id
    assert payload["link_token"] is None
    assert isinstance(payload["code"], str)


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {}})
def test_request_with_an_unconfigured_channel_field_takes_the_decoy_path() -> None:
    # PHONE_FIELD is unset entirely (the default leg has no phone field at all) — an unconfigured
    # channel field behaves exactly like an unresolved identifier, never a crash.
    before_count = OtpChallenge.objects.count()
    with captured(phone_otp_requested) as received:
        result = OtpService.request("+15550001234", channel="phone", purpose="login")

    assert OtpChallenge.objects.count() == before_count
    assert received == []
    assert isinstance(result, OtpRequestResult)


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_decoy_path_writes_zero_rows_and_fires_zero_signals() -> None:
    before_count = OtpChallenge.objects.count()

    with (
        patch("jwt_multiauth.models.OtpChallenge.objects.create") as mock_create,
        captured(email_otp_requested) as received,
    ):
        result = OtpService.request("nobody@example.com", channel="email", purpose="login")

    mock_create.assert_not_called()
    assert OtpChallenge.objects.count() == before_count
    assert received == []
    assert isinstance(result, OtpRequestResult)


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_decoy_response_is_shape_indistinguishable_from_the_real_response() -> None:
    UserFactory(email="alice@example.com")

    real = OtpService.request("alice@example.com", channel="email", purpose="login")
    decoy = OtpService.request("nobody@example.com", channel="email", purpose="login")

    assert {f.name for f in real.__dataclass_fields__.values()} == {
        f.name for f in decoy.__dataclass_fields__.values()
    }
    assert isinstance(real.challenge_id, str)
    assert isinstance(decoy.challenge_id, str)
    assert isinstance(real.expires_at, type(decoy.expires_at))
    assert isinstance(real.resend_available_at, type(decoy.resend_available_at))


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_single_active_challenge_invalidates_the_prior_unconsumed_one() -> None:
    user = UserFactory(email="alice@example.com")
    first = OtpService.request("alice@example.com", channel="email", purpose="login")

    second = OtpService.request("alice@example.com", channel="email", purpose="login")

    first_row = OtpChallenge.objects.get(pk=first.challenge_id)
    assert first_row.consumed_at is not None
    with pytest.raises(ChallengeInvalid):
        OtpService.verify(first.challenge_id, code="000000")

    second_row = OtpChallenge.objects.get(pk=second.challenge_id)
    assert second_row.consumed_at is None
    assert second_row.user_id == user.pk


@override_settings(JWT_MULTIAUTH=_otp_settings(TTL_SECONDS=900))
def test_purpose_override_wins_over_channel_default() -> None:
    UserFactory(email="alice@example.com")
    with override_settings(
        JWT_MULTIAUTH={
            **_otp_settings(),
            "OTP": {"PURPOSES": {"password_reset": {"TTL_SECONDS": 60}}},
        }
    ):
        login_result = OtpService.request("alice@example.com", channel="email", purpose="login")
        reset_result = OtpService.request(
            "alice@example.com", channel="email", purpose="password_reset"
        )
    login_ttl = (login_result.expires_at - timezone.now()).total_seconds()
    reset_ttl = (reset_result.expires_at - timezone.now()).total_seconds()
    assert reset_ttl < login_ttl


@override_settings(
    JWT_MULTIAUTH={**_otp_settings(), "OTP": {"DEFAULTS": {"EMIT_LINK_TOKEN": True}}}
)
def test_emit_link_token_on_includes_a_verifiable_link_token() -> None:
    UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        result = OtpService.request("alice@example.com", channel="email", purpose="login")

    link_token = received[0]["link_token"]
    assert link_token is not None
    OtpService.verify(result.challenge_id, link_token=link_token)


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_emit_link_token_off_payload_carries_the_kwarg_as_none() -> None:
    UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        OtpService.request("alice@example.com", channel="email", purpose="login")

    assert "link_token" in received[0]
    assert received[0]["link_token"] is None


# --------------------------------------------------------------------- verify


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_real_request_verify_round_trip_on_email() -> None:
    user = UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        request_result = OtpService.request("alice@example.com", channel="email", purpose="login")
    code = received[0]["code"]

    with captured(otp_verified) as verified:
        result = OtpService.verify(request_result.challenge_id, code=code)

    assert result == OtpVerifyResult(user=user, purpose="login", created=False)
    assert verified == [
        {
            "sender": OtpChallenge,
            "user_id": user.pk,
            "challenge_id": request_result.challenge_id,
            "purpose": "login",
        }
    ]


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_verify_unknown_challenge_id_raises_challenge_invalid() -> None:
    import uuid

    with pytest.raises(ChallengeInvalid):
        OtpService.verify(str(uuid.uuid4()), code="000000")


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_verify_expired_challenge_raises_challenge_invalid() -> None:
    user = UserFactory(email="alice@example.com")
    pepper = keys.get_otp_pepper()
    challenge = OtpChallengeFactory(
        user=user,
        channel="email",
        purpose="login",
        destination="alice@example.com",
        code_hash=otp.hash_secret("123456", pepper=pepper),
        expires_at=timezone.now() - timedelta(seconds=1),
    )
    with pytest.raises(ChallengeInvalid):
        OtpService.verify(str(challenge.challenge_id), code="123456")


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_verify_already_consumed_challenge_raises_challenge_invalid() -> None:
    user = UserFactory(email="alice@example.com")
    pepper = keys.get_otp_pepper()
    challenge = OtpChallengeFactory(
        user=user,
        channel="email",
        purpose="login",
        destination="alice@example.com",
        code_hash=otp.hash_secret("123456", pepper=pepper),
        consumed_at=timezone.now(),
    )
    with pytest.raises(ChallengeInvalid):
        OtpService.verify(str(challenge.challenge_id), code="123456")


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_attempts_lockout_rejects_even_the_correct_code_after_max_attempts() -> None:
    user = UserFactory(email="alice@example.com")
    pepper = keys.get_otp_pepper()
    challenge = OtpChallengeFactory(
        user=user,
        channel="email",
        purpose="login",
        destination="alice@example.com",
        code_hash=otp.hash_secret("123456", pepper=pepper),
        max_attempts=3,
    )

    for _ in range(3):
        with pytest.raises(ChallengeInvalid):
            OtpService.verify(str(challenge.challenge_id), code="000000")

    # Attempt #max_attempts+1 — even the CORRECT code must now be rejected.
    with pytest.raises(ChallengeInvalid):
        OtpService.verify(str(challenge.challenge_id), code="123456")

    challenge.refresh_from_db()
    assert challenge.attempts == 3
    assert challenge.consumed_at is None


# --------------------------------------------------------------------- resend


@override_settings(JWT_MULTIAUTH=_otp_settings(RESEND_COOLDOWN_SECONDS=60, MAX_RESENDS=2))
def test_resend_before_cooldown_elapses_raises_challenge_invalid() -> None:
    UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        request_result = OtpService.request("alice@example.com", channel="email", purpose="login")
    original_code = received[0]["code"]

    with pytest.raises(ChallengeInvalid):
        OtpService.resend(request_result.challenge_id)

    challenge = OtpChallenge.objects.get(pk=request_result.challenge_id)
    assert otp.verify_secret(original_code, challenge.code_hash, pepper=keys.get_otp_pepper())


@override_settings(JWT_MULTIAUTH=_otp_settings(RESEND_COOLDOWN_SECONDS=60, MAX_RESENDS=2))
def test_resend_after_cooldown_issues_a_genuinely_different_code() -> None:
    UserFactory(email="alice@example.com")
    with freeze_time("2026-01-01 00:00:00"):
        with captured(email_otp_requested) as received:
            request_result = OtpService.request(
                "alice@example.com", channel="email", purpose="login"
            )
        original_code = received[0]["code"]

    with freeze_time("2026-01-01 00:01:01"):
        with captured(email_otp_requested) as resend_received:
            resend_result = OtpService.resend(request_result.challenge_id)
        new_code = resend_received[0]["code"]

    assert resend_result.challenge_id == request_result.challenge_id
    assert new_code != original_code
    challenge = OtpChallenge.objects.get(pk=request_result.challenge_id)
    assert otp.verify_secret(new_code, challenge.code_hash, pepper=keys.get_otp_pepper())
    assert not otp.verify_secret(original_code, challenge.code_hash, pepper=keys.get_otp_pepper())


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_resend_unknown_challenge_id_raises_challenge_invalid() -> None:
    import uuid

    with pytest.raises(ChallengeInvalid):
        OtpService.resend(str(uuid.uuid4()))


@override_settings(JWT_MULTIAUTH=_otp_settings(RESEND_COOLDOWN_SECONDS=0, MAX_RESENDS=1))
def test_resend_exhausting_max_resends_raises_challenge_invalid() -> None:
    UserFactory(email="alice@example.com")
    request_result = OtpService.request("alice@example.com", channel="email", purpose="login")

    OtpService.resend(request_result.challenge_id)  # consumes the one allowed resend

    with pytest.raises(ChallengeInvalid):
        OtpService.resend(request_result.challenge_id)


# --------------------------------------------------------------------- auto-provisioning


@override_settings(
    JWT_MULTIAUTH={
        **_otp_settings(),
        "USER_FIELDS": {"EMAIL_FIELD": "email", "AUTO_PROVISION_METHODS": ["email_otp"]},
    }
)
def test_request_on_an_unresolving_auto_provision_identifier_persists_a_real_row() -> None:
    with (
        patch(
            "jwt_multiauth.models.OtpChallenge.objects.create",
            side_effect=OtpChallenge.objects.create,
        ) as mock_create,
        captured(email_otp_requested) as received,
    ):
        result = OtpService.request("new@example.com", channel="email", purpose="login")

    mock_create.assert_called_once()
    challenge = OtpChallenge.objects.get(pk=result.challenge_id)
    assert challenge.user_id is None
    assert challenge.destination == "new@example.com"
    assert len(received) == 1
    assert received[0]["user_id"] is None
    assert received[0]["destination"] == "new@example.com"


@override_settings(
    JWT_MULTIAUTH={
        **_otp_settings(),
        "USER_FIELDS": {"EMAIL_FIELD": "email", "AUTO_PROVISION_METHODS": ["email_otp"]},
    }
)
def test_auto_provision_response_shape_matches_the_resolves_path_not_the_decoy_path() -> None:
    # On a channel with AUTO_PROVISION_METHODS set, an unresolving identifier is now on the SAME
    # real-row path as a resolving one — it must be indistinguishable from THAT, and it now
    # genuinely differs from a decoy on some other, non-auto-provisioning channel/purpose
    # combination the fixture below doesn't exercise (the decoy branch requires the miss to also
    # fail the AUTO_PROVISION_METHODS membership test).
    UserFactory(email="alice@example.com")
    resolves = OtpService.request("alice@example.com", channel="email", purpose="login")
    provisioned = OtpService.request("new@example.com", channel="email", purpose="login")

    resolves_row = OtpChallenge.objects.get(pk=resolves.challenge_id)
    provisioned_row = OtpChallenge.objects.get(pk=provisioned.challenge_id)
    assert resolves_row.user_id is not None
    assert provisioned_row.user_id is None
    assert {f.name for f in resolves.__dataclass_fields__.values()} == {
        f.name for f in provisioned.__dataclass_fields__.values()
    }


@override_settings(
    JWT_MULTIAUTH={
        **_otp_settings(),
        "USER_FIELDS": {"EMAIL_FIELD": "email", "AUTO_PROVISION_METHODS": ["email_otp"]},
    }
)
def test_verify_on_an_auto_provision_challenge_creates_exactly_one_user() -> None:
    with captured(email_otp_requested) as received:
        request_result = OtpService.request("new@example.com", channel="email", purpose="login")
    code = received[0]["code"]

    user_model = OtpChallenge.objects.get(pk=request_result.challenge_id).user
    assert user_model is None

    with captured(otp_verified) as verified, captured(user_provisioned) as provisioned:
        result = OtpService.verify(request_result.challenge_id, code=code)

    assert result.created is True
    assert result.purpose == "login"
    from django.contrib.auth import get_user_model

    assert get_user_model().objects.filter(email="new@example.com").count() == 1
    challenge = OtpChallenge.objects.get(pk=request_result.challenge_id)
    assert challenge.user_id == result.user.pk
    assert VerifiedContact.objects.filter(
        user=result.user, field="email", value="new@example.com"
    ).exists()
    assert len(verified) == 1
    assert len(provisioned) == 1
    assert provisioned[0]["sender"] == get_user_model()
    assert provisioned[0]["user_id"] == result.user.pk
    assert provisioned[0]["field"] == "email"
    assert provisioned[0]["value"] == "new@example.com"


@override_settings(
    JWT_MULTIAUTH={
        **_otp_settings(),
        "USER_FIELDS": {"EMAIL_FIELD": "email", "AUTO_PROVISION_METHODS": ["email_otp"]},
    }
)
def test_verify_on_an_existing_user_never_fires_user_provisioned() -> None:
    user = UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        request_result = OtpService.request("alice@example.com", channel="email", purpose="login")
    code = received[0]["code"]

    with captured(user_provisioned) as provisioned:
        result = OtpService.verify(request_result.challenge_id, code=code)

    assert result.created is False
    assert result.user == user
    assert provisioned == []


# --------------------------------------------------------------------- UserProvisioningService


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_get_or_create_built_in_default_sets_unusable_password_and_no_extra_field() -> None:
    user, created = UserProvisioningService.get_or_create("new@example.com", field="email")

    assert created is True
    assert user.has_usable_password() is False
    assert user.is_staff is False
    assert user.is_superuser is False
    assert user.email == "new@example.com"
    assert user.username == "new@example.com"  # USERNAME_FIELD, different+empty on stock User


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_get_or_create_returns_existing_user_without_firing_the_signal() -> None:
    existing = UserFactory(email="alice@example.com")
    with captured(user_provisioned) as received:
        user, created = UserProvisioningService.get_or_create("alice@example.com", field="email")

    assert created is False
    assert user == existing
    assert received == []


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {
            "EMAIL_FIELD": "email",
            "PROVISION_CALLBACK": "tests.backend.test_otp_service._custom_provision_callback",
        }
    }
)
def test_get_or_create_working_callback_return_value_passes_through() -> None:
    user, created = UserProvisioningService.get_or_create("new@example.com", field="email")

    assert created is True
    assert user.email == "new@example.com"
    assert user.username == "callback-new@example.com"


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {
            "EMAIL_FIELD": "email",
            "PROVISION_CALLBACK": "tests.backend.does_not_exist.callback",
        }
    }
)
def test_get_or_create_unimportable_callback_raises_loudly_not_silently() -> None:
    with pytest.raises(ImproperlyConfigured, match="PROVISION_CALLBACK"):
        UserProvisioningService.get_or_create("new@example.com", field="email")


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {
            "EMAIL_FIELD": "email",
            # A real, importable, but non-callable target.
            "PROVISION_CALLBACK": "jwt_multiauth.otp._NUMERIC",
        }
    }
)
def test_get_or_create_non_callable_callback_raises_loudly_not_silently() -> None:
    with pytest.raises(ImproperlyConfigured, match="PROVISION_CALLBACK"):
        UserProvisioningService.get_or_create("new@example.com", field="email")


# --------------------------------------------------------------------- security: hashed at rest


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_code_hash_is_hashed_at_rest_proven_by_row_inspection() -> None:
    UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        result = OtpService.request("alice@example.com", channel="email", purpose="login")
    code = received[0]["code"]

    row = OtpChallenge.objects.get(pk=result.challenge_id)
    assert len(row.code_hash) == 64
    assert row.code_hash != code
    assert row.code_hash == otp.hash_secret(code, pepper=keys.get_otp_pepper())


@override_settings(
    JWT_MULTIAUTH={**_otp_settings(), "OTP": {"DEFAULTS": {"EMIT_LINK_TOKEN": True}}}
)
def test_link_token_hash_is_hashed_at_rest_proven_by_row_inspection() -> None:
    UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        result = OtpService.request("alice@example.com", channel="email", purpose="login")
    link_token = received[0]["link_token"]

    row = OtpChallenge.objects.get(pk=result.challenge_id)
    assert row.link_token_hash is not None
    assert len(row.link_token_hash) == 64
    assert row.link_token_hash != link_token
    assert row.link_token_hash == otp.hash_secret(link_token, pepper=keys.get_otp_pepper())


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_pepper_actually_keys_the_hash() -> None:
    UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        result = OtpService.request("alice@example.com", channel="email", purpose="login")
    code = received[0]["code"]
    row = OtpChallenge.objects.get(pk=result.challenge_id)

    assert not otp.verify_secret(code, row.code_hash, pepper="a-completely-different-pepper")


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_no_plaintext_code_leaks_into_any_text_column() -> None:
    UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        result = OtpService.request("alice@example.com", channel="email", purpose="login")
    code = received[0]["code"]
    OtpService.verify(result.challenge_id, code=code)

    row = OtpChallenge.objects.get(pk=result.challenge_id)
    for field in ("code_hash", "link_token_hash", "destination"):
        value = getattr(row, field)
        if field == "destination":
            continue  # destination is legitimately the identifier, not the secret
        assert value is None or code not in value


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_result_objects_carry_no_secret_in_repr() -> None:
    UserFactory(email="alice@example.com")
    with captured(email_otp_requested) as received:
        result = OtpService.request("alice@example.com", channel="email", purpose="login")
    code = received[0]["code"]
    pepper = keys.get_otp_pepper()
    digest = otp.hash_secret(code, pepper=pepper)

    assert code not in repr(result)
    assert digest not in repr(result)

    verify_result = OtpService.verify(result.challenge_id, code=code)
    assert code not in repr(verify_result)
    assert digest not in repr(verify_result)


@override_settings(JWT_MULTIAUTH=_otp_settings())
def test_exception_message_carries_no_secret_on_wrong_code() -> None:
    user = UserFactory(email="alice@example.com")
    pepper = keys.get_otp_pepper()
    challenge = OtpChallengeFactory(
        user=user,
        channel="email",
        purpose="login",
        destination="alice@example.com",
        code_hash=otp.hash_secret("123456", pepper=pepper),
    )
    with pytest.raises(ChallengeInvalid) as excinfo:
        OtpService.verify(str(challenge.challenge_id), code="000000")

    assert "123456" not in str(excinfo.value)
    assert challenge.code_hash not in str(excinfo.value)


@override_settings(JWT_MULTIAUTH=_otp_settings(RESEND_COOLDOWN_SECONDS=0))
def test_no_secret_reaches_any_log_record(caplog: pytest.LogCaptureFixture) -> None:
    UserFactory(email="alice@example.com")
    with caplog.at_level(logging.DEBUG):
        with captured(email_otp_requested) as received:
            result = OtpService.request("alice@example.com", channel="email", purpose="login")
        code = received[0]["code"]
        pepper = keys.get_otp_pepper()

        try:
            OtpService.verify(result.challenge_id, code="000000")
        except ChallengeInvalid:
            pass

        with captured(email_otp_requested) as resent:
            OtpService.resend(result.challenge_id)
        resent_code = resent[0]["code"]
        OtpService.verify(result.challenge_id, code=resent_code)

    for record in caplog.records:
        message = record.getMessage()
        assert code not in message
        assert resent_code not in message
        assert pepper not in message


@override_settings(
    JWT_MULTIAUTH={
        **_otp_settings(),
        "USER_FIELDS": {"EMAIL_FIELD": "email", "AUTO_PROVISION_METHODS": ["email_otp"]},
    }
)
def test_provisioned_account_is_unreachable_via_password_login() -> None:
    with captured(email_otp_requested) as received:
        request_result = OtpService.request("new@example.com", channel="email", purpose="login")
    code = received[0]["code"]

    result = OtpService.verify(request_result.challenge_id, code=code)

    assert result.user.has_usable_password() is False
    assert result.user.check_password("anything") is False
