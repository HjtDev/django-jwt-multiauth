"""Proves ``jwt_multiauth.models`` matches ``docs/CONTRACT.md`` §1 exactly: every user reference
is indirect, every ``Meta.indexes``/``Meta.constraints`` entry is present, every secret-holding
field is a plain ``CharField``/``TextField`` (never a custom descriptor), and no module under
``src/jwt_multiauth`` imports a concrete user model.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.db import models

from jwt_multiauth import models as jwt_models

SEVEN_MODELS = [
    jwt_models.OtpChallenge,
    jwt_models.AuthSession,
    jwt_models.TwoFactorDevice,
    jwt_models.RecoveryCode,
    jwt_models.VerifiedContact,
    jwt_models.LoginAttempt,
    jwt_models.TrustedDevice,
]


@pytest.mark.parametrize("model", SEVEN_MODELS)
def test_user_field_targets_the_resolved_user_model(model: type[models.Model]) -> None:
    field = model._meta.get_field("user")
    assert field.related_model is get_user_model()


def test_otp_challenge_indexes() -> None:
    index_fields = {tuple(index.fields) for index in jwt_models.OtpChallenge._meta.indexes}
    assert ("user", "purpose", "consumed_at") in index_fields
    assert ("expires_at",) in index_fields


def test_auth_session_indexes() -> None:
    index_fields = {tuple(index.fields) for index in jwt_models.AuthSession._meta.indexes}
    assert ("user", "revoked_at") in index_fields
    assert ("expires_at",) in index_fields


def test_two_factor_device_unique_constraint() -> None:
    names = {c.name for c in jwt_models.TwoFactorDevice._meta.constraints}
    assert "unique_user_method_2fa_device" in names


def test_recovery_code_index() -> None:
    index_fields = {tuple(index.fields) for index in jwt_models.RecoveryCode._meta.indexes}
    assert ("user", "used_at") in index_fields


def test_verified_contact_unique_constraint() -> None:
    names = {c.name for c in jwt_models.VerifiedContact._meta.constraints}
    assert "unique_user_field_value_verified" in names


def test_login_attempt_indexes() -> None:
    index_fields = {tuple(index.fields) for index in jwt_models.LoginAttempt._meta.indexes}
    assert ("identifier", "created_at") in index_fields
    assert ("ip_address", "created_at") in index_fields
    assert ("user", "created_at") in index_fields


def test_trusted_device_index() -> None:
    index_fields = {tuple(index.fields) for index in jwt_models.TrustedDevice._meta.indexes}
    assert ("user", "revoked_at") in index_fields


@pytest.mark.parametrize(
    ("model", "field_name"),
    [
        (jwt_models.OtpChallenge, "code_hash"),
        (jwt_models.OtpChallenge, "link_token_hash"),
        (jwt_models.AuthSession, "current_jti"),
        (jwt_models.TwoFactorDevice, "secret_encrypted"),
        (jwt_models.RecoveryCode, "code_hash"),
        (jwt_models.TrustedDevice, "token_hash"),
    ],
)
def test_secret_fields_are_plain_char_or_text_fields(
    model: type[models.Model], field_name: str
) -> None:
    field = model._meta.get_field(field_name)
    # Exactly django.db.models.CharField/TextField, never a subclass masquerading as one — a
    # custom descriptor hiding hashing/encryption is exactly what CLAUDE.md rule 4 forbids here.
    assert type(field) in (models.CharField, models.TextField)


def test_otp_challenge_user_is_nullable() -> None:
    field = jwt_models.OtpChallenge._meta.get_field("user")
    assert field.null is True


def test_no_concrete_user_model_import_anywhere_in_the_package() -> None:
    package_dir = Path(inspect.getfile(jwt_models)).parent
    offenders = []
    for path in package_dir.rglob("*.py"):
        if "migrations" in path.parts:
            continue
        text = path.read_text()
        concrete_import = "from django.contrib.auth.models import User"
        module_import = "import django.contrib.auth.models"
        if concrete_import in text or module_import in text:
            offenders.append(str(path))
    assert offenders == []
