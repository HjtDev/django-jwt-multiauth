"""Proves the migration graph is swappable-correct and complete — a passing ``pytest --create-db``
run proves the migration *applies*; this module proves it is *shaped* correctly (``APP-DESIGN.md``
§7.4's migrations row: ``makemigrations --check --dry-run`` catches a missing migration before
``pytest`` would ever notice via a stale schema).

``0001_initial`` is loaded via ``importlib`` because ``0001_initial`` is not a valid Python
identifier for a plain ``import`` statement (it starts with a digit) — Django's own migration
loader does the same thing internally.
"""

from __future__ import annotations

import importlib

import pytest
from django.conf import settings
from django.core.management import call_command
from django.db import migrations

_initial = importlib.import_module("jwt_multiauth.migrations.0001_initial")


def test_swappable_dependency_on_auth_user_model() -> None:
    dependency = migrations.swappable_dependency(settings.AUTH_USER_MODEL)
    assert dependency in _initial.Migration.dependencies


def test_every_user_fk_targets_settings_auth_user_model() -> None:
    fk_targets = []
    for operation in _initial.Migration.operations:
        fields = getattr(operation, "fields", None) or []
        for field_name, field in fields:
            if field_name == "user":
                fk_targets.append(field.remote_field.model)

    assert fk_targets, "expected at least one 'user' FK across the seven models"
    assert all(target == settings.AUTH_USER_MODEL for target in fk_targets)


@pytest.mark.django_db
def test_no_missing_migrations() -> None:
    """``makemigrations --check --dry-run`` exits non-zero (raising ``SystemExit``) the moment a
    model change has no corresponding migration — this is the CI-equivalent gate
    ``APP-DESIGN.md`` §7.4 names, run here as a plain test instead of a separate CI step.
    ``django_db`` is required: ``check_consistent_history`` queries the migration-history table.
    """
    call_command("makemigrations", "jwt_multiauth", check=True, dry_run=True, verbosity=0)
