"""App-wide fixtures (``APP-DESIGN.md`` §7.2). ``appkit``'s own
``appkit_user``/``appkit_admin_user``/``appkit_auth_client``/``appkit_admin_client``/
``appkit_assert_error_envelope`` fixtures are already available via ``-p appkit.testing`` in
``addopts`` (``backend/pyproject.toml``) — these fixtures exist for tests that want this app's own
naming instead, built over ``jwt_multiauth.factories`` rather than duplicating appkit's own
user-creation logic.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from django.contrib.auth import get_user_model
from django.dispatch import Signal
from rest_framework.test import APIClient

from jwt_multiauth.factories import UserFactory


@contextmanager
def captured(signal: Signal) -> Iterator[list[dict[str, Any]]]:
    """Collects every payload a signal fires with while the context is open, sender included.

    Originated in ``test_token_service.py`` (Phase 3); promoted here in Phase 4 once a second and
    third consumer (``test_otp_service.py``) needed the same helper — one definition, matching
    Phase 6's guide text ("reuse Phase 4's test helper").
    """
    received: list[dict[str, Any]] = []

    def _receiver(**kwargs: Any) -> None:
        kwargs.pop("signal", None)
        received.append(kwargs)

    signal.connect(_receiver, weak=False)
    try:
        yield received
    finally:
        signal.disconnect(_receiver)


@pytest.fixture
def api_client() -> APIClient:
    return APIClient()


@pytest.fixture
def user(db: None) -> object:
    return UserFactory(username="alice")


@pytest.fixture
def admin_user(db: None) -> object:
    return get_user_model().objects.create_superuser(username="admin", password="pw")


@pytest.fixture
def auth_client(api_client: APIClient, user: object) -> APIClient:
    api_client.force_authenticate(user=user)
    return api_client


@pytest.fixture
def admin_client(api_client: APIClient, admin_user: object) -> APIClient:
    api_client.force_authenticate(user=admin_user)
    return api_client
