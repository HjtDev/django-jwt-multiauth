"""App-wide fixtures (``APP-DESIGN.md`` §7.2). ``appkit``'s own
``appkit_user``/``appkit_admin_user``/``appkit_auth_client``/``appkit_admin_client``/
``appkit_assert_error_envelope`` fixtures are already available via ``-p appkit.testing`` in
``addopts`` (``backend/pyproject.toml``) — these fixtures exist for tests that want this app's own
naming instead, built over ``jwt_multiauth.factories`` rather than duplicating appkit's own
user-creation logic.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from jwt_multiauth.factories import UserFactory


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
