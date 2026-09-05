"""Exists so this app's schema can be generated, and its admin/API tests can run, standalone
without a host (``APP-DESIGN.md`` §7.1). Mounts the same URLconfs a real host's own
``backend/config/urls.py`` would mount per this app's README — nothing host-specific, since this
file ships in the test tree, not a real host's tree.
"""

from __future__ import annotations

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/auth/", include("jwt_multiauth.urls")),
    path("api/v1/admin/auth/", include("jwt_multiauth.urls_admin")),
]
