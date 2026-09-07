"""Self-service and admin DRF permission classes.

Phase 8 implements the admin gate: the single callable/class every ``admin_views.py`` view
imports, resolved once from ``JWT_MULTIAUTH["ADMIN_REQUIRES_SUPERUSER"]`` (``False`` behaves like
``appkit.permissions.IsAppAdmin`` — ``is_staff``; ``True`` tightens to ``is_superuser``) — never a
conditional repeated per view, per ``docs/CONTRACT.md`` §5. Plus a **separate**, always-
``is_superuser`` gate used only by force-disable-2FA, never affected by that setting
(``docs/CONTRACT.md`` §0's "Admin gating" row).

``is_superuser()`` is exported as a plain function, not only wrapped in a permission class, so
``admin.py``'s ``TwoFactorDeviceAdmin.force_disable_two_factor`` action (Django admin, not DRF) can
call the identical check the REST route's ``IsSuperUser`` permission class uses — one predicate,
never two copies that could silently drift apart.

Self-service permission checks (own-session/own-trusted-device ownership) are enforced at the
queryset level in ``views_session.py``, not via a permission class here — ``docs/CONTRACT.md``
§5's own review note picks ``404`` over ``403`` for that case, which only a queryset filter (never
``has_object_permission``, which DRF only consults from ``get_object()`` after a queryset lookup
already succeeded) can produce.
"""

from __future__ import annotations

from typing import Any

from appkit.permissions import IsAppAdmin
from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView

from jwt_multiauth import conf

__all__ = ["IsAdmin", "IsSuperUser", "is_superuser"]


def is_superuser(user: Any) -> bool:
    """The one predicate both ``IsSuperUser`` (REST) and ``admin.py``'s force-disable-2FA action
    (Django admin) call — never duplicated, since a mismatch between the two would mean this
    app's REST and Django-admin surfaces disagree about who may force-disable another user's 2FA.
    Never raises: an anonymous/unauthenticated ``user`` simply isn't a superuser.
    """
    return bool(user and getattr(user, "is_authenticated", False) and user.is_superuser)


class IsAdmin(BasePermission):
    """The single configurable admin gate every ``admin_views.py`` view (except force-disable-2FA)
    declares as its ``permission_classes``. Resolves ``JWT_MULTIAUTH["ADMIN_REQUIRES_SUPERUSER"]``
    freshly on every call, inside :meth:`has_permission` — never once at class-definition/import
    time, or a test's ``override_settings`` would have no effect on an already-evaluated class
    attribute.
    """

    def has_permission(self, request: Request, view: APIView) -> bool:
        if conf.get_setting("ADMIN_REQUIRES_SUPERUSER"):
            return is_superuser(request.user)
        return IsAppAdmin().has_permission(request, view)


class IsSuperUser(BasePermission):
    """Used ONLY by ``POST /admin/users/{id}/2fa/force-disable/`` — always ``is_superuser``,
    never reads ``ADMIN_REQUIRES_SUPERUSER`` (``docs/CONTRACT.md`` §0: this is the one admin gate
    that setting never loosens, in either direction).
    """

    def has_permission(self, request: Request, view: APIView) -> bool:
        return is_superuser(request.user)
