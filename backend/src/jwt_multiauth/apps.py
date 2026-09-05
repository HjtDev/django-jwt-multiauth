"""This app's ``AppConfig`` — registers ``jwt_multiauth.checks``' system checks.

Registration happens from :meth:`JwtMultiauthConfig.ready`, never at module import time — a
fresh, unconfigured host must be able to import ``jwt_multiauth.apps`` (which Django does merely
by listing ``"jwt_multiauth"`` in ``INSTALLED_APPS``) without a settings lookup ever running.
Every import inside ``ready()`` is function-local, never at this module's top level, so importing
``jwt_multiauth.apps`` alone can never trigger a settings access or an ``ImportError`` from a
module that isn't ready yet.

Nothing else needs wiring in ``ready()`` at this phase — there is no swappable-model machinery in
this app (unlike ``django-dynamic-user``'s auto-provisioning receivers), so there is nothing to
connect beyond the checks themselves.
"""

from __future__ import annotations

from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class JwtMultiauthConfig(AppConfig):
    name = "jwt_multiauth"
    verbose_name = _("JWT Multi-Auth")
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        """Register this app's system checks — see ``jwt_multiauth.checks`` for what each one
        validates and why every one of them is a no-op against a fresh, zero-config Django
        project (``ALLOWED_AUTH_METHODS`` defaults to ``["password"]``, which imposes no field
        or key requirement at all).
        """
        from django.core.checks import register

        from jwt_multiauth import checks

        register(checks.check_user_field_requirements)
        register(checks.check_totp_requirements)
        register(checks.check_allowed_methods_closed_set)
        register(checks.check_unknown_settings_keys)
