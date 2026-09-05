"""``jwt_multiauth`` — the importable module for the ``django-jwt-multiauth`` distribution.

A standalone JWT authentication layer for a host Django project: username/password login (with
password reset), phone-OTP login, email-OTP login (plus a magic-link variant), optional
policy-driven 2FA (TOTP/OTP/recovery codes), refresh-token rotation with reuse detection,
self-service and admin session management, IP/account lockout, and a persistent login-attempt
audit log. Depends on ``appkit`` (a real, versioned dependency) for caching, pagination,
permissions, the error envelope, encryption, client-IP resolution, and ``HttpClient``/provider.

**This app does not do user data management.** No profile, settings, avatar, or account-deletion
flow — that is ``django-dynamic-user``'s job. The two apps meet only at
``settings.AUTH_USER_MODEL``/``get_user_model()``, the same indirection ``django.contrib.auth``'s
own views use.

The PyPI distribution is ``django-jwt-multiauth``; npm is ``@hjtdev/django-jwt-multiauth``; the
GitHub repo is ``HjtDev/django-jwt-multiauth``. Only the local directory and this importable
module are ``jwt_multiauth``.

This module intentionally re-exports nothing. Each submodule below is its own public surface —
import from ``jwt_multiauth.<module>`` directly (e.g. ``from jwt_multiauth.conf import
get_setting``), never from ``jwt_multiauth`` itself. Every model reference elsewhere in this
package is indirect: ``settings.AUTH_USER_MODEL``/``get_user_model()`` — never a concrete user
model import, including from this package's own ``admin.py`` and ``services.py``. That
indirection is what lets this app work against any host user model that satisfies its enabled
methods' field requirements.
"""
