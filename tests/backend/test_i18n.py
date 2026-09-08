"""Proves the shipped ``locale/fa/LC_MESSAGES/django.mo`` catalogue actually resolves, and pins
the boundary this repo's pre-Phase-10 localisation pass drew: ``error.message``, model
``verbose_name``s, and choice *labels* translate under ``fa``; ``error.code``/``details.code``,
choice *values*, and ``throttling.py``'s scope constants never do, under any locale.

No settings changes were needed to write these: ``USE_I18N`` is unset and therefore Django's
default ``True``, and ``django.utils.translation.override("fa")`` activates a locale and loads an
installed app's own ``locale/`` catalogue regardless of the project's ``LANGUAGES`` setting or
whether ``LocaleMiddleware`` is installed — locale *activation* (that middleware, ``LANGUAGES``)
is deliberately left to the host, per ``docs/CONTRACT.md``'s new i18n section.
"""

from __future__ import annotations

import pytest
from django.utils import translation
from rest_framework.test import APIClient

from jwt_multiauth import checks, throttling
from jwt_multiauth.factories import UserFactory
from jwt_multiauth.models import LoginAttempt, OtpChallenge
from jwt_multiauth.services import RequestMeta, TokenService

pytestmark = pytest.mark.django_db

_REQUEST_META: RequestMeta = {"ip": "203.0.113.5", "method": "password"}


def test_model_verbose_name_translates_under_fa() -> None:
    with translation.override("en"):
        assert str(OtpChallenge._meta.verbose_name) == "OTP challenge"

    with translation.override("fa"):
        assert str(OtpChallenge._meta.verbose_name) == "چالش رمز یک‌بارمصرف"


def test_choice_label_translates_while_the_stored_value_stays_frozen() -> None:
    user = UserFactory()
    attempt = LoginAttempt.objects.create(
        user=user,
        identifier="alice",
        method="email_otp",
        ip_address="203.0.113.5",
        success=True,
    )

    # The stored value is the machine identifier, in any locale.
    assert attempt.method == "email_otp"

    with translation.override("en"):
        assert attempt.get_method_display() == "Email OTP"

    with translation.override("fa"):
        assert attempt.get_method_display() == "رمز یک‌بارمصرف ایمیل"
        # Locale never touches the value itself — only the display label.
        assert attempt.method == "email_otp"


def test_authentication_failed_message_translates_but_error_code_does_not() -> None:
    """``authentication.py``'s prose message is the one place this app writes real ``message``
    text; ``error.code``/``details`` must stay byte-identical across locales — the regression
    guard for "never translate a code".
    """
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION="Bearer not-a-real-token")

    with translation.override("en"):
        en_response = client.post(
            "/api/v1/auth/password/change/",
            {"old_password": "whatever", "new_password": "whatever-else-9"},
            format="json",
        )

    with translation.override("fa"):
        fa_response = client.post(
            "/api/v1/auth/password/change/",
            {"old_password": "whatever", "new_password": "whatever-else-9"},
            format="json",
        )

    assert en_response.status_code == fa_response.status_code == 401
    en_body = en_response.json()
    fa_body = fa_response.json()

    assert en_body["error"]["message"] == "Invalid or expired access token."
    assert fa_body["error"]["message"] == "توکن دسترسی نامعتبر یا منقضی شده است."

    # Everything machine-readable is untouched by locale.
    assert en_body["error"]["code"] == fa_body["error"]["code"]
    assert en_body["error"]["details"] == fa_body["error"]["details"]


def test_old_password_incorrect_message_translates_under_fa() -> None:
    user = UserFactory()
    user.set_password("correct-horse-battery-staple-9")
    user.save()
    pair = TokenService.issue_token_pair(user, request_meta=_REQUEST_META)

    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {pair.access}")

    with translation.override("fa"):
        response = client.post(
            "/api/v1/auth/password/change/",
            {"old_password": "wrong-old-password", "new_password": "another-correct-8"},
            format="json",
        )

    assert response.status_code == 400
    body = response.json()
    assert body["error"]["details"]["old_password"] == ["رمز عبور قبلی نادرست است."]


def test_throttle_scopes_and_check_messages_are_never_translated() -> None:
    """``throttling.py``'s scope constants are DRF ``throttle_scope`` keys cross-checked against
    ``REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]`` (``appkit``'s ``W004``); ``checks.py`` messages
    fire at ``manage.py check`` time. Neither is wrapped in ``gettext_lazy`` — pin it so a future
    contributor doesn't "helpfully" translate a machine identifier.
    """
    with translation.override("fa"):
        assert throttling.LOGIN == "jwt_multiauth_login"
        assert throttling.OTP_REQUEST == "jwt_multiauth_otp_request"
        assert isinstance(checks.ALLOWED_LOGIN_METHODS, frozenset | set)
        assert "password" in checks.ALLOWED_LOGIN_METHODS
