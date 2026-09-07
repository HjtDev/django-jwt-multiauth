"""Self-service URLconf, basePath ``/api/v1/auth``, frontend basePath key ``jwt_multiauth``.

``docs/CONTRACT.md`` §5's self-service routes land here across Phases 6-8 — login, password
change/reset, OTP request/verify/resend, token refresh/verify, logout(-all), 2FA verify/status/
enroll/confirm/disable/recovery-regenerate, session and trusted-device list/revoke, contact
verification. A host mounts this module under its own API namespace; ``urls_admin.py``
(admin-only) is mounted separately, under a different namespace/permission tier entirely.

No ``app_name`` here, and flat hyphenated url names (``jwt-multiauth-login``, not
``jwt_multiauth:login``) — matching the only in-ecosystem precedent, ``dynamic_user.urls``'s own
``name="dynamic-user-me"`` convention. Not specified anywhere in ``docs/CONTRACT.md``, which names
no url at all — recorded as a deviation in its §11 register.
"""

from __future__ import annotations

from django.urls import URLPattern, path

from jwt_multiauth.views_account import VerifyContactConfirmView, VerifyContactRequestView
from jwt_multiauth.views_discovery import AuthMethodsView
from jwt_multiauth.views_otp import OtpRequestView, OtpResendView, OtpVerifyView
from jwt_multiauth.views_password import (
    LoginView,
    PasswordChangeView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
)
from jwt_multiauth.views_session import (
    SessionListView,
    SessionRevokeView,
    TrustedDeviceListView,
    TrustedDeviceRevokeView,
)
from jwt_multiauth.views_token import LogoutAllView, LogoutView, TokenRefreshView, TokenVerifyView
from jwt_multiauth.views_twofactor import (
    RecoveryCodesRegenerateView,
    TotpConfirmView,
    TotpEnrollView,
    TwoFactorDisableView,
    TwoFactorOtpRequestView,
    TwoFactorStatusView,
    TwoFactorVerifyView,
)

urlpatterns: list[URLPattern] = [
    path("login/", LoginView.as_view(), name="jwt-multiauth-login"),
    path("password/change/", PasswordChangeView.as_view(), name="jwt-multiauth-password-change"),
    path(
        "password/reset/request/",
        PasswordResetRequestView.as_view(),
        name="jwt-multiauth-password-reset-request",
    ),
    path(
        "password/reset/confirm/",
        PasswordResetConfirmView.as_view(),
        name="jwt-multiauth-password-reset-confirm",
    ),
    path("otp/request/", OtpRequestView.as_view(), name="jwt-multiauth-otp-request"),
    path("otp/verify/", OtpVerifyView.as_view(), name="jwt-multiauth-otp-verify"),
    path("otp/resend/", OtpResendView.as_view(), name="jwt-multiauth-otp-resend"),
    path("methods/", AuthMethodsView.as_view(), name="jwt-multiauth-methods"),
    path("2fa/status/", TwoFactorStatusView.as_view(), name="jwt-multiauth-2fa-status"),
    path("2fa/totp/enroll/", TotpEnrollView.as_view(), name="jwt-multiauth-2fa-totp-enroll"),
    path("2fa/totp/confirm/", TotpConfirmView.as_view(), name="jwt-multiauth-2fa-totp-confirm"),
    path("2fa/disable/", TwoFactorDisableView.as_view(), name="jwt-multiauth-2fa-disable"),
    path(
        "2fa/recovery-codes/regenerate/",
        RecoveryCodesRegenerateView.as_view(),
        name="jwt-multiauth-2fa-recovery-codes-regenerate",
    ),
    path(
        "2fa/otp/request/",
        TwoFactorOtpRequestView.as_view(),
        name="jwt-multiauth-2fa-otp-request",
    ),
    path("2fa/verify/", TwoFactorVerifyView.as_view(), name="jwt-multiauth-2fa-verify"),
    path("token/refresh/", TokenRefreshView.as_view(), name="jwt-multiauth-token-refresh"),
    path("token/verify/", TokenVerifyView.as_view(), name="jwt-multiauth-token-verify"),
    path("logout/", LogoutView.as_view(), name="jwt-multiauth-logout"),
    path("logout/all/", LogoutAllView.as_view(), name="jwt-multiauth-logout-all"),
    path("sessions/", SessionListView.as_view(), name="jwt-multiauth-sessions"),
    path("sessions/<uuid:pk>/", SessionRevokeView.as_view(), name="jwt-multiauth-sessions-revoke"),
    path(
        "trusted-devices/",
        TrustedDeviceListView.as_view(),
        name="jwt-multiauth-trusted-devices",
    ),
    path(
        "trusted-devices/<int:pk>/",
        TrustedDeviceRevokeView.as_view(),
        name="jwt-multiauth-trusted-devices-revoke",
    ),
    path(
        "account/verify-contact/request/",
        VerifyContactRequestView.as_view(),
        name="jwt-multiauth-verify-contact-request",
    ),
    path(
        "account/verify-contact/confirm/",
        VerifyContactConfirmView.as_view(),
        name="jwt-multiauth-verify-contact-confirm",
    ),
]
