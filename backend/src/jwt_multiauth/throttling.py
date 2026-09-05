"""The literal ``jwt_multiauth_*``/``jwt_multiauth_admin_*`` throttle-scope string constants
every view in this app sets as its ``throttle_scope``.

**Not** built via ``appkit.throttling.throttle_scope()`` — that helper raises ``ValueError`` if
either argument contains an underscore (``"appkit.throttling.throttle_scope() arguments must not
contain an underscore"``), and this app's own namespace, ``jwt_multiauth``, contains one.
Every scope below is therefore a hand-written literal instead, exactly as
``django-dynamic-user`` does for the same reason (its own namespace, ``dynamic_user``, has the
same problem). ``appkit.checks.check_throttle_scopes`` (``appkit.W004``) still validates each of
these has a matching ``REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]`` entry — that check doesn't care
how the scope string was produced.

Every name below is frozen the moment a view sets it — renaming one without also updating a
host's ``DEFAULT_THROTTLE_RATES`` config is silently invisible (DRF only raises at request time,
per request, for a missing rate), which is exactly what ``appkit.W004`` exists to catch at
``manage.py check`` time instead.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- self-service (§5)
LOGIN = "jwt_multiauth_login"
PASSWORD_CHANGE = "jwt_multiauth_password_change"  # noqa: S105 -- a throttle scope, not a secret
PASSWORD_RESET_REQUEST = "jwt_multiauth_password_reset_request"  # noqa: S105 -- see above
PASSWORD_RESET_CONFIRM = "jwt_multiauth_password_reset_confirm"  # noqa: S105 -- see above
OTP_REQUEST = "jwt_multiauth_otp_request"
OTP_VERIFY = "jwt_multiauth_otp_verify"
OTP_RESEND = "jwt_multiauth_otp_resend"
TOKEN_REFRESH = "jwt_multiauth_token_refresh"  # noqa: S105 -- a throttle scope, not a secret
TOKEN_VERIFY = "jwt_multiauth_token_verify"  # noqa: S105 -- see above
LOGOUT = "jwt_multiauth_logout"
LOGOUT_ALL = "jwt_multiauth_logout_all"
TWO_FACTOR_STATUS = "jwt_multiauth_2fa_status"
TWO_FACTOR_TOTP_ENROLL = "jwt_multiauth_2fa_totp_enroll"
TWO_FACTOR_TOTP_CONFIRM = "jwt_multiauth_2fa_totp_confirm"
TWO_FACTOR_DISABLE = "jwt_multiauth_2fa_disable"
TWO_FACTOR_RECOVERY_REGENERATE = "jwt_multiauth_2fa_recovery_regenerate"
TWO_FACTOR_VERIFY = "jwt_multiauth_2fa_verify"
SESSIONS_LIST = "jwt_multiauth_sessions_list"
SESSIONS_REVOKE = "jwt_multiauth_sessions_revoke"
TRUSTED_DEVICES_LIST = "jwt_multiauth_trusted_devices_list"
TRUSTED_DEVICES_REVOKE = "jwt_multiauth_trusted_devices_revoke"
VERIFY_CONTACT_REQUEST = "jwt_multiauth_verify_contact_request"
VERIFY_CONTACT_CONFIRM = "jwt_multiauth_verify_contact_confirm"
#: Generous default rate, cached via appkit.mixins.CachedListMixin (static per deployment) —
#: docs/CONTRACT.md §5.
METHODS = "jwt_multiauth_methods"

# ---------------------------------------------------------------------------------- admin (§5)
ADMIN_SESSIONS_LIST = "jwt_multiauth_admin_sessions_list"
ADMIN_SESSIONS_REVOKE = "jwt_multiauth_admin_sessions_revoke"
ADMIN_TRUSTED_DEVICES_LIST = "jwt_multiauth_admin_trusted_devices_list"
ADMIN_TRUSTED_DEVICES_REVOKE = "jwt_multiauth_admin_trusted_devices_revoke"
ADMIN_LOGIN_ATTEMPTS_LIST = "jwt_multiauth_admin_login_attempts_list"
ADMIN_USER_SECURITY = "jwt_multiauth_admin_user_security"
ADMIN_USER_UNLOCK = "jwt_multiauth_admin_user_unlock"
ADMIN_TWO_FACTOR_FORCE_DISABLE = "jwt_multiauth_admin_2fa_force_disable"
