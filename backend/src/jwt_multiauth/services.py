"""This app's public callable interface — the ONLY place a token is issued/rotated, an OTP
challenge is created/verified, a password is changed/reset, a 2FA method is enrolled/verified/
disabled, or a lockout is checked/recorded.

``docs/CONTRACT.md`` §4 specifies this module in full: ``TokenService`` (Phase 3), ``OtpService``
(Phase 4), ``PasswordService``/``TwoFactorService``/``VerificationService``/``LockoutService``
(Phase 5) — plus every exception class this module raises and the frozen dataclasses it returns.
Exception classes are declared first in the real implementation, each docstring naming its raiser
and the HTTP status the relevant ``views_*`` module maps it to.

Every model reference is resolved through ``settings.AUTH_USER_MODEL``/``get_user_model()`` at
call time, never a concrete import (this repo's ``CLAUDE.md`` rule 1). Recovery codes are never
the only offered second factor — ``eligible_methods`` never returns ``["recovery_code"]`` alone,
a hard constraint restated here per ``docs/CONTRACT.md`` §11 item 14, proven by a dedicated
Phase 7 test.

A ``services.py`` method signature is frozen the moment it ships — changing one is a MAJOR
version bump with a ``Host action:`` line in ``CHANGELOG.md`` (this repo's ``CLAUDE.md``
semver-trigger list).
"""

from __future__ import annotations


class TokenService:
    """Phase 3 implements this class in full (``docs/CONTRACT.md`` §4: ``issue_token_pair``,
    ``rotate_refresh``, ``revoke_session``, ``revoke_all_sessions``, ``verify_access_token``,
    ``issue_pending_2fa_token``, ``verify_pending_2fa_token``). Only ``revoke_session`` exists at
    Phase 2, because ``admin.AuthSessionAdmin``'s revoke action calls it — see this repo's
    ``CLAUDE.md``: "an admin action to revoke selected sessions calling TokenService.revoke_session,
    never a raw queryset .update()".
    """

    @staticmethod
    def revoke_session(session_id: str, *, reason: str) -> None:
        """Idempotent — revoking an already-revoked session is a no-op, not an error. Fires
        ``session_revoked``. Signature and docstring frozen by ``docs/CONTRACT.md`` §4; the body
        is Phase 3's job — raising here rather than a silent ``...`` so an admin's "revoke" click
        cannot report success while doing nothing.
        """
        raise NotImplementedError("TokenService.revoke_session lands in Phase 3.")
