"""Plain ``django.contrib.admin.ModelAdmin`` registrations for the seven models.

Phase 2 implements registrations for ``OtpChallenge``, ``AuthSession``, ``TwoFactorDevice``,
``RecoveryCode``, ``VerifiedContact``, ``LoginAttempt``, ``TrustedDevice``. Jazzmin is **not** a
dependency of this package — this app never writes to ``JAZZMIN_SETTINGS`` itself; a suggested
icon per model lives in the README (``docs/CONTRACT.md`` §0's "Jazzmin" row).

Every model reference here is indirect — ``django.contrib.auth.get_user_model()`` for the user,
never a concrete import (this repo's ``CLAUDE.md`` rule 1). Never renders ``secret_encrypted``,
``code_hash``, or ``token_hash``; session revocation goes through ``services.TokenService``,
never a raw queryset ``.update()``, so the revoked-session signal path always fires.
"""
