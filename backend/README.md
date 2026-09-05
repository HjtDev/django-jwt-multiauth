# django-jwt-multiauth

JWT authentication layer for a host Django project, as an installable app package —
username/password login (with password reset), phone-OTP login, email-OTP login, optional
TOTP/OTP-based 2FA, refresh-token rotation with reuse detection, session management, and a
secure frontend token manager.

- **Importable module:** `jwt_multiauth`.
- **PyPI distribution:** `django-jwt-multiauth`. **npm package:** `@hjtdev/django-jwt-multiauth`.
- This app does not do user data management — no profile, settings, avatar, or account-deletion
  flow. It reaches the active user only via `settings.AUTH_USER_MODEL`/`get_user_model()`, the
  same indirection `django.contrib.auth`'s own views use.
- Requires another app package: **No.** `hjtdev-appkit` is a real, versioned dependency (cache,
  pagination, permissions, error envelope, encryption, client-IP resolution,
  `HttpClient`/provider) — install and wire it *before* this app.

**This README is a placeholder.** The full config block, settings table, endpoint list, signal
payloads, and service signatures land in Phase 12, once the surfaces they document actually
exist. See `docs/CONTRACT.md` for the frozen contract in the meantime.

## Compatibility

- Python 3.13+ · Django 5.2–6.x · Django REST Framework 3.15+ · drf-spectacular 0.27+
- `hjtdev-appkit>=2.0,<3.0` — a declared dependency, not optional.

## Installation — backend

```bash
uv add "django-jwt-multiauth>=1.0,<2.0"
```

Optional extras:

```bash
uv add "django-jwt-multiauth[totp]"       # pyotp + hjtdev-appkit[crypto], for TOTP 2FA
uv add "django-jwt-multiauth[channels]"   # channels, for JWTAuthMiddlewareStack
uv add "django-jwt-multiauth[celery]"     # celery[redis] + django-celery-beat, for scheduled tasks
```

None of the three extras is required for the app to be fully functional against its default
settings (`ALLOWED_AUTH_METHODS = ["password"]`, `TWO_FACTOR["POLICY"] = "off"`).
