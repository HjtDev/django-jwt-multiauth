# graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).

# CLAUDE.md — django-jwt-multiauth (app package #4)

A standalone, versioned, dual-package Django + React app package that **is** a host project's JWT
authentication layer: username/password login (with password reset), phone-OTP login, email-OTP
login, optional TOTP/OTP-based 2FA, refresh-token rotation with reuse detection, session
management, and a secure frontend token manager. It depends on `appkit` (app package #1) for
caching, pagination, permissions, error envelope, encryption, client-IP resolution, and
`HttpClient`/provider, exactly like every other app in this ecosystem — and it is the app
`appkit`'s own `docs/CONTRACT.md` §16 and §J were written in anticipation of (`headerSources`, and
the standing rule that token refresh belongs in the host's client, never in `appkit`).

**This app does not do user data management.** No profile, no settings, no avatar, no
account-deletion flow — that is `django-dynamic-user`'s job (app package #3), and this app never
imports it. The two apps meet only at `settings.AUTH_USER_MODEL` and `get_user_model()`, exactly
the indirection `django.contrib.auth`'s own views use — the same boundary `django-dynamic-user`'s
own `CLAUDE.md` states from its side ("This app does not do authentication… a separate `auth-app`
package's job"). This app is that package.

**Read `docs/APP-DESIGN.md` in full before making changes.** For the actual build order, use
**`docs/CLAUDE-CODE-GUIDE-APP-JWT-MULTIAUTH.md`** — it is this project's own pre-customized
instance of `docs/CLAUDE-CODE-GUIDE-APP.md`, with every phase prompt, model, endpoint, setting,
and hook already decided so a phase session is paste-and-go instead of a re-derive-the-prompt
session. Once `docs/CONTRACT.md` exists (Phase 0), read that too — it's the frozen contract this
file's summary reflects. This file is the fast reference; the guide is the map.

**Shared docs live in `HjtDev/ecosystem-docs`, not here.** `docs/APP-DESIGN.md`,
`docs/BASE-DESIGN.md`, `docs/INTEGRATION-GUIDE.md`, `docs/CLAUDE-CODE-GUIDE-APP.md`, and
`docs/CLAUDE-CODE-GUIDE-BASE.md` are symlinks into a sibling `../ecosystem-docs` checkout
(`make docs-link`) — the same five files, unchanged, shared with `appkit`, `cleanup_app`, and
`django-dynamic-user`. **Edit them there, never here** — a local edit to the symlink target
changes the file in every project that links it, which is the point, but only if the edit actually
lands in `ecosystem-docs` and gets committed/pushed from that repo. `docs/CONTRACT.md`,
`docs/CLAUDE-CODE-GUIDE-APP-JWT-MULTIAUTH.md`, and `docs/SECURITY-CHECKLIST.md` are this project's
own and stay real files here.

## The rules that define this package

1. **Every model reference is indirect, always.** `settings.AUTH_USER_MODEL` /
   `django.contrib.auth.get_user_model()` for the user — **never** a concrete import, not even
   inside this package's own `admin.py` or `services.py`. This app must never know or care whether
   the host runs `django.contrib.auth.User`, a project-specific subclass, or `dynamic_user.User`.
2. **The user model is validated, never assumed.** `checks.py` fails Django's startup checks when
   an *enabled* authentication method needs a field the resolved user model doesn't have —
   `phone_otp` requires a unique, nullable phone field named by
   `JWT_MULTIAUTH["USER_FIELDS"]["PHONE_FIELD"]`; `email_otp` requires a unique email field named
   by `["EMAIL_FIELD"]`. A missing field is a **system-check error at `manage.py check` time**,
   never a `500` the first time someone tries to log in with it.
3. **Fail closed, everywhere, with no exceptions carved out later.** An unresolvable 2FA method
   (the user's enrolled factors, intersected with the allowlist and the different-channel rule,
   come up empty), an unconfigured OTP delivery channel, a missing encryption key needed by an
   *enabled* feature, an ambiguous or malformed identifier — every one of these **rejects the
   request**. This app never silently downgrades a login to weaker-than-configured security to
   keep a request succeeding.
4. **No secret is ever stored recoverably, and no comparison is ever fast-fail.** OTP codes and
   recovery codes are stored as salted HMAC-SHA256 digests, never plaintext. TOTP secrets are
   encrypted at rest with `appkit.crypto.Cipher` (Fernet), keyed by
   `JWT_MULTIAUTH_ENCRYPTION_KEY` — never the app's own scheme, never plaintext, never derived
   silently from `SECRET_KEY` for this one value (a `SECRET_KEY` rotation must never invisibly
   brick every enrolled authenticator). Every code/hash/token comparison anywhere in this package
   uses `hmac.compare_digest` or an equivalent constant-time comparison — never `==`. Every
   generated code, token, or key uses the `secrets` module — never `random`.
5. **Every failure path is enumeration-resistant.** An unknown identifier and a known identifier
   with a wrong credential return the same status code, the same response shape, and
   (deliberately, via a dummy-hash computation on the miss path) approximately the same timing.
   `POST /otp/request/` for an unregistered identifier returns a real-shaped decoy challenge rather
   than a 404. `POST /password/reset/request/` always returns `200`, whether or not the identifier
   resolves to a real, active account.

## Scope boundary

| In | Out |
|---|---|
| Password login + password change + password reset (via OTP challenge), phone-OTP login, email-OTP login, magic-link login (an OTP challenge's link-token form). Account **creation** for a phone/email-OTP identifier nobody has seen before, but only when its method is opted into `USER_FIELDS["AUTO_PROVISION_METHODS"]` (default: no methods are) — sets the one proven contact field and an unusable password, nothing else | Registration/signup as a *feature* (a signup form, a "create account" flow), profile fields, avatars, account-deletion — `django-dynamic-user`'s job. Auto-provisioning is a side effect of a successful OTP login, not a signup surface this app exposes |
| Refresh-token rotation, reuse detection, session listing/revocation (self-service + admin) | Anything resembling a general-purpose session/cache store — sessions here mean auth sessions only |
| Optional 2FA: TOTP, email-OTP, phone-OTP, and recovery codes as second factors, with a policy toggle (`off`/`opt_in`/`required`/`staff_only`) and a different-channel rule | Authenticator-app UI, QR rendering — the backend returns an `otpauth://` URI; rendering the QR is the frontend/host's job |
| Login-attempt audit log, IP/account lockout, trusted-device (skip-2FA) cookies | Notification delivery of any kind — this app only emits `phone_otp_requested`/`email_otp_requested` signals; wiring them to Twilio/SES/whatever is the host's or a notification-app's job |
| Optional Channels `JWTAuthMiddlewareStack`, behind a `[channels]` extra | Any WebSocket business logic — that's the app that ships the consumer |
| A frontend token manager (`authStore`, `authHeaderSource`, `withAuthRetry`) the host wires into appkit's `ApiClientProvider` | A concrete `HttpClient` implementation, CSRF handling, or CORS config — those stay the host's, per `BASE-DESIGN.md` §3's "Auth integration" |

## Dependency ranges & pinned versions

| Decision | Value |
|---|---|
| Python | `requires-python = ">=3.13"` (range); `.python-version` pins `3.14` locally |
| Django / DRF | `>=5.2,<7.0` / `>=3.15,<4.0` |
| `appkit` | `hjtdev-appkit>=2.0,<3.0` |
| `PyJWT` | `pyjwt>=2.9,<3.0` — this app owns token issuance/verification directly; it does **not** depend on `djangorestframework-simplejwt` (see `docs/CONTRACT.md` for why: its own `AuthSession` model supersedes simplejwt's `token_blacklist` app, which would otherwise force an extra `INSTALLED_APPS` entry and migration set onto every host, and simplejwt's classifiers stop at Django 5.2 against this app's `<7.0` ceiling) |
| TOTP (optional `totp` extra) | `pyotp>=2.9,<3.0` + `hjtdev-appkit[crypto]>=2.0,<3.0` (Fernet, for encrypting TOTP secrets at rest) |
| Channels (optional `channels` extra) | `channels>=4.1,<5.0` |
| Celery (optional `celery` extra) | `celery[redis]>=5.4,<6.0`, `django-celery-beat>=2.7,<3.0` |
| React / `@tanstack/react-query` (peer deps) | `>=18` / `>=5` |
| `@hjtdev/appkit` (peer dep) | matching appkit's own published major |
| Vitest | 4.x |
| Coverage gate | **90%** — raised from the ecosystem's standard 85%; this app holds credentials |

## Commands

Tests run on Postgres, not SQLite (`docs/APP-DESIGN.md` §7.5), against **two** settings modules —
`tests.backend.settings` (`django.contrib.auth`'s own default `User`, proving this app works
against the model every fresh Django project starts with) and `tests.backend.settings_dynamic_user`
(a `dynamic_user.User`-shaped host, proving the phone/email field resolution actually works against
a real subclassed model, not just a hand-rolled test double). `make check` (repo root) is the local
equivalent of the raw commands below — it brings up `docker-compose.test.yml`'s ephemeral Postgres
itself, so a fresh clone needs nothing pre-installed beyond Docker and `uv`.

```bash
cd backend && uv sync                              # core only
uv sync --extra totp                                # prove the optional extra resolves
uv sync --extra channels                            # prove the optional extra resolves
uv sync --extra celery                              # prove the optional extra resolves
uv run pytest                                        # gate: authoritative, >=90% coverage, default settings
DJANGO_SETTINGS_MODULE=tests.backend.settings_dynamic_user uv run pytest -k dynamic_user  # the phone-field gate
uv run --exact pytest -m "not requires_extra" --no-cov   # bare-install check, no extras
uv run ruff check --fix . ../tests && uv run ruff format . ../tests
uv run mypy src
uv build

cd frontend && npm ci
npm run test                      # Vitest + MSW — authoritative gate for the TS half
npx tsc --noEmit && npm run lint

# Verify against real hosts before tagging — playground/default and playground/dynamic_user
cd playground/default/backend && uv sync
docker compose -f playground/docker-compose.yml up
```

CI: `.github/workflows/ci.yml` here is a ~10-line caller only, per `docs/APP-DESIGN.md` §10.2,
using the org-level reusable workflow at `HjtDev/.github`'s `app-package-ci.yml` — not recreated
locally, plus this repo's own `publish-pypi` job (§10.2 explains why that one can't live in the
shared workflow).

## Semver triggers — MAJOR bumps even when the diff is small

- Removing/renaming a signal (`phone_otp_requested`, `email_otp_requested`, `otp_verified`,
  `contact_verified`, `user_logged_in`, `user_logged_out`, `login_failed`, `account_locked`,
  `password_changed`, `two_factor_enabled`, `two_factor_disabled`, `refresh_reuse_detected`,
  `session_revoked`, `user_provisioned`), a `services.py` method signature, an exported hook, or a
  field a host might query on any of this app's models.
- Renaming a `JWT_MULTIAUTH` settings key (top-level or inside any of its sub-dicts —
  `TOKENS`/`REFRESH_COOKIE`/`OTP`/`TWO_FACTOR`/`LOCKOUT`/`PASSWORD`/`USER_FIELDS`) or the
  `ALLOWED_AUTH_METHODS` top-level key.
- Adding a value to, or removing one from, the closed set of accepted `ALLOWED_AUTH_METHODS` /
  `TWO_FACTOR["ALLOWED_METHODS"]` strings.
- Changing a token's claim shape, a JWT's algorithm default, the refresh-cookie's default
  attributes (`HttpOnly`/`Secure`/`SameSite`), or what a `details.*` error key means for any
  existing `code`.
- Weakening a default safety rail — loosening the enumeration-resistance behavior, changing
  `TWO_FACTOR["REQUIRE_DIFFERENT_CHANNEL"]`'s default, shortening `LOCKOUT`'s default thresholds,
  changing `OTP["TTL_SECONDS"]`'s default downward implicitly-permissively, or changing
  `ADMIN_REQUIRES_SUPERUSER`'s default — treat as breaking even if it's "just a default," since a
  host that never overrode it inherits the new behavior silently.
- Renaming the published distribution name (`django-jwt-multiauth` / `@hjtdev/django-jwt-multiauth`).

Every one needs a **Host action:** line in `CHANGELOG.md`.

## Working agreement (delete after v1.0.0 ships)

- One phase at a time, per `docs/CLAUDE-CODE-GUIDE-APP-JWT-MULTIAUTH.md`. Don't create files
  outside the current phase's scope.
- Re-read the relevant `docs/APP-DESIGN.md` section, and this app's own guide section, before
  writing files it specifies.
- After each phase, run its verification command **against both settings modules** where the
  phase touches business logic, and paste the real output. Never report success you haven't
  observed.
- If the spec is ambiguous or looks wrong, ask. Don't guess and proceed.
- This package must work in ANY host project, against any `AUTH_USER_MODEL` that satisfies the
  fields its *enabled* methods require. **Whenever you're about to write
  `from django.contrib.auth.models import User` (a concrete import) anywhere in this package's own
  code**, stop — use `settings.AUTH_USER_MODEL` / `get_user_model()` instead.
- Whenever you're about to store a secret (an OTP code, a recovery code, a TOTP seed, a refresh
  token) or compare one, stop and confirm: hashed-not-plaintext, `secrets`-not-`random`,
  constant-time-not-`==`. This is the one constraint that matters more than the boundary rule
  above.
- Whenever a code path is about to succeed differently depending on whether an identifier exists,
  stop and confirm the enumeration-resistance rule (rule 5 above) actually holds for it.

## Definition of done

- `docs/CONTRACT.md` and the code agree; `README.md` and the code agree.
- `backend/README.md` and `frontend/README.md` are current copies of `README.md`
  (`readme-contract` CI job green).
- Both halves at the same version, in all three places; CI's lockstep job green.
- `uv run pytest` (against both settings modules) and `npm run test` green, over 90% coverage.
- `ruff`, `mypy`, `tsc --noEmit`, `eslint` all clean.
- Zero imports of another app package; zero concrete user-model imports anywhere in this package's
  own code; `appkit` is the only exception.
- Every emitted signal has a test asserting its exact documented payload.
- Every endpoint has a non-permitted-user-gets-403(-or-404) test that actually fails when the
  relevant permission check is removed.
- The enumeration-resistance rule is proven, not assumed, for every identifier-taking endpoint:
  unknown vs. known-wrong-credential produce the same status/shape, and a timing-sensitive test
  exists for the password path.
- Every stored secret is proven hashed/encrypted at rest by an actual database-row inspection in a
  test, not by reading the code that claims it.
- The privilege-escalation guard (admin force-disable-2FA, admin session revocation) is proven, not
  assumed, by an actual attempt against it.
- Playground verified on **both** hosts: default `django.contrib.auth` user and a
  `dynamic_user`-shaped host with a real phone field, the latter's phone-OTP login round-tripping
  over real HTTP with zero package-level code changes.
- Security checklists (`APP-DESIGN.md` §9 and §12, plus this app's own `docs/SECURITY-CHECKLIST.md`
  additions) walked with evidence, not assumed.
- Installed into a fresh `base-scaffold` clone using only the README.
- Tagged `v1.0.0`; PyPI and npm entries both show a real, non-empty description — checked
  directly against the registry, not assumed from green CI.

## Git protocol

- Never stage or commit unless explicitly asked. Every diff gets reviewed before it lands.
- Never `git push`, `git reset --hard`, `git checkout <branch>`, force-push, or amend an existing
  commit. Ever. Ask instead.
- When a phase or task is done, don't commit — summarise what changed and the verification output
  that passed, propose a commit message in the format below (fenced, copy-pasteable), then stop
  and wait for review.
- If something needs reverting, say so and let the reviewer do it.

### Commit message format

```
semantic(<scope>): <short_commit_message>

- Add <what was added>
- Remove <what was removed>
- Update <what was changed>
```

Rules for it:
- `semantic` is one of: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `build`, `ci`, `perf`,
  `style`. Use `!` after the scope for a breaking change: `feat(services)!:`.
- `<scope>`: lowercase, one word — `backend`, `frontend`, `api`, `hooks`, `ci`, `deps`,
  `playground`, `docs`, `admin`. Narrowest scope that covers the change.
- `<short_commit_message>`: imperative mood, lowercase, no trailing period, under 60 chars.
- Blank line after the title, then literal `- `-prefixed bullets, each starting with an
  imperative verb (`Add`, `Remove`, `Update`, `Move`, `Rename`, `Fix`, `Pin`, `Enable`,
  `Disable`), capitalised, no trailing period. Group trivia, don't list every file.
- Host action required (new settings key, a config block to copy)? Final line:
  `Host action: <what to do>`.
- No co-author trailers, no "generated with" footers, no emoji.
- A commit changing a signal payload, a service signature, a settings key, a token claim shape, or
  a default safety rail uses `!` and always gets a `Host action:` line.

Example:

```
chore(backend): add uv project config and tooling baseline

- Add backend/pyproject.toml with dependencies, dev/test dependency groups and uv default-groups
- Add ruff, mypy, pytest and coverage configuration
- Add commented banned-api table enforcing the no-inter-app-import rule
- Add MANIFEST.in, .python-version and .gitignore
```
