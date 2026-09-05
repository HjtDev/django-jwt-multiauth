# CLAUDE-CODE-GUIDE-APP-JWT-MULTIAUTH.md — Building `django-jwt-multiauth`

Project-specific instance of `docs/CLAUDE-CODE-GUIDE-APP.md`, pre-customized so each phase is a
paste-and-go session instead of a re-derive-the-design session. **This file is what you follow
phase by phase.** The generic guide stays as reference for *why* each phase is shaped this way;
this one has already made every project-specific call the generic guide's §1.3 table asks for (see
§1 below), so no session needs to re-decide them.

> Companions: `docs/APP-DESIGN.md` (the architecture every app package follows),
> `docs/CLAUDE-CODE-GUIDE-APP.md` (the generic process this document instantiates),
> `docs/INTEGRATION-GUIDE.md` (the host side), `docs/BASE-DESIGN.md` (what a host provides),
> `appkit/docs/CONTRACT.md` §16 and §J (the two sections of `appkit`'s own contract written in
> anticipation of this app — read them once before Phase 0, they aren't repeated in full here).

---

## 0. What this app is, and the five constraints unique to it

A reusable Django + React app package that **is** a host project's JWT authentication layer:
username/password login with password reset, phone-OTP login, email-OTP login (including a
magic-link variant), optional 2FA (TOTP, OTP-based, or recovery codes) with a channel-diversity
rule, refresh-token rotation with reuse detection, session listing/revocation on both the
self-service and admin surfaces, IP/account lockout, a persistent login-attempt audit log, and a
frontend token manager a host wires into `appkit`'s shared `ApiClientProvider` via
`headerSources`.

**This app deliberately does not manage user data.** No registration form beyond "create the
account row," no profile, no settings, no avatar, no account-deletion flow — that is
`django-dynamic-user`'s job (app package #3), which this app never imports. The two meet only
through `settings.AUTH_USER_MODEL` / `django.contrib.auth.get_user_model()`, the same indirection
`django.contrib.auth`'s own views use. `django-dynamic-user`'s `CLAUDE.md` states its side of this
same boundary ("This app does not do authentication… a separate `auth-app` package's job") —
this app is that package, and it depends on nothing `django-dynamic-user` provides. A host can run
this app against `django.contrib.auth`'s own default `User`, against `django-dynamic-user`'s
`User`, or against any other custom user model — the only requirement is that the fields its
*enabled* auth methods need actually exist (§0.2 below).

**`appkit`'s own contract was written with this app in mind.** `appkit/docs/CONTRACT.md` §16
(`headerSources`) exists specifically so this app's `Authorization` header can be attached without
`appkit` ever knowing a token exists, and §J states outright: *"The eventual JWT app's own README
must document that refresh belongs in the host's client."* Phase 10 (frontend) and Phase 12
(README) are where that promise gets kept — don't reach for a retry-on-401 mechanism inside
`appkit` itself; it was never going to exist there, on purpose.

Same operating principle as every app package (`CLAUDE-CODE-GUIDE-APP.md` §0): a contract before
code, machine-enforced boundaries from Phase 1. Five things are unique to *this* app and apply to
every phase below without exception — they are `CLAUDE.md`'s "rules that define this package,"
restated here with the reasoning behind each:

1. **Every model reference is indirect, always.** `settings.AUTH_USER_MODEL` /
   `django.contrib.auth.get_user_model()` — never a concrete `User` import, not even in this
   package's own `admin.py` or `services.py`. Unlike `django-dynamic-user`, this app has no
   `resolution.py` of its own to write — Django's own indirection is already the complete
   mechanism, since this app never defines or swaps the user model itself.
2. **The user model is validated per *enabled* method, never assumed.** `checks.py` fails
   `manage.py check` when `"phone_otp"` is in `ALLOWED_AUTH_METHODS` but the resolved user model
   has no field named `JWT_MULTIAUTH["USER_FIELDS"]["PHONE_FIELD"]`, or when `"email_otp"` is
   enabled and `["EMAIL_FIELD"]` doesn't resolve, or when `TWO_FACTOR["ENABLED"]` is true and
   `"totp"` is in its `ALLOWED_METHODS` but `JWT_MULTIAUTH_ENCRYPTION_KEY` is unset. A method a
   host never turns on imposes no requirement at all — this is a check on the *combination* of
   settings, not a blanket demand for every field this app could ever use.
3. **Fail closed, everywhere, permanently.** An unresolvable second factor (the intersection of a
   user's enrolled methods, `TWO_FACTOR["ALLOWED_METHODS"]`, and the different-channel rule comes
   up empty), an unconfigured delivery channel, a missing key an enabled feature needs, a malformed
   or ambiguous identifier — every one of these is a rejected request, never a request that
   quietly proceeds with less security than configured. There is no "if 2FA can't be satisfied,
   just log them in" code path anywhere in this design, and no phase should introduce one, even
   temporarily, even behind a TODO.
4. **No secret is ever stored recoverably; every comparison is constant-time; every generator is
   `secrets`, never `random`.** OTP codes and recovery codes are HMAC-SHA256 digests. TOTP secrets
   are encrypted with `appkit.crypto.Cipher`, keyed by `JWT_MULTIAUTH_ENCRYPTION_KEY` — a value
   independent of `SECRET_KEY`, deliberately, so rotating `SECRET_KEY` (a routine incident-response
   action) can never silently invalidate every user's authenticator app. Trusted-device cookies are
   hashed the same way a refresh token would be. A login identifier (username/email/phone attempted
   at the login form) is **not** a secret by this rule's own definition and is stored in
   `LoginAttempt` as plain text — deliberately, so an admin reviewing the audit log can actually
   search it; don't "improve" this into a hash later without updating the admin UI to match.
5. **Every failure path is enumeration-resistant.** Unknown identifier and known-identifier-wrong-
   credential produce the same status, the same response body shape, and near-identical timing (a
   dummy password-hash computation on the miss path, matching Django's own
   `django.contrib.auth.authenticate` guard against exactly this). `POST /otp/request/` for an
   identifier that doesn't resolve returns a real-shaped, unpersisted decoy challenge — a
   response body no different from the real one, but no database row and no message actually sent.
   `POST /password/reset/request/` always returns `200`.

---

## 1. Decisions already made (the generic guide's §1.3 table, answered)

Read this once; every phase prompt below assumes it.

| Question | Decision |
|---|---|
| Importable module name | **`jwt_multiauth`** — verified unclaimed against every currently-installed app in this ecosystem (`appkit`, `cleanup_app`, `dynamic_user`) |
| PyPI distribution | **`django-jwt-multiauth`** — verified free on PyPI at the time this guide was written (re-verify in Phase 13 per that phase's own step 1) |
| npm package | **`@hjtdev/django-jwt-multiauth`** — verified free on npm at the time this guide was written; scoped, matching every other frontend SDK in this ecosystem |
| GitHub repo | `HjtDev/django-jwt-multiauth` |
| Namespacing (`APP-DESIGN.md` §1.2) | settings dict `JWT_MULTIAUTH` (nested sub-dicts, see §1's settings table below); throttle prefix `jwt_multiauth_` (admin: `jwt_multiauth_admin_`) — **hardcoded string constants in `throttling.py`, never `appkit.throttling.throttle_scope()`**, because that helper raises `ValueError` if either argument contains an underscore, and `jwt_multiauth` itself contains one; cache namespace `jwt_multiauth`; Celery task names `jwt_multiauth.tasks.*`; **two** frontend basePath keys — `jwt_multiauth` → `/api/v1/auth` (self-service) and `jwt_multiauth_admin` → `/api/v1/admin/auth` (admin), same two-surface shape `django-dynamic-user` already established in this ecosystem |
| Scope | Authentication only: login (three methods), password reset, 2FA, sessions, lockout, audit log. No profile/settings/avatar/deletion — `django-dynamic-user`'s job. No delivery of anything — this app emits `phone_otp_requested`/`email_otp_requested` and a host wires them to Twilio/SES/whatever, exactly the signal-mediator pattern `APP-DESIGN.md` §6 describes |
| JWT layer | **PyJWT directly** (`pyjwt>=2.9,<3.0`), not `djangorestframework-simplejwt`. `tokens.py` owns claim construction/verification; `AuthSession` (this app's own model) supersedes simplejwt's `token_blacklist` app for rotation/reuse-detection, so a host never gets `rest_framework_simplejwt.token_blacklist` forced into `INSTALLED_APPS`. Also: simplejwt 5.5.1 (latest at time of writing) declares no Django 6 classifier, a live risk against this app's own `django>=5.2,<7.0` range |
| Refresh transport | **HttpOnly, Secure, SameSite cookie by default** (`REFRESH_COOKIE["TRANSPORT"]="cookie"`); a `"body"` mode exists for native/non-browser clients. Access token is never persisted anywhere — issued in the response body, held in JS memory only on the frontend (Phase 10) |
| 2FA | Optional, policy-driven (`off`/`opt_in`/`required`/`staff_only`), method allowlist (`totp`/`email_otp`/`phone_otp`/`recovery_code`), and a **mandatory different-channel rule**: the second factor can never be the same channel as the primary login method. If a user's enrolled methods, intersected with the allowlist and that rule, come up empty, login fails with `two_factor_unavailable` — it never degrades to single-factor |
| View↔transport binding | Separate view modules per method, per your own instruction: `views_password.py`, `views_otp.py`, `views_token.py`, `views_twofactor.py`, `views_session.py`, `views_account.py`, plus `admin_views.py`. No god `views.py` |
| Admin gating | `appkit.permissions.IsAppAdmin` (`is_staff`) by default on every admin endpoint, consistent with the rest of the ecosystem. `JWT_MULTIAUTH["ADMIN_REQUIRES_SUPERUSER"]` (default `False`) tightens every admin gate to `is_superuser`. **Unconditionally, regardless of that setting**: forcing another user's 2FA off is superuser-only |
| Frontend half? | Yes — hooks for both surfaces, plus the token-manager trio (`authStore`, `authHeaderSource`, `withAuthRetry`) that is this app's whole answer to "handle login/logout and token store/refresh/verify securely" |
| User-model need beyond itself | `settings.AUTH_USER_MODEL`, plus two *field names* it reads off whatever that model resolves to (`USER_FIELDS.EMAIL_FIELD`, `USER_FIELDS.PHONE_FIELD`) — never a concrete type, never a required base class, never a required mixin |
| Other-app references | None. No `contenttypes` need (nothing here is polymorphic) |
| `.env` keys | **One conditionally required**: `JWT_MULTIAUTH_ENCRYPTION_KEY` (Fernet key, `appkit.crypto.generate_key()`) — required only when `TWO_FACTOR["ENABLED"]` and `"totp"` is in `ALLOWED_METHODS`. Two optional, HKDF-derived from `SECRET_KEY` when unset: `JWT_MULTIAUTH_SIGNING_KEY` (JWT signing — deriving from `SECRET_KEY` is fine for `HS256`, but a host on `RS256` must set this to a private key), `JWT_MULTIAUTH_OTP_PEPPER` (extra HMAC input for OTP/recovery-code hashing, independent of the DB) |
| Celery | Optional extra `[celery]`. Tasks: `jwt_multiauth.tasks.purge_expired_otp_challenges`, `.purge_expired_sessions`, `.purge_login_attempts`, `.purge_expired_trusted_devices`. Every task has a matching management command for a host with no worker |
| Other extras | `[totp]` → `pyotp>=2.9,<3.0` + `hjtdev-appkit[crypto]>=2.0,<3.0` (needed only if `"totp"` is ever in `TWO_FACTOR["ALLOWED_METHODS"]`). `[channels]` → `channels>=4.1,<5.0` (needed only if a host mounts `JWTAuthMiddlewareStack`) |
| `appkit` helpers used | `crypto.Cipher`/`generate_key` (TOTP secret encryption, `crypto` extra), `net.client_ip` (lockout scoping, login-attempt IP), `permissions.IsAppAdmin`/`IsObjectOwner`, `pagination.DefaultPagination`, `mixins.CachedListMixin` (the `GET /methods/` discovery endpoint only — nothing else in this app is cacheable, since everything else is per-request-sensitive auth state), `cache.build_cache_key`/`cached_call`/`invalidate_namespace` (lockout counters), `validation.validate_query_params`/`safe_filter_kwargs` (admin filtering), `exceptions.standard_exception_handler` (wired by the host per `BASE-DESIGN.md` §3, consumed as-is), `testing` pytest plugin (`-p appkit.testing` — see the note in §2 Phase 1 about why its fixtures need a companion, not a replacement). Frontend: `HttpClient`, `ApiClientProvider`/`useApiClient`, `ApiError`/`isApiError`. **No gap, no appkit release needed** — confirmed against `appkit` v2.0.2's full inventory before writing this guide |
| Coverage gate | **90%** — raised above the ecosystem's standard 85%, because this app holds credentials |

**Design facts this guide already settled, so no phase re-derives them:**

- **`OtpChallenge` rows for a real, resolved identifier are persisted; decoy challenges for an
  unknown identifier are not.** The decoy path still performs an equivalent HMAC computation before
  responding, so the *timing* is close, without paying the storage/GC cost of a challenge nobody
  can ever complete. `challenge_id` is a `uuid4` in both cases, so the response shape is identical
  either way — there is nothing in the wire format an attacker can use to distinguish them.
- **Settings resolve purpose → channel → global**, so e.g. an email OTP can carry 8
  alphanumeric characters with a 10-minute TTL while an SMS OTP carries 6 digits with a 5-minute
  TTL, and a `password_reset` OTP can have a longer TTL than a `login` OTP on the same channel.
  `conf.get_otp_setting(key, *, channel, purpose)` is the one function every OTP-touching file calls
  — never a raw `settings.JWT_MULTIAUTH["OTP"][...]` dict walk anywhere else.
- **A successful primary factor never returns tokens directly when 2FA applies.** It returns a
  short-lived, single-purpose "pending" token (a separate JWT `typ`, unusable against any other
  endpoint) plus the caller's eligible second-factor list. Only `POST /2fa/verify/` (given a valid
  pending token) issues real tokens. This is a hard rule, not a default — no view is allowed to
  offer a "skip 2FA" branch under any settings combination.
- **`TrustedDevice` is a real, hashed bearer secret**, not a boolean flag — it is issued as a
  second cookie alongside the refresh cookie, checked at login *before* 2FA is even evaluated, and
  is itself revocable per-device from both the self-service and admin session surfaces.
- **Refresh rotation is family-based.** `AuthSession.current_jti` is replaced on every successful
  refresh; presenting an already-superseded `jti` for that session is **reuse** — the entire session
  is revoked immediately (`refresh_reuse_detected` fires), not just the offending token, on the
  standard assumption that reuse means the token was stolen and the legitimate holder's copy is now
  worthless anyway.

---

## 2. The build, phase by phase

Fresh session per phase, same hygiene as always: `/clear` between phases, one phase's scope only,
review every diff, verification command's real output pasted before moving on.

### Phase 0 — The contract (no code)

```
Phase 0: design the public contract. Write it to docs/CONTRACT.md. No implementation code.

Read docs/APP-DESIGN.md fully first — especially §1 (package contract), §2's "Referencing the
host's user model" note, §6 (inter-app communication), and §8 (README contract). Also read
appkit/docs/CONTRACT.md §16 and §J in full — appkit's own headerSources mechanism and its explicit
"token refresh belongs in the host's client, not appkit" rule were written for this app; don't
propose anything that would require appkit to know about tokens. Then read this app's own
docs/CLAUDE-CODE-GUIDE-APP-JWT-MULTIAUTH.md §0 and §1 in full — this app's name, module, scope,
JWT layer choice, refresh-transport default, 2FA model, and every namespacing decision are already
made there; do not re-derive or change them, only formalize them into CONTRACT.md's required
shape. Flag, rather than silently resolve, anything that seems to need a decision §1 didn't make.

This is django-jwt-multiauth (module: jwt_multiauth) — the JWT authentication layer for a host
project. It supports password login (+ reset), phone-OTP login, email-OTP login (+ a magic-link
variant), optional policy-driven 2FA (TOTP / OTP / recovery codes) with a mandatory
different-channel rule, refresh-token rotation with reuse detection, self-service + admin session
management, IP/account lockout, and a persistent login-attempt audit log. It does not manage user
profile data and it does not deliver anything itself — delivery is a signal a host wires up.

Produce, using the specifics below as the starting point — refine names/shapes only where the
reasoning is genuinely better, and flag any change explicitly rather than silently drifting:

1. Models — full field lists, types, indexes, every FK (all via settings.AUTH_USER_MODEL):
   - OtpChallenge: uuid pk (challenge_id must be unguessable), user (FK, nullable — a real
     challenge always has one; nothing ever creates a persisted row for a decoy), channel
     ("email"|"phone"), purpose ("login"|"password_reset"|"verify_contact"|"two_factor"),
     destination (the actual email/phone the code targeted — needed later to mark VerifiedContact),
     code_hash, link_token_hash (nullable — only set when EMIT_LINK_TOKEN applies), attempts (int,
     default 0), max_attempts (int, snapshotted from conf at creation — a mid-flight settings
     change must not retroactively change an in-flight challenge's budget), created_at, expires_at,
     consumed_at (nullable). Index on (user, purpose, consumed_at) and (expires_at) for the purge
     task.
   - AuthSession: uuid pk, user (FK), current_jti (str, unique), rotation_count (int, default 0),
     device_label (str, optional, client-supplied), ip_address, user_agent (truncated), remember_me
     (bool), created_at, last_used_at, expires_at, revoked_at (nullable), revoked_reason (nullable
     choice: user_logout|admin_revoked|reuse_detected|password_changed|expired). Index on
     (user, revoked_at) and (current_jti) unique, (expires_at).
   - TwoFactorDevice: user (FK), method (choice, currently just "totp" — the field exists so a
     future method needing persistent enrollment state doesn't need a new model), secret_encrypted
     (str, via appkit.crypto.Cipher), confirmed_at (nullable — unconfirmed enrollment never counts
     as an eligible method), last_used_step (int, replay guard for TOTP's 30s window), created_at,
     disabled_at (nullable). Unique (user, method).
   - RecoveryCode: user (FK), code_hash, used_at (nullable), created_at. Index (user, used_at).
   - VerifiedContact: user (FK), field ("email"|"phone"), value (the exact value that was
     verified — NOT hashed, since it's compared against the user model's own live field value, and
     that field is already plaintext PII on the user model itself), verified_at, created_at. Unique
     (user, field, value) — if the user's live field value later differs from every VerifiedContact
     row for that field, the field is effectively unverified again; state this resolution rule
     explicitly rather than leaving it implicit.
   - LoginAttempt: user (FK, nullable — null when the identifier never resolved), identifier (str,
     PLAINTEXT — not a secret by this app's own rule 4, and an admin needs to search it), method
     (choice), ip_address, user_agent (truncated), success (bool), failure_reason (nullable
     choice), created_at. Index (identifier, created_at), (ip_address, created_at),
     (user, created_at).
   - TrustedDevice: user (FK), token_hash (this IS a bearer secret controlling a skip-2FA decision
     — hash it like a refresh token, never store it plaintext), device_label, created_at,
     last_used_at, expires_at, revoked_at (nullable). Unique (token_hash). Index (user, revoked_at).
   Flag anything that would need a concrete import instead of settings.AUTH_USER_MODEL.

2. conf.py's OTP resolution — get_otp_setting(key: str, *, channel: str, purpose: str | None = None)
   -> Any, resolving purpose-override -> channel-override -> JWT_MULTIAUTH["OTP"]["DEFAULTS"][key],
   raising ImproperlyConfigured for an unknown key (never a silent None). Full DEFAULTS key list:
   LENGTH, ALPHABET ("numeric"|"alpha"|"alphanumeric"|a literal custom character-set string),
   EXCLUDE_AMBIGUOUS (bool — drops 0/O/1/I/l when true), CASE_SENSITIVE, TTL_SECONDS, MAX_ATTEMPTS,
   RESEND_COOLDOWN_SECONDS, MAX_RESENDS, SINGLE_ACTIVE_CHALLENGE (bool — a new request for the same
   user+purpose+channel invalidates the prior one when true), EMIT_LINK_TOKEN. The hash algorithm
   itself (HMAC-SHA256) is NOT configurable — state this explicitly as a deliberate non-setting.

3. Signals — name + exact payload kwargs (primitives/IDs only, never a model instance) + when it
   fires: phone_otp_requested(user_id, destination, code, link_token, purpose, challenge_id,
   expires_at), email_otp_requested(same shape) — TWO signals, never one with a channel kwarg, so a
   host's SMS receiver is never invoked for an email event and vice versa. otp_verified(user_id,
   challenge_id, purpose), contact_verified(user_id, field, value), user_logged_in(user_id,
   session_id, method), user_logged_out(user_id, session_id), login_failed(identifier, reason, ip),
   account_locked(user_id, until, scope), password_changed(user_id),
   two_factor_enabled(user_id, method), two_factor_disabled(user_id, method),
   refresh_reuse_detected(user_id, session_id, ip), session_revoked(session_id, user_id, reason).
   State explicitly, in the doc: the two *_otp_requested signals carry a PLAINTEXT code by design —
   that is this app's entire delivery contract, argue for keeping the payload otherwise minimal.

4. services.py — full signatures, fully typed. TokenService (issue_token_pair, rotate_refresh,
   revoke_session, revoke_all_sessions, verify_access_token, issue_pending_2fa_token,
   verify_pending_2fa_token), OtpService (request, verify, resend — request's return shape must be
   IDENTICAL for a real vs. decoy identifier), PasswordService (authenticate — constant-time,
   change_password, request_reset, confirm_reset), TwoFactorService (eligible_methods, enroll_totp,
   confirm_totp, disable, admin_force_disable, generate_recovery_codes, verify_second_factor),
   VerificationService (request_contact_verification, confirm), LockoutService (record_attempt,
   is_locked, unlock). Every method that can fail states what it raises, not just what it returns.

5. Endpoints — both surfaces, every one: method, path, permission, throttle scope name
   (jwt_multiauth_/jwt_multiauth_admin_ prefixed, literal strings), request/response shape.
   Self-service, split across the view modules named in §1's table: login, password change,
   password reset request/confirm (views_password.py); otp request/verify/resend (views_otp.py);
   token refresh/verify, logout, logout-all (views_token.py); 2fa verify/status/totp-enroll/
   totp-confirm/disable/recovery-regenerate (views_twofactor.py); session list/revoke
   (views_session.py); contact-verification request/confirm (views_account.py). Plus an
   UNAUTHENTICATED GET /methods/ discovery endpoint (allowed auth methods + 2FA policy/allowed
   methods) so a frontend renders only what's actually enabled. Admin (admin_views.py): session
   list/revoke for any user, login-attempt log (filterable), per-user security summary, unlock, and
   a force-disable-2FA route restricted to an actual superuser regardless of
   ADMIN_REQUIRES_SUPERUSER. For every endpoint touching an identifier, state explicitly how it
   satisfies rule 5 (enumeration resistance) — this is the review gate at the end of this phase.

6. Settings — the full JWT_MULTIAUTH dict, every sub-dict (TOKENS, REFRESH_COOKIE, OTP, TWO_FACTOR,
   LOCKOUT, PASSWORD, USER_FIELDS) with every key and its default, plus the top-level
   ALLOWED_AUTH_METHODS (default ["password"] — the one method that works against any user model
   with zero delivery wiring) and ADMIN_REQUIRES_SUPERUSER. Explain every interaction: what happens
   when ALLOWED_AUTH_METHODS includes "phone_otp" but USER_FIELDS.PHONE_FIELD doesn't resolve
   (checks.py error, §0 item 2); what happens when TWO_FACTOR.REQUIRE_DIFFERENT_CHANNEL leaves a
   user with zero eligible methods (login fails, never degrades).

7. Frontend hooks + the token-manager trio. Manager/hook list, both surfaces — self-service:
   useLogin, useOtpRequest, useOtpVerify, useOtpResend, usePasswordChange, usePasswordResetRequest,
   usePasswordResetConfirm, useLogout, useLogoutAll, useSessions, useRevokeSession,
   useAuthMethods (wraps GET /methods/), useTwoFactorStatus, useEnrollTotp, useConfirmTotp,
   useDisableTwoFactor, useRegenerateRecoveryCodes, useVerifyTwoFactor, useRequestContactVerification,
   useConfirmContactVerification. Admin: useAdminSessions, useAdminRevokeSession,
   useAdminLoginAttempts, useAdminUserSecurity, useAdminUnlockUser, useAdminForceDisableTwoFactor.
   Then the manager trio's contract (not full implementation — that's Phase 10): authStore's public
   shape (getAccessToken, subscribe, setAccessToken/clear — module singleton, in-memory only, never
   localStorage/sessionStorage), authHeaderSource's contract (a stable HeaderSource per appkit's
   own headerSources shape, proactive refresh inside a skew window, single-flight dedup),
   withAuthRetry's contract (an HttpClient decorator: 401 -> refresh-once -> retry-once, per
   appkit CONTRACT §J's explicit assignment of this responsibility to the host's client, satisfied
   here by shipping a ready decorator instead of leaving a host to invent one).

8. tasks.py — jwt_multiauth.tasks.purge_expired_otp_challenges, .purge_expired_sessions,
   .purge_login_attempts (respecting JWT_MULTIAUTH["LOGIN_ATTEMPT_RETENTION_DAYS"]),
   .purge_expired_trusted_devices. Behind the celery extra only. Recommended schedule for each, and
   the matching management command name for a host with no worker.

9. Dependencies: "hjtdev-appkit>=2.0,<3.0" and "pyjwt>=2.9,<3.0" in [project.dependencies];
   "pyotp>=2.9,<3.0" + "hjtdev-appkit[crypto]>=2.0,<3.0" as the "totp" extra (verify appkit's crypto
   extra name against its own pyproject.toml/README rather than assuming);
   "channels>=4.1,<5.0" as the "channels" extra; "celery[redis]>=5.4,<6.0",
   "django-celery-beat>=2.7,<3.0" as the "celery" extra.

For each of 1-8: state explicitly whether it requires knowledge of another app package. It never
should — if anything seems to, propose the decoupled alternative rather than accepting it.
```

**Review this yourself before Phase 1.** Beyond the generic guide's four checks: for every
identifier-taking endpoint, does the contract actually spell out an unknown-vs-wrong-credential
response that is byte-for-byte identical in shape? Does anything return an access token before a
required second factor completes, under any settings combination? Is `TrustedDevice` genuinely a
hashed bearer secret rather than a boolean flag on `AuthSession`? Does any signal payload carry a
model instance instead of an ID/primitive? Does `LOCKOUT`'s default `LOCK_SCOPE` avoid a shape that
lets one malicious IP lock out an arbitrary victim account by repeatedly failing their username
from many source IPs (an "identifier-only" scope is vulnerable to this in isolation — the contract
should say explicitly whether `LOCK_SCOPE` mitigates it or whether that's accepted as `LOCKOUT`'s
known trade-off, not silently overlooked).

### Phase 1 — Package skeleton, `pyproject.toml`, boundary enforcement

```
Phase 1: the package skeleton. docs/APP-DESIGN.md §2 and §3, this app's docs/CONTRACT.md.

Create the repo structure from APP-DESIGN.md §2 exactly (module directory is jwt_multiauth), then:
1. backend/pyproject.toml complete per §3.1 — dependencies from CONTRACT.md item 9 with WIDE
   RANGES: "django>=5.2,<7.0", "djangorestframework>=3.15,<4.0", "drf-spectacular>=0.27,<1.0",
   "hjtdev-appkit>=2.0,<3.0", "pyjwt>=2.9,<3.0". [project.optional-dependencies]:
   totp = ["pyotp>=2.9,<3.0", "hjtdev-appkit[crypto]>=2.0,<3.0"] (confirm appkit's crypto extra
   name against its own pyproject.toml before trusting this guide's guess), channels =
   ["channels>=4.1,<5.0"], celery = ["celery[redis]>=5.4,<6.0", "django-celery-beat>=2.7,<3.0"].
   [dependency-groups] dev + test per §3.1's template, plus "freezegun>=1.5" in test (OTP/token TTL
   tests need controllable time). [tool.uv] default-groups = ["dev", "test"]. Coverage threshold 90
   in addopts — this app's own bar, raised from the ecosystem's 85 because it holds credentials.
   Wire "-p appkit.testing" into [tool.pytest.ini_options] addopts.
2. The flake8-tidy-imports banned-api block: "cleanup_app" and "dynamic_user" (every OTHER app
   package that exists in this ecosystem as of this writing — check ecosystem-docs/APPS.md for
   whether more exist by the time you run this phase), plus "jwt_multiauth.factories" test-only
   guard. Do NOT add a line for "appkit" — it's a declared dependency every app is expected to
   import.
3. backend/MANIFEST.in so locale/, templates/, and static/ ship in the wheel.
4. .python-version (3.14), .gitignore, .pre-commit-config.yaml per §3.6.
5. src/jwt_multiauth/__init__.py, apps.py — AppConfig with a translatable verbose_name and a
   ready() that registers this app's Django system checks (see checks.py below). Nothing else
   needs wiring in ready() at this phase — there is no swappable-model machinery in this app, so
   no auto-provisioning receiver like django-dynamic-user's exists here.
   conf.py per §3.5 with the DEFAULTS from CONTRACT.md item 6, PLUS the OTP resolver function from
   CONTRACT.md item 2 (get_otp_setting(key, *, channel, purpose=None)).
6. checks.py — Django system checks (registered from apps.py's ready()) implementing CONTRACT.md's
   §0-item-2 rule: for each method actually present in JWT_MULTIAUTH["ALLOWED_AUTH_METHODS"] or
   JWT_MULTIAUTH["TWO_FACTOR"]["ALLOWED_METHODS"], verify the resolved user model / configured .env
   actually supports it — "phone_otp" needs USER_FIELDS.PHONE_FIELD to exist on
   get_user_model()._meta.get_fields(); "email_otp" needs USER_FIELDS.EMAIL_FIELD; "totp" needs
   JWT_MULTIAUTH_ENCRYPTION_KEY set AND the totp extra importable. Every failure is a real
   django.core.checks.Error naming the exact offending setting, never a crash at import time, and
   never a check that fires for a method the host never enabled.
7. keys.py — the HKDF derivation for JWT_MULTIAUTH_SIGNING_KEY and JWT_MULTIAUTH_OTP_PEPPER when
   unset (derive from settings.SECRET_KEY with a fixed, distinct HKDF "info" string per purpose, so
   the two derived values are cryptographically independent of each other even though they share a
   root secret), and a loud, actionable error if JWT_MULTIAUTH_ENCRYPTION_KEY is required (per
   checks.py above) but absent — this one is NEVER derived from SECRET_KEY, by design (§0 item 4).
8. Empty-but-present, each with a docstring stating its role per CONTRACT.md: models.py,
   tokens.py, otp.py, validators.py, views_password.py, views_otp.py, views_token.py,
   views_twofactor.py, views_session.py, views_account.py, admin_views.py, serializers.py,
   permissions.py, signals.py, services.py, urls.py, urls_admin.py, admin.py, tasks.py,
   factories.py, throttling.py (the literal jwt_multiauth_*/jwt_multiauth_admin_* scope-name
   constants — NOT built via appkit.throttling.throttle_scope(), state why in the docstring).
   middleware/ package (empty __init__.py + jwt_auth.py stub) reserved for Phase 9's Channels
   middleware, guarded so importing it without the channels extra fails with an actionable message,
   not an ImportError from deep inside Channels' own code.

Run `uv sync`, then `uv sync --extra totp`, then `uv sync --extra channels`, then
`uv sync --extra celery`, then `uv build`. Paste all five outputs.
```

**Verify:** all five commands succeed; `dependencies` are ranges, not `==`, including on `appkit`
and `pyjwt`; `checks.py` genuinely does not fire against a fresh, zero-config Django project at
`manage.py check` time (`ALLOWED_AUTH_METHODS` defaulting to `["password"]` means no field/key
requirement is active at all until a host opts into more).

**Review for:** exact pins anywhere; `include-package-data` present; `banned-api` populated and
**not** listing `appkit`; `JWT_MULTIAUTH_ENCRYPTION_KEY` genuinely never falling back to
`SECRET_KEY`-derivation anywhere in `keys.py`, even as a convenience default.

### Phase 2 — Models, migrations, admin

```
Phase 2: data layer. docs/APP-DESIGN.md §2, this app's docs/CONTRACT.md item 1.

Implement models.py exactly as CONTRACT.md specifies: OtpChallenge, AuthSession, TwoFactorDevice,
RecoveryCode, VerifiedContact, LoginAttempt, TrustedDevice. Every user-referencing field is
settings.AUTH_USER_MODEL, never a concrete import — this app has no resolution.py because it never
defines the user model itself, so there's only ONE indirection to get right here, not two like
django-dynamic-user's Profile/Setting. Meta.indexes exactly as CONTRACT.md item 1 lists them.

Fields that hold a secret (OtpChallenge.code_hash/link_token_hash, RecoveryCode.code_hash,
TwoFactorDevice.secret_encrypted, TrustedDevice.token_hash, AuthSession.current_jti) are declared
as plain CharField/TextField at the model layer — hashing/encryption happens in services.py
(Phase 5), never as a custom field descriptor that hides what's actually being stored. Say so in a
comment on each such field, naming which service function is responsible for ever writing to it.

Then makemigrations, and verify 0001_initial uses
migrations.swappable_dependency(settings.AUTH_USER_MODEL) for every FK.

Then admin.py: ModelAdmin for AuthSession (list_display incl. user, ip_address, created_at,
revoked_at; an admin action to revoke selected sessions calling TokenService.revoke_session, never
a raw queryset .update()), LoginAttempt (readonly, list_filter on success/method, search_fields on
identifier — this is the one model where a plaintext searchable field is correct, per §0 item 4),
TwoFactorDevice (list_display excluding secret_encrypted entirely — never render it, not even
truncated), RecoveryCode (list_display excluding code_hash), VerifiedContact, TrustedDevice.
select_related/prefetch_related on every get_queryset. Do NOT touch JAZZMIN_SETTINGS — note
suggested icons for the README instead.

Create tests/backend/settings.py per APP-DESIGN.md §7.1 — Postgres, jwt_multiauth in
INSTALLED_APPS, AUTH_USER_MODEL left at Django's own default django.contrib.auth.User. Also create
a SECOND settings module, tests/backend/settings_dynamic_user.py, importing everything from
settings.py but pointing AUTH_USER_MODEL at a tiny test-only user model under
tests/backend/phone_user_app/ that adds a unique, nullable `phone` field (mirroring the shape a
django-dynamic-user host would actually have) and setting
JWT_MULTIAUTH["ALLOWED_AUTH_METHODS"] += ["phone_otp"], USER_FIELDS.PHONE_FIELD = "phone" — this is
what proves the field-resolution machinery in checks.py and later phases' OTP code actually works
against a real non-default user model, not just the one every fresh Django project ships with.

Run `uv run pytest --create-db` against BOTH settings modules to prove migrations apply from zero.
Paste both outputs.
```

**Verify:** both settings modules' migrations apply against real Postgres from zero;
`swappable_dependency` present on every FK; `manage.py check` under `settings_dynamic_user` passes
cleanly (phone_otp is enabled and the phone field genuinely resolves).

**Review for:** any concrete `User` import anywhere, including inside `admin.py`; missing indexes;
`secret_encrypted`/`code_hash`/`token_hash` ever rendered in an admin `list_display` or
`readonly_fields` in a way that would print the actual value.

### Phase 3 — Token issuance, rotation, and reuse detection

The load-bearing phase — get this wrong and every other phase built on top of it is wrong too.

```
Phase 3: tokens.py + TokenService's session-rotation half. docs/APP-DESIGN.md §6, this app's
docs/CONTRACT.md items 3 and 4 (TokenService only).

tokens.py — pure PyJWT wrapper, no database access, no Django ORM import beyond what's needed for
type hints:
- issue(claims: dict, *, typ: str, ttl_seconds: int) -> str — sets iat/nbf/exp/jti (a fresh
  secrets-generated jti per token, always, even for a short-lived pending-2FA token) and typ
  itself as a claim, so an access token can never be replayed where a refresh or pending-2FA token
  is expected, and vice versa. Algorithm and signing key come from conf (HS256 default;
  RS256-ready via a separate verifying key setting, but don't build RS256-specific test
  infrastructure this phase if the default path is HS256 — just don't hardcode HS256 in a way that
  makes the setting a lie).
- decode(token: str, *, expected_typ: str) -> dict — verifies signature, exp/nbf, AND typ, raising
  one clearly-named exception per failure mode (expired vs. bad signature vs. wrong typ) so
  services.py can map each to the right error detail without re-parsing the exception message.

services.py's TokenService, built on tokens.py plus AuthSession:
- issue_token_pair(user, *, request_meta, remember_me=False) -> TokenPair: creates a NEW
  AuthSession row (current_jti = fresh jti, expires_at from REMEMBER_ME_TTL_SECONDS if remember_me
  else the session-less default), issues an access token (sub=user_id, sid=session_id) and a
  refresh token (sub=user_id, sid=session_id, jti=the session's current_jti). Fires
  user_logged_in with the real session_id.
- rotate_refresh(raw_refresh_token, *, request_meta) -> TokenPair: decodes as typ="refresh",
  looks up the AuthSession by sid. Three outcomes, and the tests in this phase must cover exactly
  these three, not just the happy path: (1) jti matches current_jti and session not revoked/expired
  -> rotate (new jti, rotation_count+1, last_used_at=now, issue a fresh pair, same session_id
  throughout its life); (2) jti does NOT match current_jti (a superseded token being replayed) ->
  REVOKE THE ENTIRE SESSION immediately, fire refresh_reuse_detected, raise — this is theft
  detection, not a retry-me error, and the rotation MUST have already happened for outcome (1) to
  even make jti mismatch possible, so write the reuse test by rotating once, then replaying the
  now-stale original token; (3) session revoked or expired -> reject, no signal beyond the
  ordinary auth-failure path.
- revoke_session(session_id, *, reason) -> None; revoke_all_sessions(user, *,
  except_session_id=None, reason) -> int (returns count revoked; each fires session_revoked).
- verify_access_token(raw_token) -> claims dict (typ="access" only).
- issue_pending_2fa_token(user, *, primary_method, request_meta) -> str (typ="pending_2fa", short
  TTL from TWO_FACTOR.PENDING_TOKEN_TTL_SECONDS, carries primary_method as a claim so
  TwoFactorService can enforce the different-channel rule without a second database round trip);
  verify_pending_2fa_token(token) -> claims (typ="pending_2fa" only).

Hard constraints: no hardcoded TTL/algorithm literal anywhere outside conf.get_setting() calls; the
reuse-detection path is unconditional — there is no settings flag that turns it off.

Tests: happy-path issue + rotate; the three rotate_refresh outcomes above, explicitly, with the
reuse case actually replaying a stale token after a real rotation (not a fabricated stale jti);
revoke_session and revoke_all_sessions actually prevent a subsequent rotate_refresh; a token with
the wrong typ is rejected by decode() even with a valid signature; freezegun-based expiry tests for
access, refresh, and pending_2fa tokens independently. Run pytest against BOTH settings modules
(this phase's logic doesn't touch the user model's extra fields, but running both from here forward
is the standing rule — confirm it's still green, don't skip it because "nothing here differs").
```

**Verify:** `uv run pytest` green against both settings modules; the reuse-detection test genuinely
revokes the whole session (a subsequent legitimate-looking rotate on that session_id also fails,
proving the WHOLE session died, not just the one bad token).

**Review for:** any place `jti` comparison uses `==` on a Python string outside a
`hmac.compare_digest`-guarded path in `otp.py`'s cousin functions (JWT `jti` values aren't secrets
compared for auth on their own — the DB unique constraint is doing the real work here — but the
*next* phase's OTP code hashes must never regress to `==`, so start the grep habit now); the
different-channel enforcement claim (`primary_method`) actually being carried on the pending token
rather than re-derived unsafely later.

### Phase 4 — The OTP engine

```
Phase 4: otp.py — code/link-token generation, hashing, and the decoy-response mechanism.
docs/APP-DESIGN.md §6, this app's docs/CONTRACT.md item 2, and this guide's §0 item 5
(enumeration resistance) — read that again before writing generate_code().

otp.py, pure functions, no database access:
- generate_code(*, length: int, alphabet: str, exclude_ambiguous: bool, case_sensitive: bool) ->
  str, using secrets.choice over a character set built from the alphabet keyword ("numeric" ->
  "0123456789", "alpha" -> ascii letters per case_sensitive, "alphanumeric" -> both, anything else
  treated as a literal custom character set). exclude_ambiguous strips {0, O, 1, I, l, o} from
  whatever set results, THEN validates the remaining set isn't empty (raise ImproperlyConfigured
  naming the exact setting combination if a host's custom alphabet + exclude_ambiguous leaves
  nothing to choose from — fail at first use, not with an infinite loop or a biased fallback).
- generate_link_token() -> str, a high-entropy secrets.token_urlsafe(32) independent of the code's
  own alphabet — a magic link's security must never depend on how short a host configured its
  numeric code to be.
- hash_secret(value: str, *, pepper: str) -> str — HMAC-SHA256(key=pepper, msg=value.encode()),
  hexdigest. Every OTP code hash, link-token hash, recovery-code hash, and trusted-device-token
  hash in this app goes through this ONE function — no second hashing scheme anywhere.
- verify_secret(value: str, expected_hash: str, *, pepper: str) -> bool — recomputes via
  hash_secret and compares with hmac.compare_digest, never ==.

services.py's OtpService, built on otp.py + OtpChallenge + conf.get_otp_setting:
- request(identifier, *, channel, purpose) -> OtpRequestResult(challenge_id, expires_at,
  resend_available_at). Resolves identifier -> user via USER_FIELDS (email/phone/username
  depending on channel and PasswordService's own identifier rules from Phase 6). If the user
  resolves: honor SINGLE_ACTIVE_CHALLENGE (invalidate any prior unconsumed challenge for the same
  user+purpose+channel), create the row, fire the matching *_otp_requested signal with the
  PLAINTEXT code. If the user does NOT resolve: perform hash_secret on a throwaway value anyway (so
  the CPU cost is comparable), generate a fresh uuid4 as a decoy challenge_id, and return an
  IDENTICAL OtpRequestResult shape — no database row, no signal fired, nothing sent. Write the test
  that proves this by mocking both the DB insert and the signal and asserting NEITHER happens on
  the decoy path, while the return value is indistinguishable in shape from the real path.
- verify(challenge_id, *, code=None, link_token=None) -> OtpVerifyResult(user, purpose): looks up
  by challenge_id (a decoy challenge_id simply won't be found — same NotFound-shaped failure as a
  real-but-expired one, don't leak the distinction). Enforces expires_at, attempts < max_attempts
  (incrementing attempts on every failed compare, locking the challenge out after max_attempts
  regardless of whether the LAST attempt would have been correct), consumed_at is None. Uses
  verify_secret for the actual compare. On success: consumed_at = now, fire otp_verified.
- resend(challenge_id) -> OtpRequestResult: enforces RESEND_COOLDOWN_SECONDS and MAX_RESENDS,
  reuses the same challenge_id and destination but a freshly generated code/hash and expires_at.

Tests, run against BOTH settings modules: a real request/verify round trip per channel
(email/phone — phone only exercised under settings_dynamic_user, since the default settings module
has no phone field at all, which is itself a test that ALLOWED_AUTH_METHODS never including
"phone_otp" under default settings means the endpoint correctly 4xxs rather than 500ing). A decoy
request test per the above. attempts lockout test (max_attempts reached rejects even a
subsequently-correct code). resend cooldown and max-resends tests. A purpose-override test proving
password_reset's TTL/length differ from login's on the same channel when configured to. A test
proving generate_code with exclude_ambiguous=True and a tiny custom alphabet that would go empty
raises ImproperlyConfigured rather than looping or crashing. Run pytest, paste coverage.
```

**Verify:** the decoy-path test passes and genuinely asserts zero DB writes and zero signal
dispatch; the attempts-lockout test passes even when attempt #`max_attempts+1` would have been the
correct code.

**Review for:** any `==` comparison on a code/hash/token anywhere in this phase's diff (grep for it
explicitly, don't just trust the docstring); the decoy path's response timing/shape — read it next
to the real path's response builder side by side, not from memory; `SINGLE_ACTIVE_CHALLENGE`
actually invalidating the prior challenge server-side (not just letting two valid codes coexist).

### Phase 5 — Remaining services, signals, lockout, tasks

```
Phase 5: business logic. docs/APP-DESIGN.md §6, this app's docs/CONTRACT.md items 3, 4, 8.

Implement:
- signals.py — every signal from CONTRACT.md item 3, each with a comment documenting its exact
  payload above it, matching CONTRACT.md character for character.
- PasswordService: authenticate(identifier, password) -> user | None — resolves identifier against
  USER_FIELDS.IDENTIFIER_FIELDS in order (default ["username", "email"]), and on ANY failure to
  resolve OR a resolved-but-wrong password, performs Django's own
  django.contrib.auth.hashers.check_password against a fixed dummy hash before returning None —
  this is what makes the unknown-identifier and wrong-password paths take the same time; write the
  test that this dummy-hash call actually happens on the no-such-user path, not just on the
  wrong-password path (a common way to half-implement this rule and still leak via timing).
  change_password(user, old_password, new_password) -> None, validates old_password first, runs
  Django's AUTH_PASSWORD_VALIDATORS, fires password_changed, and — this is a hard requirement —
  calls TokenService.revoke_all_sessions(user, reason="password_changed") so a password change
  actually invalidates every other logged-in session. request_reset(identifier) -> None: always
  returns (never raises for an unknown identifier), delegates to OtpService.request(...,
  purpose="password_reset") and discards its result — the view layer (Phase 6) is what turns this
  into an unconditional 200. confirm_reset(challenge_id, *, code=None, link_token=None,
  new_password) -> None: calls OtpService.verify(purpose must be password_reset or reject), then
  sets the new password and revokes all sessions same as change_password.
- LockoutService: record_attempt(identifier, *, ip, success, reason=None) -> None, writing a
  LoginAttempt row every time (success or not) and, on failure, incrementing an
  appkit.cache-backed counter keyed by LOCKOUT.LOCK_SCOPE ("identifier"|"ip"|"identifier_and_ip" —
  implement all three, don't just pick one and hardcode it) within LOCKOUT.WINDOW_SECONDS.
  is_locked(identifier, *, ip) -> LockStatus(locked: bool, until: datetime | None) — checked BEFORE
  PasswordService.authenticate/OtpService.verify are ever called, so a locked-out caller never even
  reaches the dummy-hash path (state explicitly why this ordering doesn't reintroduce a timing
  side-channel: locked vs. not-locked is not a secret about a SPECIFIC identifier's validity the
  way "which password is right" is — it's fine for this one check to be fast). Reaching
  MAX_ATTEMPTS fires account_locked. unlock(identifier) -> None (admin-only caller, Phase 8) resets
  the counter early.
- VerificationService: request_contact_verification(user, *, field) -> OtpRequestResult
  (delegates to OtpService with purpose="verify_contact", destination = the user's CURRENT value
  for that field — always resolvable since the caller is already authenticated, so no decoy path
  applies here). confirm(challenge_id, *, code) -> None: OtpService.verify(purpose must be
  verify_contact), then get_or_create a VerifiedContact row for (user, field, destination) and fire
  contact_verified.
- tasks.py — jwt_multiauth.tasks.purge_expired_otp_challenges, .purge_expired_sessions (only rows
  well past expires_at — never touch a merely-revoked-but-not-yet-expired row, an admin/support
  agent may still want to see it), .purge_login_attempts (respecting
  LOGIN_ATTEMPT_RETENTION_DAYS), .purge_expired_trusted_devices. Behind the celery extra only, each
  continuing past a single row's failure rather than aborting the batch.
- management/commands/ — one thin command per task above, calling the same underlying function the
  task calls (never duplicating the query), for a host running no Celery worker.

Hard constraints, restated because this is the phase they matter most:
- No import of any other app package. appkit IS allowed.
- No import from a host (core, tools, config).
- Every service method emitting a signal emits EXACTLY the documented payload.
- Anything configurable comes from conf.get_setting()/get_otp_setting(), never a hardcoded literal.
- password_changed unconditionally revokes every other session — no settings flag disables this.

Tests: happy path + at least one failure path per service method; one test per signal asserting the
exact payload by connecting a receiver; the dummy-hash timing test described above; all three
LOCK_SCOPE modes tested independently (an "identifier" scope test proving many source IPs failing
the SAME username still locks it; an "ip" scope test proving one IP failing many DIFFERENT
usernames still locks that IP); a test proving change_password/confirm_reset both actually kill
other sessions, not just the current one. Run pytest against BOTH settings modules.
```

**Verify:** `uv run pytest` green against both settings modules; `uv run ruff check .` clean.

**Review for:** signal payloads matching `CONTRACT.md` exactly; any hardcoded literal that should
be a setting; the dummy-hash call actually reachable on the unknown-identifier path (step through
it, don't just read the function that claims to call it); `is_locked` being checked before, not
after, the real credential check on every call site that exists so far.

### Phase 6 — Password + OTP login APIs

```
Phase 6: the primary-authentication endpoints. docs/APP-DESIGN.md §4, this app's
docs/CONTRACT.md item 5's password/otp/discovery endpoints.

Implement serializers.py's login-related pieces, permissions.py, views_password.py, views_otp.py,
and the GET /methods/ discovery endpoint (wherever CONTRACT.md placed it), plus urls.py entries for
all of them.

Shared login-response shape used by BOTH views_password.py and views_otp.py's verify endpoint (a
single helper, not two copies): given a user, request_meta, and remember_me, call
TwoFactorService.eligible_methods(user, used_primary_channel=...). Empty list -> issue tokens
directly via TokenService.issue_token_pair, set the refresh cookie (name/attributes from
REFRESH_COOKIE settings) or include it in the body per REFRESH_COOKIE.TRANSPORT, return
{access, session_id}. Non-empty list -> issue a pending_2fa token via
TokenService.issue_pending_2fa_token, return {pending_token, eligible_methods} — HTTP 200, this is
not an error response, appkit's error envelope must never wrap it.

Every view, without exception:
- a namespaced throttle_scope: jwt_multiauth_login, jwt_multiauth_password_change,
  jwt_multiauth_password_reset_request, jwt_multiauth_password_reset_confirm,
  jwt_multiauth_otp_request, jwt_multiauth_otp_verify, jwt_multiauth_otp_resend,
  jwt_multiauth_methods.
- a complete @extend_schema: summary, description, request/response serializers,
  tags=["jwt-multiauth"].
- POST /login/: calls LockoutService.is_locked first (reject with a generic message before touching
  PasswordService at all if locked), then PasswordService.authenticate, then
  LockoutService.record_attempt either way, then the shared login-response helper above. 401 (not
  404/400) for both "no such user" and "wrong password" — same body shape, same status.
- POST /password/change/: IsAuthenticated. Old password required even for an authenticated caller
  (this is a re-auth step for a sensitive action, not a plain profile edit).
- POST /password/reset/request/: unauthenticated, ALWAYS 200, delegates to
  PasswordService.request_reset and discards any information about whether it did anything real.
- POST /password/reset/confirm/: unauthenticated, delegates to PasswordService.confirm_reset.
- POST /otp/request/: unauthenticated. Rejects (400, not 401/404) if the requested channel isn't
  actually in ALLOWED_AUTH_METHODS for a "login" purpose — a host that only enabled email_otp must
  not accept a phone_otp request even for a real phone-having user.
- POST /otp/verify/: unauthenticated. Accepts EITHER code OR link_token (never both required) —
  this is where the magic-link variant lives, not a separate view. Success runs through the SAME
  shared login-response helper as /login/.
- POST /otp/resend/: unauthenticated.
- GET /methods/: unauthenticated, no throttle beyond a generous default (it's read-only, static per
  deployment) — returns ALLOWED_AUTH_METHODS and TWO_FACTOR's policy/allowed-methods, nothing
  user-specific.

Serializers use explicit field lists throughout — never fields = "__all__". Never expose a
password, a code, a code_hash, a token_hash, or a secret_encrypted value in any response.

Tests, run against BOTH settings modules: /login/ unknown-identifier and wrong-password produce
identical status+body (assert body equality directly, not just "both are 401"); a rough timing
assertion for the dummy-hash path (document the tolerance chosen and why — this is inherently a
noisy assertion, don't set it so tight CI flakes); a locked-out account's /login/ never reaches
PasswordService.authenticate at all (mock it and assert zero calls); /otp/request/ for an unknown
identifier returns 200 with the same shape as a real one, and zero signal dispatch (reuse Phase 4's
test helper); /otp/verify/ accepts a link_token when EMIT_LINK_TOKEN is on and rejects one when
it's off; a full login -> eligible 2FA methods -> (Phase 7 will complete this handshake, so here
just assert the pending_token/eligible_methods shape, not a full round trip) test under a
TWO_FACTOR-enabled settings override. One test per throttle scope. phone_otp specific tests run
ONLY under settings_dynamic_user; assert /otp/request/ with channel="phone" 400s under default
settings (phone_otp isn't in that module's ALLOWED_AUTH_METHODS). Run pytest and paste coverage.

Then generate the schema: DJANGO_SETTINGS_MODULE=tests.backend.settings uv run python manage.py
spectacular --file schema.yml --fail-on-warn, and commit schema.yml.
```

**Verify:** coverage over 90%; the identical-response test for unknown-vs-wrong-password passes on
a byte-for-byte body comparison, not just a status-code comparison; `--fail-on-warn` clean.

**Review for:** any response distinguishing "no such user" from "wrong password" in status, body,
or an easily-measurable timing gap; a 2FA-pending response accidentally wrapped in appkit's error
envelope; `/otp/request/` honoring a channel not present in `ALLOWED_AUTH_METHODS`.

### Phase 7 — Two-factor authentication

The phase where the different-channel rule either holds or doesn't.

```
Phase 7: 2FA. docs/APP-DESIGN.md §4, this app's docs/CONTRACT.md item 5's 2fa endpoints and item 4's
TwoFactorService, and this guide's §1 "design facts" on the different-channel rule and the
pending-token handshake.

Finish TwoFactorService:
- eligible_methods(user, *, used_primary_channel) -> list[str]: start from
  TWO_FACTOR.ALLOWED_METHODS, intersect with the user's actually-enrolled methods (a confirmed
  TwoFactorDevice for "totp"; a VerifiedContact for the user's email/phone for "email_otp"/
  "phone_otp" respectively — being enrolled in email_otp as a 2FA method literally just means the
  email is verified, no separate enrollment record); "recovery_code" is eligible whenever the user
  has at least one unused RecoveryCode AND at least one other method is also eligible (recovery
  codes alone must never be the ONLY offered second factor, since that would make them a second
  password rather than a true second factor — state this as a deliberate rule). THEN, if
  TWO_FACTOR.REQUIRE_DIFFERENT_CHANNEL, remove used_primary_channel from the result (password's
  "channel" for this rule's purposes is a channel of its own, distinct from email/phone, so 2FA via
  email/phone is fully eligible after a password login). Return the remaining list; empty means the
  caller-side login MUST fail with a two_factor_unavailable failure, never proceed.
- enroll_totp(user) -> TotpEnrollment(secret, otpauth_uri): generates a fresh secret (pyotp's own
  random_base32()), encrypts it with appkit.crypto.Cipher before ever touching the database, stores
  the TwoFactorDevice row with confirmed_at=None (an unconfirmed enrollment is not yet eligible —
  see eligible_methods above, which only counts confirmed_at is not None). Returns the PLAINTEXT
  secret and an otpauth:// URI (pyotp.totp.TOTP(secret).provisioning_uri(...)) — this is the one
  and only moment the plaintext secret is ever returned; it is never retrievable again afterward.
- confirm_totp(user, *, code) -> None: decrypts the pending device's secret, verifies via pyotp
  with the configured drift window, sets confirmed_at, fires two_factor_enabled. A confirm attempt
  against an already-confirmed device, or with no pending enrollment at all, is rejected.
- disable(user, *, method) -> None: requires the CALLER to already be authenticated with a fresh
  session (view layer, below, additionally requires re-entering the password OR a valid current
  2FA code as defense-in-depth for this specific action — decide and document which, consistently).
  Fires two_factor_disabled.
- admin_force_disable(user) -> None: no re-auth requirement (the caller is a superuser acting on
  someone else's account, not re-authenticating their own) — but the view layer (Phase 8) gates
  this to an actual superuser regardless of ADMIN_REQUIRES_SUPERUSER.
- generate_recovery_codes(user) -> list[str]: invalidates any prior unused codes, generates
  TWO_FACTOR.RECOVERY_CODE_COUNT fresh codes via secrets, stores only their hashes, returns the
  PLAINTEXT list once — never retrievable again, same rule as the TOTP secret.
- verify_second_factor(pending_token, *, method, code=None, link_token=None, trust_device=False) ->
  TokenPair: verifies the pending token (typ="pending_2fa"), re-derives eligible_methods for that
  same user/primary_method and REJECTS if the requested method isn't in that set (never trust a
  client-supplied method blindly — this is the actual enforcement point for the different-channel
  rule, not eligible_methods alone, since eligible_methods is also just advisory information handed
  to a client). Verifies per-method: "totp" via pyotp against the decrypted device secret with
  replay guard (reject a step number <= last_used_step, update it on success); "email_otp"/
  "phone_otp" via OtpService.verify(purpose="two_factor"); "recovery_code" via hash lookup +
  mark used_at, constant-time compare across ALL unused codes (never short-circuit on the first
  match check in a way that leaks which position matched via timing — iterate every candidate).
  On success: if trust_device, issue a TrustedDevice row and its cookie; call
  TokenService.issue_token_pair (the REAL tokens, finally); fire otp_verified only for the
  OTP-based methods (not totp/recovery_code, which have no OtpChallenge involved).

views_twofactor.py: POST /2fa/verify/ (unauthenticated except for the pending token itself — this
is intentionally reachable pre-full-login, since that's the whole point), GET /2fa/status/ (auth),
POST /2fa/totp/enroll/ (auth), POST /2fa/totp/confirm/ (auth), POST /2fa/disable/ (auth, re-auth
required per above), POST /2fa/recovery-codes/regenerate/ (auth, re-auth required). Throttle scopes
jwt_multiauth_2fa_verify, _2fa_status, _2fa_totp_enroll, _2fa_totp_confirm, _2fa_disable,
_2fa_recovery_regenerate. Also: check TrustedDevice's cookie BEFORE offering 2FA at login (Phase
6's shared login-response helper needs a small addition here — if a valid, unrevoked, unexpired
TrustedDevice cookie for this user is present, skip straight to issuing real tokens; wire this in
this phase, not by reopening Phase 6's file structure from scratch).

Tests, against BOTH settings modules, under a TWO_FACTOR-enabled settings override: full round
trip per method (totp enroll -> confirm -> login -> 2fa/verify with a real pyotp-generated code);
the different-channel rejection — a user who logged in via email_otp, whose ONLY enrolled 2FA
method is also email_otp, gets two_factor_unavailable rather than being offered email_otp again;
verify_second_factor rejecting a client-supplied method not in the server's own recomputed eligible
set, even if the client lies about which method it's presenting a code for; TOTP replay rejection
(same code twice); recovery-code single-use (same code twice fails the second time); trusted-device
skip actually skipping 2FA on a subsequent login and NOT skipping it once revoked/expired; the
"recovery_code alone can't be the only offered method" rule. Run pytest, paste coverage.

Regenerate schema.yml now that this surface exists; commit it.
```

**Verify:** the different-channel rejection test passes; the server-side re-validation of
`method` against `eligible_methods` inside `verify_second_factor` genuinely rejects a mismatched
client claim — try temporarily removing that check and confirm the test fails, don't just trust it
was written correctly.

**Review for:** any path issuing real tokens without going through `verify_second_factor`'s
re-derivation of eligible methods; the TOTP secret ever appearing in a response after the initial
enrollment call; `disable`/`recovery-codes/regenerate` reachable without the re-auth step.

### Phase 8 — Sessions, account verification, admin API

```
Phase 8: the remaining self-service surface plus the whole admin surface. docs/APP-DESIGN.md §5,
this app's docs/CONTRACT.md item 5's session/account/admin endpoints.

views_token.py: POST /token/refresh/ (reads the refresh cookie OR body per REFRESH_COOKIE.TRANSPORT,
calls TokenService.rotate_refresh, re-sets the cookie on success), POST /token/verify/ (auth
optional — this is meant to let another service validate a token it received, so accept the token
as a body param rather than requiring it be the caller's own Authorization header), POST /logout/
(auth, revokes the CURRENT session only, clears the cookie), POST /logout/all/ (auth, revokes every
session for the user). Throttle scopes jwt_multiauth_token_refresh, _token_verify, _logout,
_logout_all.

views_session.py: GET /sessions/ (auth, paginated via appkit.pagination.DefaultPagination, lists
the CALLER's own AuthSession rows only — never another user's, checked at the queryset level, not
just by permission class), DELETE /sessions/{id}/ (auth, IsObjectOwner-style ownership check before
revoking — a user must never be able to revoke a session by guessing another user's session id).
Throttle scopes jwt_multiauth_sessions_list, _sessions_revoke.

views_account.py: POST /account/verify-contact/request/ (auth, body: field), POST
/account/verify-contact/confirm/ (auth, body: challenge_id, code). Throttle scopes
jwt_multiauth_verify_contact_request, _verify_contact_confirm.

permissions.py adds: the admin gate resolving JWT_MULTIAUTH["ADMIN_REQUIRES_SUPERUSER"] — False
(default) uses appkit.permissions.IsAppAdmin as-is; True swaps in an is_superuser-equivalent check.
Build this as one callable/class every admin_views.py view imports, not a conditional repeated at
each view. Separately, and NEVER gated by that setting: an is_superuser-only check used
specifically by the force-disable-2FA admin route.

admin_views.py, every view using the admin gate above, a namespaced throttle_scope
(jwt_multiauth_admin_ prefixed), a complete @extend_schema tagged ["jwt-multiauth-admin"]:
- GET /admin/sessions/ (paginated, filterable by user via
  appkit.validation.validate_query_params + safe_filter_kwargs — never raw **request.GET into a
  filter() call).
- DELETE /admin/sessions/{id}/ (any user's session).
- GET /admin/login-attempts/ (paginated, filterable by identifier/ip/user/success).
- GET /admin/users/{id}/security/ (2fa status, active session count, current lock status — a
  read-only aggregate view, no model of its own).
- POST /admin/users/{id}/unlock/ (calls LockoutService.unlock).
- POST /admin/users/{id}/2fa/force-disable/ (is_superuser-only regardless of
  ADMIN_REQUIRES_SUPERUSER; calls TwoFactorService.admin_force_disable).

Tests, against both settings modules, and against BOTH ADMIN_REQUIRES_SUPERUSER=False and =True for
every admin view except force-disable-2fa (which is tested ONLY as superuser-required,
unconditionally): every self-service session/account view enforces ownership (a second user's
attempt to DELETE /sessions/{id}/ against the first user's session id 403s or 404s — pick one and
justify it, then test it); every admin view 403s a non-admin; force-disable-2fa 403s a plain staff
(non-superuser) admin even when ADMIN_REQUIRES_SUPERUSER=False. Run pytest, paste coverage.

Regenerate schema.yml now that every surface exists; commit it.
```

**Verify:** the session-ownership IDOR test exists and genuinely fails if the ownership check is
temporarily removed — try it; the force-disable-2FA superuser-only test passes independent of
`ADMIN_REQUIRES_SUPERUSER`'s value.

**Review for:** any admin filter built from raw `**request.GET`; a self-service session view
resolving its target from a URL id without also checking it belongs to `request.user`; the
force-disable-2FA route reachable by anything less than an actual superuser.

### Phase 9 — Channels `JWTAuthMiddlewareStack` (optional extra)

```
Phase 9: WebSocket auth middleware. docs/APP-DESIGN.md §6's "Realtime (optional fourth surface)"
section — read it in full, this app is the one it was written for.

middleware/jwt_auth.py, behind the channels extra (importing this module without channels
installed must raise an actionable ImportError, not a bare ModuleNotFoundError three frames deep
inside Channels' own code — guard the import at the top of the module):
- JWTAuthMiddlewareStack(inner) — a Channels middleware reading a token from the WebSocket
  handshake's query string (?token=...) since a browser cannot set an Authorization header on a
  socket handshake, per APP-DESIGN.md §6's own framing of this exact problem. Calls
  TokenService.verify_access_token, resolves the user via get_user_model(), sets scope["user"]
  (AnonymousUser on any failure — expired, malformed, wrong typ — never raise out of the
  middleware itself, since a raised exception here tends to surface as an opaque 500 at the ASGI
  layer rather than a clean close). Rejects (never accepts) a refresh or pending_2fa token
  presented where an access token is expected, using tokens.py's own typ check from Phase 3 — do
  not hand-roll a second decode path here.
- Documented, explicitly, as NOT a substitute for a consuming app's own per-consumer
  authorization check (scope["user"] being set proves identity, not that this particular user may
  open this particular socket) — that's still the consuming app's job, same as
  APP-DESIGN.md §6 states for the realtime pattern generally.

The host mounts this explicitly in config/asgi.py, same as APP-DESIGN.md §6 describes for any
websocket_urlpatterns composition — this app ships no consumer of its own, only the middleware.

Tests (skip cleanly, not error, when the channels extra isn't installed — use
pytest.importorskip("channels") at the top of the test module): a valid access token resolves the
correct user in scope; an expired/malformed/wrong-typ token resolves AnonymousUser, not an
exception; a refresh token presented as if it were an access token is rejected the same way.
Run pytest with --extra channels, then again without it to confirm the rest of the suite is
unaffected by the extra's absence.
```

**Verify:** the suite passes both with and without the `channels` extra installed; a malformed
token never raises out of the middleware.

**Review for:** any path that raises rather than falling back to `AnonymousUser`; the typ check
being re-implemented here instead of reused from `tokens.py`.

### Phase 10 — Frontend SDK: the secure token manager

```
Phase 10: the frontend half. docs/APP-DESIGN.md §12, this app's docs/CONTRACT.md item 7, and
appkit/docs/CONTRACT.md §16 + §J — re-read both before writing authHeaderSource; this is the
mechanism they were written to be consumed by.

Create in frontend/:
- package.json: name "@hjtdev/django-jwt-multiauth", react/@tanstack/react-query/@hjtdev/appkit as
  peerDependencies ONLY, openapi-typescript as devDependency, generate:types script
  ("openapi-typescript ../backend/schema.yml -o src/schema.d.ts"), exports map with just ".",
  files: ["dist"], version matching backend/pyproject.toml.
- Run npm run generate:types -> src/schema.d.ts. Never hand-edit it.
- tsconfig.json (strict), tsconfig.build.json, vitest.config.ts, eslint config.
- src/types.ts — re-export narrowed aliases from schema.d.ts, re-export HttpClient from
  @hjtdev/appkit.
- src/authStore.ts — a MODULE SINGLETON (not a hook, not context — this must be readable from
  authHeaderSource, which runs outside React) holding the access token in a closure variable,
  never localStorage/sessionStorage, never a cookie the frontend sets itself (the refresh cookie is
  HttpOnly and backend-set only — the frontend never touches it directly). Public shape:
  getAccessToken(): string | null, setAccessToken(token: string | null, expiresAt: number | null):
  void, subscribe(listener: () => void): () => void (for a useSyncExternalStore-based hook),
  clear(): void. Cross-tab awareness via BroadcastChannel: broadcast EVENTS ("logged-out",
  "token-refreshed") never the token itself — every tab re-derives its own access token from the
  shared HttpOnly refresh cookie by calling refresh, it never receives another tab's token over the
  channel. Export a useAuthState() hook wrapping subscribe() via useSyncExternalStore, for a host UI
  that wants to reactively show logged-in/out state.
- src/authHeaderSource.ts — a stable, module-scope HeaderSource (matching appkit's own
  HeaderSource type exactly) for a host to drop into
  ApiClientProvider({ headerSources: [authHeaderSource, ...] }). Reads authStore's current token;
  if it's missing or inside the configured skew window of expiring, calls the refresh manager
  BEFORE returning headers (§16's "a source doing a synchronous refresh-if-expired check before
  returning" is the literal shape this implements) — with single-flight deduplication (a module-
  level in-flight promise) so N concurrent requests during a refresh trigger exactly one network
  call, not N. Returns {} (no Authorization header) rather than throwing when there is genuinely no
  session — per §16 rule 4, a header source must fail LOUDLY on a real bug, but "not logged in" is
  not a bug, so distinguish the two explicitly in the implementation and say so in a comment.
- src/withAuthRetry.ts — an HttpClient DECORATOR: withAuthRetry(client: HttpClient): HttpClient,
  wrapping every method so a 401 response triggers exactly one refresh attempt and one retry of the
  original call; a second 401 (refresh itself failed, or the retry also 401s) propagates the error
  and calls authStore.clear() + broadcasts "logged-out". This is the concrete satisfaction of
  appkit CONTRACT §J's assignment of retry-on-401 to "the host's concrete client" — ship it here so
  a host wraps its own apiClient with it once, rather than inventing this from scratch.
- src/api/config.ts: TWO config hooks — useJwtMultiauthConfig = () =>
  useApiClient("jwt_multiauth", "/api/v1/auth"); useJwtMultiauthAdminConfig = () =>
  useApiClient("jwt_multiauth_admin", "/api/v1/admin/auth") — neither exported from index.ts.
- src/api/manager.ts — TWO managers (JwtMultiauthManager, JwtMultiauthAdminManager) covering every
  endpoint from CONTRACT.md item 5, instance-based, constructor takes client + basePath. Neither
  exported from index.ts. login()/otpVerify() on the manager return the raw
  {access,...}|{pending_token,...} union — it's authStore's caller (the hook, next) that decides
  what to do with each shape, not the manager.
- src/hooks/ — one hook per hook listed in CONTRACT.md item 7. useLogin/useOtpVerify specifically:
  on a token-bearing success, call authStore.setAccessToken(...) as a side effect before resolving
  — this is the ONE place outside authStore/authHeaderSource/withAuthRetry that ever touches the
  token directly. useLogout/useLogoutAll call authStore.clear() + broadcast "logged-out" alongside
  the actual API call. Export jwtMultiauthKeys/jwtMultiauthAdminKeys factories, two separate roots.
- src/index.ts — hooks, both key factories, this app's own types, AND (the deliberate, documented
  exception to "never export the manager/config hook") authStore's useAuthState, authHeaderSource,
  and withAuthRetry — these three are host wiring a host cannot construct itself, unlike the
  managers, which stay internal. Say so in a comment at the top of the relevant export block so a
  future session doesn't "fix" this into full symmetry with every other app's index.ts.

Then tests/frontend with Vitest + MSW: success AND error path per hook, onUnhandledRequest:
"error", retry: false. A dedicated authHeaderSource test proving single-flight dedup (fire 5
concurrent calls while a token is expired, assert exactly one refresh network call). A dedicated
withAuthRetry test proving exactly one retry, never an infinite loop, on a persistently-401ing
mock. A test proving authStore never writes to localStorage/sessionStorage (spy on both globally
and assert zero calls across the whole suite, not just this file). A test proving every
mutation hook that changes auth/security state (useLogout, useLogoutAll, useDisableTwoFactor,
useAdminForceDisableTwoFactor, useAdminRevokeSession, etc.) never fires on mount.

Run npx tsc --noEmit, npm run lint, npm run test, npm run build. Paste all four.
```

**Verify:** all four pass; the localStorage/sessionStorage-never-touched test passes suite-wide;
the single-flight dedup test genuinely shows one network call for five concurrent callers; both
basePath keys are used somewhere in the hooks, not just declared.

**Review for:** `react`/`@tanstack/react-query`/`@hjtdev/appkit` in `dependencies` instead of
`peerDependencies`; either manager or either config hook leaking through `index.ts`; the access
token appearing in any string passed to `localStorage`, `sessionStorage`, a cookie the frontend
sets, or a `BroadcastChannel` message; `withAuthRetry` looping more than once on a persistent 401.

### Phase 11 — Playground (two hosts)

```
Phase 11: the playground — TWO minimal Django+Next hosts, not one, both under playground/.
docs/APP-DESIGN.md §11.2.

playground/default/ — django.contrib.auth's own default User, only "password" in
ALLOWED_AUTH_METHODS (the zero-configuration case a host gets with no extra wiring at all):
- backend/ — minimal Django project, jwt_multiauth in INSTALLED_APPS, pyproject.toml with
  [tool.uv.sources] path-editable to ../../../backend.
- frontend/ — minimal Next app, ApiClientProvider wired with authHeaderSource in headerSources and
  the apiClient wrapped in withAuthRetry, pages exercising login, logout, logout-all, password
  change, password reset, and session listing/revocation.

playground/dynamic_user/ — a host shaped like a real django-dynamic-user installation: a `core`
app defining a User with a real phone field, AUTH_USER_MODEL pointed at it,
JWT_MULTIAUTH["ALLOWED_AUTH_METHODS"] = ["password", "phone_otp", "email_otp"],
USER_FIELDS.PHONE_FIELD/EMAIL_FIELD set, TWO_FACTOR.ENABLED = True with "totp" and "email_otp"
allowed. A dummy signal receiver in this host's own core/signals.py logging (never actually
sending) phone_otp_requested/email_otp_requested payloads to the console, standing in for a real
SMS/email provider — annotate clearly that this is a stand-in, per INTEGRATION-GUIDE.md's own
convention for demonstrating the signal-wiring pattern:
- frontend/ — same pages as playground/default, PLUS phone-OTP login, TOTP enrollment (render the
  otpauth:// URI as a QR code using any lightweight client-side QR library — confirming this app's
  own claim that it ships zero QR/image dependency itself), and the full 2FA verify handshake.

playground/docker-compose.yml — Postgres, Redis (celery extra path), BOTH host stacks on distinct
ports. Document in this file's own header comment why one compose file covers both hosts (or why
two files ended up cleaner) — your call, but state it.

Bring both up and exercise every hook through the UI on both, and report on what only a live round
trip shows:
- does a real browser round trip actually set/read the HttpOnly refresh cookie correctly under
  CORS + credentials: "include" (this needs the host wiring from BASE-DESIGN.md §3's "Auth
  integration" section applied for real, not assumed)
- does authHeaderSource's proactive refresh actually keep a session alive across the access
  token's TTL without a visible logout, on both hosts
- does withAuthRetry actually recover a request that raced an access-token expiry
- does the phone-OTP flow work end to end on the dynamic_user host, with the console-logged
  signal payload standing in for real delivery
- does TOTP enrollment -> QR scan (use a real authenticator app, not just the backend's own pyotp
  round trip) -> confirm -> subsequent login -> 2FA verify actually work with a real device
- does the different-channel rule visibly reject an ineligible method in the UI, not just in a
  unit test
- does a password change on one tab actually log out every other open session/tab (BroadcastChannel
  behavior, live) — this is the one thing a headless test genuinely cannot prove
- does the admin surface's session list/revoke and login-attempt log show real data from both hosts

Report any discrepancy and which half — or which host — is actually wrong.
```

**Verify:** a real authenticator app (not just `pyotp` in a test) completes a TOTP login on the
`dynamic_user` host; the cross-tab logout-on-password-change behavior is confirmed live in two
actual browser tabs, not simulated.

### Phase 12 — README (the config block)

```
Phase 12: README.md. docs/APP-DESIGN.md §8 is the required structure — every section.

Fill it from what was actually built (code is the truth, not CONTRACT.md — report any
disagreement rather than papering over it). Include: installation (both halves) · compatibility ·
the JWT_MULTIAUTH settings block with every nested key and its default · the ALLOWED_AUTH_METHODS
and TWO_FACTOR policy explained with a worked example of the different-channel rule · the ONE
conditionally-required .env key (JWT_MULTIAUTH_ENCRYPTION_KEY, with the exact condition that makes
it required) and the two optional ones · URL mounting for BOTH urls.py and urls_admin.py ·
migrations · the FULL signals table with exact payloads (note explicitly that the two *_otp_requested
signals carry a plaintext code, and what a host's receiver is expected to do and not do with it) ·
services table with exact signatures · a worked "wiring an SMS/email provider" example lifted
directly from playground/dynamic_user/backend/core/signals.py · test helpers note (factory-boy in
the host's test group) · recommended periodic schedule for all four tasks · suggested Jazzmin
icons · frontend install and usage for BOTH basePath keys · a dedicated "Frontend security model"
section spelling out authStore/authHeaderSource/withAuthRetry's contract, EXPLICITLY stating (per
appkit CONTRACT §J) that token refresh/retry-on-401 lives here, in this app's own SDK, and never in
appkit · the BASE-DESIGN.md §3 "Auth integration" host-action checklist (CORS_ALLOW_CREDENTIALS,
CSRF_TRUSTED_ORIGINS, credentials: "include") reproduced here as a copy-pasteable checklist, since
this is the first app in the ecosystem for which it's actually load-bearing · the
REST_FRAMEWORK["NUM_PROXIES"] / APPKIT["TRUSTED_PROXY_COUNT"] agreement note for anyone enabling
IP-based lockout.

The settings/URL blocks must be copy-pasteable into a host with zero edits — verify by copying
them into BOTH playground hosts and confirming each still boots.

Then list every place README, CONTRACT.md, and the code disagree.
```

**Verify:** copying the README's blocks into fresh configs for both playground hosts, each still
boots; a host applying ONLY this README's "Auth integration" checklist (no other knowledge) gets a
working cross-origin cookie flow.

### Phase 13 — CI, changelog, first release

```
Phase 13: CI and release.

1. Confirm django-jwt-multiauth (PyPI) and @hjtdev/django-jwt-multiauth (npm) are still free — this
   guide verified both at the time it was written; re-check before tagging, since time has passed.
2. README sync: backend/pyproject.toml readme = "README.md". Copy the finished README.md into
   backend/README.md and frontend/README.md verbatim. Add [project.urls] and package.json
   homepage/bugs pointing at github.com/HjtDev/django-jwt-multiauth.
3. .github/workflows/ci.yml — the caller from docs/APP-DESIGN.md §10.2, package-name:
   jwt_multiauth, coverage-threshold: 90, publish-npm: true, plus the publish-pypi job verbatim.
4. CHANGELOG.md — Keep a Changelog format, 1.0.0 entry covering everything built in Phases 0-12.
5. Verify version lockstep: backend/pyproject.toml, frontend/package.json, CHANGELOG.md all at
   1.0.0.
6. Walk docs/APP-DESIGN.md §9's security checklist item by item, with evidence, into this app's own
   docs/SECURITY-CHECKLIST.md (mirror django-dynamic-user's own file for the evidence format — a
   file:line, a test name plus real command output, never a citation of an earlier phase's memory
   from this session). Give particular attention to, each with a FRESH re-run of its test, not a
   citation of an earlier phase's result: the enumeration-resistance rule (login, otp/request,
   password/reset/request all re-tested here); every stored-secret field proven hashed/encrypted by
   an actual row inspection, not by reading the model definition; the reuse-detection guard
   (rotate, replay the stale token, confirm the whole session died); the different-channel 2FA rule;
   the force-disable-2FA superuser-only guard.
7. Walk §12's frontend security checklist the same way — particular attention to the
   localStorage/sessionStorage-never-touched assertion and every destructive mutation hook never
   firing on mount.
8. Register both trusted publishers before the first tag, per §10.2's steps 2-4.

Then give the exact commands to tag and push v1.0.0.
```

**Verify:** CI green on a PR; after the tag push, both registry pages show a real, non-empty
description — check directly, not from green CI alone.

### Phase 14 — Install it into a real host, twice

```
Phase 14: real-world verification. In a fresh clone of base-scaffold, install django-jwt-multiauth
at v1.0.0 following docs/INTEGRATION-GUIDE.md §2 — all steps, using only README.md for
configuration values, twice: once against the scaffold's own default django.contrib.auth user with
ALLOWED_AUTH_METHODS = ["password"] only, once after installing django-dynamic-user first and
pointing this app's ALLOWED_AUTH_METHODS/USER_FIELDS at its User model with phone_otp and email_otp
both enabled. Don't use anything you know from building either package.

Specifically confirm, on both runs: JWT_MULTIAUTH added correctly, jwt_multiauth in INSTALLED_APPS,
both urls.py and urls_admin.py mounted, the ONE conditionally-required .env key's condition is
accurately documented (confirm manage.py check actually fails with a clear message if you enable
totp 2FA and forget it), the BASE-DESIGN.md §3 Auth integration checklist as reproduced in this
app's own README is sufficient on its own to get a working cross-origin cookie login from the
scaffold's own frontend, the Jazzmin sidebar entries appear without further JAZZMIN_SETTINGS edits,
and — on the second run only — a phone-OTP login round-trips through real HTTP against
django-dynamic-user's actual phone field with zero package-level code changes to either app.

Report every step that didn't work as documented, every value the README omitted, and every place
you had to guess. Then fix the README.
```

Finally: add the app to the registry (`BASE-DESIGN.md` §11.3 / `ecosystem-docs/APPS.md`).

---

## 3. Prompt patterns for this app

The generic guide's boundary/host-perspective/version-impact questions all apply unchanged
(`CLAUDE-CODE-GUIDE-APP.md` §3) — run them at the end of Phases 3, 7, and 10. Four more, specific to
an app whose entire job is safely authenticating people while holding their credentials:

> "List every place in this package that stores, hashes, or compares a secret — an OTP code, a
> recovery code, a TOTP seed, a refresh token's `jti`, a trusted-device token. For each, confirm:
> hashed/encrypted at rest (never plaintext), generated via `secrets` (never `random`), compared
> via a constant-time function (never `==`). If any one fails any of the three, that's not a style
> issue — fix it before continuing."

> "Pick one identifier-taking endpoint (`/login/`, `/otp/request/`, `/password/reset/request/`).
> Walk through the unknown-identifier path and the known-identifier-wrong-credential path side by
> side. Confirm the status code, the response body, and the approximate timing are indistinguishable.
> If they're not, that endpoint leaks account existence — fix it before continuing."

> "Pick one code path that issues real access/refresh tokens. Trace every condition that has to be
> true for that code path to run when `TWO_FACTOR.ENABLED` is `True` and the user has at least one
> eligible second factor. If you can find any way to reach it WITHOUT `verify_second_factor` having
> succeeded, that's a fail-open bug in the app's single most important guarantee — fix it before
> continuing."

> "List every place this package reads `settings.AUTH_USER_MODEL` or calls `get_user_model()`.
> Confirm none of them assumes a field beyond what `checks.py` actually validates for the
> currently-enabled methods. Then imagine a host running the bare `django.contrib.auth.User` with
> only `password` enabled — walk through what would break, and where."

## 4. Failure modes specific to this app

| Symptom | Cause | Guard |
|---|---|---|
| A stolen refresh token silently keeps working after the legitimate user refreshes | Rotation implemented without reuse detection — a superseded `jti` is accepted instead of triggering a full session revoke | Phase 3's reuse test replays a real stale token post-rotation, not a fabricated one |
| An attacker can tell which usernames exist by timing `/login/` | The dummy-hash call only runs on the wrong-password path, not the no-such-user path | Phase 5's/Phase 6's explicit no-such-user timing test |
| A password change doesn't actually revoke a stolen session on another device | `change_password`/`confirm_reset` update the password but never call `revoke_all_sessions` | Phase 5's session-kill test on both password-change paths |
| 2FA can be bypassed by claiming a method the server never offered | `verify_second_factor` trusts the client's `method` param instead of re-deriving `eligible_methods` itself | Phase 7's server-side re-validation test, checked by temporarily removing the guard |
| A user's only 2FA method is the same channel they just logged in with, and login degrades to single-factor anyway | `REQUIRE_DIFFERENT_CHANNEL` computed but not actually enforced as a hard failure | Phase 7's different-channel rejection test |
| Rotating `SECRET_KEY` (a routine incident-response action) locks every user out of their authenticator app | TOTP secret encryption derived from `SECRET_KEY` instead of an independent `JWT_MULTIAUTH_ENCRYPTION_KEY` | `CLAUDE.md` rule 4 and `checks.py`'s explicit requirement that this key is never `SECRET_KEY`-derived |
| An OTP request for a nonexistent user 404s (or otherwise looks different from a real request) | The decoy path was never implemented, or was implemented with a visibly different response shape/timing | Phase 4's decoy-shape and zero-side-effect tests |
| An admin who is staff-but-not-superuser can strip another user's 2FA | The force-disable-2FA route uses the general `ADMIN_REQUIRES_SUPERUSER`-gated check instead of an unconditional superuser check | Phase 8's superuser-only test, run independent of that setting's value |
| A host's WebSocket consumer treats an expired/garbage token as an exception instead of an anonymous connection | `JWTAuthMiddlewareStack` re-raises instead of falling back to `AnonymousUser` | Phase 9's malformed-token test |
| The access token ends up in `localStorage` after all | A hook or the manager writes it somewhere other than `authStore`'s in-memory closure, or a dependency's default behavior does it silently | Phase 10's suite-wide `localStorage`/`sessionStorage` spy assertion |
| Five simultaneous requests during a token refresh trigger five refresh calls | `authHeaderSource` missing single-flight deduplication | Phase 10's concurrent-callers test |

## 5. Done means

Everything in `CLAUDE-CODE-GUIDE-APP.md` §7, plus:

- [ ] Every stored secret (OTP code, recovery code, TOTP seed, trusted-device token) is proven
      hashed/encrypted at rest by an actual database-row inspection in a test, not by reading the
      model definition.
- [ ] A test proves refresh-token reuse revokes the entire session, not just the replayed token.
- [ ] A test proves the unknown-identifier and wrong-credential paths are indistinguishable in
      status, body, and approximate timing, for every identifier-taking endpoint.
- [ ] A test proves a password change/reset revokes every other session.
- [ ] A test proves `verify_second_factor` rejects a client-claimed method the server didn't
      actually offer, tried against a temporarily-removed guard.
- [ ] A test proves the different-channel 2FA rule causes a hard login failure rather than a
      silent downgrade when no eligible second factor remains.
- [ ] A test proves the force-disable-2FA admin route is superuser-only independent of
      `ADMIN_REQUIRES_SUPERUSER`.
- [ ] The full test suite passes against **both** `tests.backend.settings` and
      `tests.backend.settings_dynamic_user`, in every phase from 2 onward.
- [ ] A suite-wide test proves the frontend never writes to `localStorage`/`sessionStorage`.
- [ ] `authHeaderSource`'s single-flight refresh deduplication and `withAuthRetry`'s
      exactly-one-retry behavior are both proven, not assumed.
- [ ] Playground Phase 11 proves a phone-OTP login and a real-authenticator-app TOTP login both
      round-trip over real HTTP with zero package-level code changes.
- [ ] Both frontend basePath keys (`jwt_multiauth`, `jwt_multiauth_admin`) documented and
      installed in Phase 14's real-host check.
- [ ] The README's "Auth integration" checklist, copied verbatim from `BASE-DESIGN.md` §3, is
      sufficient on its own (Phase 14) to get a working cross-origin cookie login with no other
      knowledge.
