// Hand-written, and the SDK's entire public type surface — re-exports narrowed aliases from
// schema.d.ts (generated, never hand-edited) plus everything the schema can't express. The
// manager and hooks import from here, never from ./schema.d.ts directly.
//
// Component names below (LoginResponse, AuthSession, TwoFactorStatusResponse, ...) come straight
// from the backend's drf-spectacular-generated schema.yml — pinned serializer names, not
// build_serializer()'s content-hashed ones, so they stay stable across a host's field/settings
// edits (docs/APP-DESIGN.md §12's "unstable component name" warning).

import type { components, operations } from "./schema.js";

// --- the shared login-response union ---------------------------------------------------------

/**
 * `POST /login/`, `POST /otp/verify/`, and (hand-typed below, the schema carries no response
 * body for it) `POST /2fa/verify/` all return this same discriminated union — the shared
 * `login_flow.login_response` helper on the backend (docs/CONTRACT.md §5, §11 item 24).
 *
 * Branch A (tokens issued) and branch B (2FA pending) share ZERO field names — discriminate on
 * `"access" in response` (branch A) vs `"pending_token" in response` (branch B), never on a
 * literal discriminant field, since none exists.
 */
export type LoginResponse = components["schemas"]["LoginResponse"];

/** Branch A of {@link LoginResponse} — tokens issued, no 2FA required (or 2FA just passed).
 * `refresh` is present only under `REFRESH_COOKIE["TRANSPORT"] === "body"` — this SDK is
 * cookie-transport-only (see README) and never reads this field. `created` is `true` only when
 * this call just auto-provisioned a new account (`POST /otp/verify/`'s one special case). */
export type LoginTokensResponse = components["schemas"]["LoginTokensResponse"];

/** Branch B of {@link LoginResponse} — a second factor is required before a real session issues. */
export type LoginPendingTwoFactorResponse = components["schemas"]["LoginPendingTwoFactorResponse"];

/** `POST /otp/verify/` response — identical union to {@link LoginResponse}, kept as its own alias
 * since the backend emits it under its own component name. */
export type OtpVerifyResponse = components["schemas"]["OtpVerifyResponse"];

/**
 * `POST /2fa/verify/` response — `docs/CONTRACT.md` §5's `{access, session_id}` plus the
 * `created` field the view's own `@extend_schema` documents (always `false` here; this app's
 * one auto-provisioning path is OTP login, not 2FA verification) and the optional `refresh`
 * every token-issuing endpoint can carry under body transport. Hand-typed because
 * `auth_2fa_verify_create`'s 200 in schema.yml carries prose only, no response schema
 * (docs/CONTRACT.md §11 item 25 adds this endpoint's body but the OpenApiResponse describing it
 * was never wired to a serializer) — same shape as {@link LoginTokensResponse} with a fixed
 * `created: false`, so this alias just borrows it rather than redeclaring the fields.
 */
export type TwoFactorVerifyResponse = LoginTokensResponse;

// --- request bodies ----------------------------------------------------------------------------

export type LoginInput = components["schemas"]["LoginRequestRequest"];
export type PasswordChangeInput = components["schemas"]["PasswordChangeRequest"];
export type PasswordResetRequestInput = components["schemas"]["PasswordResetRequestRequest"];
export type PasswordResetConfirmInput = components["schemas"]["PasswordResetConfirmRequest"];
export type OtpRequestInput = components["schemas"]["OtpRequestRequest"];
export type OtpVerifyInput = components["schemas"]["OtpVerifyRequest"];
export type OtpResendInput = components["schemas"]["OtpResendRequest"];
export type TotpConfirmInput = components["schemas"]["TotpConfirmRequest"];
export type TwoFactorDisableInput = components["schemas"]["TwoFactorDisableRequest"];
export type RecoveryCodesRegenerateInput = components["schemas"]["RecoveryCodesRegenerateRequest"];
export type TwoFactorOtpRequestInput = components["schemas"]["TwoFactorOtpRequestRequest"];
export type TwoFactorVerifyInput = components["schemas"]["TwoFactorVerifyRequest"];
export type TokenVerifyInput = components["schemas"]["TokenVerifyRequest"];
export type VerifyContactRequestInput = components["schemas"]["VerifyContactRequestRequest"];
export type VerifyContactConfirmInput = components["schemas"]["VerifyContactConfirmRequest"];

/** `channel`/`field` share the same closed set — `"email" | "phone"`. */
export type OtpChannel = components["schemas"]["OtpChannelEnum"];

/** The closed set of 2FA methods a user can enroll/verify/disable with. */
export type TwoFactorMethod = components["schemas"]["TwoFactorMethodEnum"];

/** The narrower closed set `POST /2fa/otp/request/` accepts — OTP-based second factors only. */
export type TwoFactorOtpMethod = components["schemas"]["TwoFactorOtpRequestMethodEnum"];

// --- response bodies ----------------------------------------------------------------------------

export type OtpRequestResponse = components["schemas"]["OtpRequestResponse"];
export type AuthMethodsResponse = components["schemas"]["AuthMethodsResponse"];
export type TwoFactorStatusResponse = components["schemas"]["TwoFactorStatusResponse"];
export type TotpEnrollResponse = components["schemas"]["TotpEnrollResponse"];
export type RecoveryCodesResponse = components["schemas"]["RecoveryCodesResponse"];
export type TokenRefreshResponse = components["schemas"]["TokenRefreshResponse"];
export type TokenVerifyResponse = components["schemas"]["TokenVerifyResponse"];
export type LogoutAllResponse = components["schemas"]["LogoutAllResponse"];
export type AuthSession = components["schemas"]["AuthSession"];
export type PaginatedAuthSessionList = components["schemas"]["PaginatedAuthSessionList"];
export type TrustedDevice = components["schemas"]["TrustedDevice"];
export type PaginatedTrustedDeviceList = components["schemas"]["PaginatedTrustedDeviceList"];
export type LoginAttempt = components["schemas"]["LoginAttempt"];
export type PaginatedLoginAttemptList = components["schemas"]["PaginatedLoginAttemptList"];
export type LockStatusResponse = components["schemas"]["LockStatusResponse"];
export type AdminUserSecurityResponse = components["schemas"]["AdminUserSecurityResponse"];

/**
 * `POST /2fa/otp/request/` response — `docs/CONTRACT.md` §11 item 25: same shape as
 * {@link OtpRequestResponse}, but `auth_2fa_otp_request_create`'s 200 in schema.yml carries only
 * prose (no response schema was wired), so this alias borrows the sibling shape instead of
 * redeclaring the three fields.
 */
export type TwoFactorOtpRequestResponse = OtpRequestResponse;

// --- query params --------------------------------------------------------------------------

/** `GET /sessions/`, `GET /trusted-devices/` — `page`/`page_size` only, schema-declared. */
export type SessionsParams = NonNullable<operations["auth_sessions_list"]["parameters"]["query"]>;
export type TrustedDevicesParams = NonNullable<
  operations["auth_trusted_devices_list"]["parameters"]["query"]
>;

/**
 * `GET /admin/sessions/`'s query params — `page`/`page_size` are schema-declared;
 * `user` is applied inside `AdminSessionListView.get_queryset()` and never reaches
 * drf-spectacular (docs/CONTRACT.md §5's own admin table names it, the schema doesn't), so it's
 * added by hand here rather than being part of the generated `operations[...]` type.
 */
export type AdminSessionsParams = NonNullable<
  operations["admin_auth_sessions_list"]["parameters"]["query"]
> & { user?: number };

/** Same hand-extension as {@link AdminSessionsParams}, for `GET /admin/trusted-devices/`. */
export type AdminTrustedDevicesParams = NonNullable<
  operations["admin_auth_trusted_devices_list"]["parameters"]["query"]
> & { user?: number };

/**
 * `GET /admin/login-attempts/`'s query params — `page`/`page_size` are schema-declared;
 * `identifier`/`ip_address`/`user`/`success` are applied inside
 * `AdminLoginAttemptListView.get_queryset()` and never reach drf-spectacular, same reasoning as
 * {@link AdminSessionsParams}.
 */
export type AdminLoginAttemptsParams = NonNullable<
  operations["admin_auth_login_attempts_list"]["parameters"]["query"]
> & {
  identifier?: string;
  ip_address?: string;
  user?: number;
  success?: boolean;
};

// appkit owns the HttpClient interface; re-exported for convenience, never redeclared.
export type { HttpClient } from "@hjtdev/appkit";
