// Two instance-based managers — the ONLY place a raw HTTP call happens in this SDK. Neither is
// exported from src/index.ts; a host only ever reaches them indirectly, through a hook
// (docs/CONTRACT.md §7's "manager/hook two-layer split").

import type { HttpClient } from "@hjtdev/appkit";
import type {
  AdminLoginAttemptsParams,
  AdminSessionsParams,
  AdminTrustedDevicesParams,
  AdminUserSecurityResponse,
  AuthMethodsResponse,
  LoginInput,
  LoginResponse,
  LogoutAllResponse,
  OtpRequestInput,
  OtpRequestResponse,
  OtpResendInput,
  OtpVerifyInput,
  OtpVerifyResponse,
  PaginatedAuthSessionList,
  PaginatedLoginAttemptList,
  PaginatedTrustedDeviceList,
  PasswordChangeInput,
  PasswordResetConfirmInput,
  PasswordResetRequestInput,
  RecoveryCodesRegenerateInput,
  RecoveryCodesResponse,
  SessionsParams,
  TokenRefreshResponse,
  TokenVerifyInput,
  TokenVerifyResponse,
  TotpConfirmInput,
  TotpEnrollResponse,
  TrustedDevicesParams,
  TwoFactorDisableInput,
  TwoFactorOtpRequestInput,
  TwoFactorOtpRequestResponse,
  TwoFactorStatusResponse,
  TwoFactorVerifyInput,
  TwoFactorVerifyResponse,
  VerifyContactConfirmInput,
  VerifyContactRequestInput,
} from "../types.js";

/**
 * Builds a query string from a plain params object, skipping `undefined`/`null` values.
 * `HttpClient` (appkit) has no params channel of its own — `get`/`delete` take only a path and
 * `RequestInit` — so this is the one place a query string is assembled, via `URLSearchParams`
 * rather than raw template interpolation, per the frontend security checklist's "manager methods
 * never build a URL by concatenating unescaped user input" rule.
 */
function toQueryString(params: Record<string, unknown> | undefined): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : "";
}

/** Self-service surface — bound to the `jwt_multiauth` basePath (`/api/v1/auth` by default). */
export class JwtMultiauthManager {
  constructor(
    private readonly client: HttpClient,
    private readonly basePath: string,
  ) {}

  login(data: LoginInput): Promise<LoginResponse> {
    return this.client.post<LoginResponse>(`${this.basePath}/login/`, data);
  }

  passwordChange(data: PasswordChangeInput): Promise<void> {
    return this.client.post<void>(`${this.basePath}/password/change/`, data);
  }

  passwordResetRequest(data: PasswordResetRequestInput): Promise<void> {
    return this.client.post<void>(`${this.basePath}/password/reset/request/`, data);
  }

  passwordResetConfirm(data: PasswordResetConfirmInput): Promise<void> {
    return this.client.post<void>(`${this.basePath}/password/reset/confirm/`, data);
  }

  otpRequest(data: OtpRequestInput): Promise<OtpRequestResponse> {
    return this.client.post<OtpRequestResponse>(`${this.basePath}/otp/request/`, data);
  }

  otpVerify(data: OtpVerifyInput): Promise<OtpVerifyResponse> {
    return this.client.post<OtpVerifyResponse>(`${this.basePath}/otp/verify/`, data);
  }

  otpResend(data: OtpResendInput): Promise<OtpRequestResponse> {
    return this.client.post<OtpRequestResponse>(`${this.basePath}/otp/resend/`, data);
  }

  authMethods(): Promise<AuthMethodsResponse> {
    return this.client.get<AuthMethodsResponse>(`${this.basePath}/methods/`);
  }

  twoFactorStatus(): Promise<TwoFactorStatusResponse> {
    return this.client.get<TwoFactorStatusResponse>(`${this.basePath}/2fa/status/`);
  }

  /** `POST /2fa/totp/enroll/` ignores its request body entirely (schema.yml's
   * `TotpEnrollResponseRequest` is a phantom, generated only because the view's
   * `serializer_class` is its own response serializer) — this sends no body. */
  enrollTotp(): Promise<TotpEnrollResponse> {
    return this.client.post<TotpEnrollResponse>(`${this.basePath}/2fa/totp/enroll/`);
  }

  confirmTotp(data: TotpConfirmInput): Promise<void> {
    return this.client.post<void>(`${this.basePath}/2fa/totp/confirm/`, data);
  }

  disableTwoFactor(data: TwoFactorDisableInput): Promise<void> {
    return this.client.post<void>(`${this.basePath}/2fa/disable/`, data);
  }

  regenerateRecoveryCodes(data: RecoveryCodesRegenerateInput): Promise<RecoveryCodesResponse> {
    return this.client.post<RecoveryCodesResponse>(
      `${this.basePath}/2fa/recovery-codes/regenerate/`,
      data,
    );
  }

  /** `POST /2fa/otp/request/` — docs/CONTRACT.md §11 item 25, not in the frozen §5 table. Issues
   * the `challenge_id` `verifyTwoFactor` needs for the `email_otp`/`phone_otp` second-factor
   * methods. */
  requestTwoFactorOtp(data: TwoFactorOtpRequestInput): Promise<TwoFactorOtpRequestResponse> {
    return this.client.post<TwoFactorOtpRequestResponse>(`${this.basePath}/2fa/otp/request/`, data);
  }

  verifyTwoFactor(data: TwoFactorVerifyInput): Promise<TwoFactorVerifyResponse> {
    return this.client.post<TwoFactorVerifyResponse>(`${this.basePath}/2fa/verify/`, data);
  }

  /** `POST /token/refresh/` — cookie-transport only (see README): sends no body, relies on the
   * HttpOnly refresh cookie the browser attaches automatically. Exposed for completeness
   * (`useRefreshToken`); the trio's own refresh.ts calls the endpoint directly rather than
   * through this manager, since it must work outside any React tree / `ApiClientProvider`. */
  tokenRefresh(): Promise<TokenRefreshResponse> {
    return this.client.post<TokenRefreshResponse>(`${this.basePath}/token/refresh/`);
  }

  tokenVerify(data: TokenVerifyInput): Promise<TokenVerifyResponse> {
    return this.client.post<TokenVerifyResponse>(`${this.basePath}/token/verify/`, data);
  }

  logout(): Promise<void> {
    return this.client.post<void>(`${this.basePath}/logout/`);
  }

  /** `POST /logout/all/` ignores its request body entirely — same phantom-schema situation as
   * `enrollTotp` (`LogoutAllResponseRequest`). Sends no body. */
  logoutAll(): Promise<LogoutAllResponse> {
    return this.client.post<LogoutAllResponse>(`${this.basePath}/logout/all/`);
  }

  sessions(params?: SessionsParams): Promise<PaginatedAuthSessionList> {
    return this.client.get<PaginatedAuthSessionList>(
      `${this.basePath}/sessions/${toQueryString(params)}`,
    );
  }

  /** Session ids are UUID strings — do not confuse with `revokeTrustedDevice`'s numeric id. */
  revokeSession(id: string): Promise<void> {
    return this.client.delete<void>(`${this.basePath}/sessions/${id}/`);
  }

  trustedDevices(params?: TrustedDevicesParams): Promise<PaginatedTrustedDeviceList> {
    return this.client.get<PaginatedTrustedDeviceList>(
      `${this.basePath}/trusted-devices/${toQueryString(params)}`,
    );
  }

  /** Trusted-device ids are plain integers — do not confuse with `revokeSession`'s UUID id. */
  revokeTrustedDevice(id: number): Promise<void> {
    return this.client.delete<void>(`${this.basePath}/trusted-devices/${id}/`);
  }

  requestContactVerification(data: VerifyContactRequestInput): Promise<OtpRequestResponse> {
    return this.client.post<OtpRequestResponse>(
      `${this.basePath}/account/verify-contact/request/`,
      data,
    );
  }

  confirmContactVerification(data: VerifyContactConfirmInput): Promise<void> {
    return this.client.post<void>(`${this.basePath}/account/verify-contact/confirm/`, data);
  }
}

/**
 * Admin surface — bound to the `jwt_multiauth_admin` basePath (`/api/v1/admin/auth` by default).
 * Paths below collapse to the basePath root — `${basePath}/sessions/`, never
 * `${basePath}/admin/sessions/` (docs/CONTRACT.md §5's admin table already folds the `/admin/`
 * segment into the basePath itself; `urls_admin.py`'s own patterns carry no `admin/` prefix).
 */
export class JwtMultiauthAdminManager {
  constructor(
    private readonly client: HttpClient,
    private readonly basePath: string,
  ) {}

  /** `user` is applied server-side in `get_queryset()` and isn't schema-declared — see
   * {@link AdminSessionsParams}'s own doc comment in types.ts. */
  sessions(params?: AdminSessionsParams): Promise<PaginatedAuthSessionList> {
    return this.client.get<PaginatedAuthSessionList>(
      `${this.basePath}/sessions/${toQueryString(params)}`,
    );
  }

  revokeSession(id: string): Promise<void> {
    return this.client.delete<void>(`${this.basePath}/sessions/${id}/`);
  }

  trustedDevices(params?: AdminTrustedDevicesParams): Promise<PaginatedTrustedDeviceList> {
    return this.client.get<PaginatedTrustedDeviceList>(
      `${this.basePath}/trusted-devices/${toQueryString(params)}`,
    );
  }

  revokeTrustedDevice(id: number): Promise<void> {
    return this.client.delete<void>(`${this.basePath}/trusted-devices/${id}/`);
  }

  loginAttempts(params?: AdminLoginAttemptsParams): Promise<PaginatedLoginAttemptList> {
    return this.client.get<PaginatedLoginAttemptList>(
      `${this.basePath}/login-attempts/${toQueryString(params)}`,
    );
  }

  userSecurity(userId: number): Promise<AdminUserSecurityResponse> {
    return this.client.get<AdminUserSecurityResponse>(`${this.basePath}/users/${userId}/security/`);
  }

  unlockUser(userId: number): Promise<void> {
    return this.client.post<void>(`${this.basePath}/users/${userId}/unlock/`);
  }

  /** Always superuser-gated server-side, regardless of `ADMIN_REQUIRES_SUPERUSER`
   * (docs/CONTRACT.md §5) — this manager makes no attempt to pre-check that client-side. */
  forceDisableTwoFactor(userId: number): Promise<void> {
    return this.client.post<void>(`${this.basePath}/users/${userId}/2fa/force-disable/`);
  }
}
