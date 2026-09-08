import type {
  AdminUserSecurityResponse,
  AuthMethodsResponse,
  AuthSession,
  LoginAttempt,
  LoginPendingTwoFactorResponse,
  LoginTokensResponse,
  LogoutAllResponse,
  OtpRequestResponse,
  PaginatedAuthSessionList,
  PaginatedLoginAttemptList,
  PaginatedTrustedDeviceList,
  RecoveryCodesResponse,
  TokenRefreshResponse,
  TokenVerifyResponse,
  TotpEnrollResponse,
  TrustedDevice,
  TwoFactorStatusResponse,
} from "../../frontend/src/types.js";

function base64UrlEncode(input: string): string {
  return Buffer.from(input, "utf-8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Builds a syntactically-real (unsigned) JWT so `jwt.ts`'s `readTokenExpiry` has something
 * genuine to decode in tests — never a real, verifiable token; this package never verifies a
 * token itself, only the backend does. */
export function makeFakeJwt(claimOverrides: Record<string, unknown> = {}): string {
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64UrlEncode(
    JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 900, sub: "1", ...claimOverrides }),
  );
  return `${header}.${payload}.fake-signature`;
}

/** A syntactically three-segment "JWT" whose payload segment decodes to non-JSON — exercises
 * `jwt.ts`'s `readTokenExpiry` catch path (a malformed/undecodable token degrades to `null`,
 * never a thrown error). */
export function makeUndecodableJwt(): string {
  return "aGVhZGVy.not-valid-json-once-decoded.fake-signature";
}

export function makeLoginTokensResponse(
  overrides: Partial<LoginTokensResponse> = {},
): LoginTokensResponse {
  return {
    access: makeFakeJwt(),
    session_id: "session-1",
    created: false,
    ...overrides,
  };
}

export function makeLoginPendingTwoFactorResponse(
  overrides: Partial<LoginPendingTwoFactorResponse> = {},
): LoginPendingTwoFactorResponse {
  return {
    pending_token: "pending-token-1",
    eligible_methods: ["totp"],
    ...overrides,
  };
}

export function makeOtpRequestResponse(
  overrides: Partial<OtpRequestResponse> = {},
): OtpRequestResponse {
  return {
    challenge_id: "challenge-1",
    expires_at: "2026-01-01T00:05:00Z",
    resend_available_at: "2026-01-01T00:00:30Z",
    ...overrides,
  };
}

export function makeAuthMethodsResponse(
  overrides: Partial<AuthMethodsResponse> = {},
): AuthMethodsResponse {
  return {
    allowed_auth_methods: ["password", "email_otp"],
    two_factor: { policy: "opt_in", allowed_methods: ["totp", "email_otp"] },
    ...overrides,
  };
}

export function makeTwoFactorStatusResponse(
  overrides: Partial<TwoFactorStatusResponse> = {},
): TwoFactorStatusResponse {
  return {
    policy: "opt_in",
    enrolled_methods: [],
    eligible_methods: ["totp", "email_otp"],
    ...overrides,
  };
}

export function makeTotpEnrollResponse(
  overrides: Partial<TotpEnrollResponse> = {},
): TotpEnrollResponse {
  return {
    secret: "JBSWY3DPEHPK3PXP",
    otpauth_uri: "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
    ...overrides,
  };
}

export function makeRecoveryCodesResponse(
  overrides: Partial<RecoveryCodesResponse> = {},
): RecoveryCodesResponse {
  return {
    codes: ["aaaa-bbbb", "cccc-dddd", "eeee-ffff"],
    ...overrides,
  };
}

export function makeTokenRefreshResponse(
  overrides: Partial<TokenRefreshResponse> = {},
): TokenRefreshResponse {
  return {
    access: makeFakeJwt(),
    session_id: "session-1",
    ...overrides,
  };
}

export function makeTokenVerifyResponse(
  overrides: Partial<TokenVerifyResponse> = {},
): TokenVerifyResponse {
  return {
    valid: true,
    claims: { sub: "1" },
    ...overrides,
  };
}

export function makeLogoutAllResponse(
  overrides: Partial<LogoutAllResponse> = {},
): LogoutAllResponse {
  return {
    revoked_count: 3,
    ...overrides,
  };
}

export function makeAuthSession(overrides: Partial<AuthSession> = {}): AuthSession {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    device_label: "Chrome on macOS",
    ip_address: "203.0.113.10",
    user_agent: "Mozilla/5.0",
    remember_me: false,
    rotation_count: 0,
    created_at: "2026-01-01T00:00:00Z",
    last_used_at: "2026-01-01T00:00:00Z",
    expires_at: "2026-01-15T00:00:00Z",
    revoked_at: null,
    revoked_reason: null,
    ...overrides,
  };
}

export function makePaginatedAuthSessionList(
  overrides: Partial<PaginatedAuthSessionList> = {},
): PaginatedAuthSessionList {
  return {
    count: 1,
    next: null,
    previous: null,
    results: [makeAuthSession()],
    ...overrides,
  };
}

export function makeTrustedDevice(overrides: Partial<TrustedDevice> = {}): TrustedDevice {
  return {
    id: 1,
    device_label: "Chrome on macOS",
    created_at: "2026-01-01T00:00:00Z",
    last_used_at: "2026-01-01T00:00:00Z",
    expires_at: "2026-02-01T00:00:00Z",
    revoked_at: null,
    ...overrides,
  };
}

export function makePaginatedTrustedDeviceList(
  overrides: Partial<PaginatedTrustedDeviceList> = {},
): PaginatedTrustedDeviceList {
  return {
    count: 1,
    next: null,
    previous: null,
    results: [makeTrustedDevice()],
    ...overrides,
  };
}

export function makeLoginAttempt(overrides: Partial<LoginAttempt> = {}): LoginAttempt {
  return {
    id: 1,
    user: 1,
    identifier: "alice@example.com",
    method: "password",
    ip_address: "203.0.113.10",
    user_agent: "Mozilla/5.0",
    success: true,
    failure_reason: null,
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

export function makePaginatedLoginAttemptList(
  overrides: Partial<PaginatedLoginAttemptList> = {},
): PaginatedLoginAttemptList {
  return {
    count: 1,
    next: null,
    previous: null,
    results: [makeLoginAttempt()],
    ...overrides,
  };
}

export function makeAdminUserSecurityResponse(
  overrides: Partial<AdminUserSecurityResponse> = {},
): AdminUserSecurityResponse {
  return {
    two_factor_status: makeTwoFactorStatusResponse(),
    active_session_count: 1,
    lock_status: { scope: "identifier_and_ip", locked: null, until: null },
    ...overrides,
  };
}
