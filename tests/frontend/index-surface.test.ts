import { describe, expect, it } from "vitest";
import * as mod from "../../frontend/src/index.js";

// Runtime bindings only — `export type { ... }` produces no property on the compiled module
// object, so this list is exactly the 39 real exports: 25 self-service hooks, 8 admin hooks,
// 2 key factories, and the 4 token-manager-trio exports (docs/CONTRACT.md §7's documented
// exception to "never export the manager/config hook").
const EXPECTED_EXPORTS = [
  // self-service hooks
  "useLogin",
  "useOtpRequest",
  "useOtpVerify",
  "useOtpResend",
  "usePasswordChange",
  "usePasswordResetRequest",
  "usePasswordResetConfirm",
  "useLogout",
  "useLogoutAll",
  "useSessions",
  "useRevokeSession",
  "useTrustedDevices",
  "useRevokeTrustedDevice",
  "useAuthMethods",
  "useTwoFactorStatus",
  "useEnrollTotp",
  "useConfirmTotp",
  "useDisableTwoFactor",
  "useRegenerateRecoveryCodes",
  "useRequestTwoFactorOtp",
  "useVerifyTwoFactor",
  "useRequestContactVerification",
  "useConfirmContactVerification",
  "useVerifyToken",
  "useRefreshToken",
  // admin hooks
  "useAdminSessions",
  "useAdminRevokeSession",
  "useAdminTrustedDevices",
  "useAdminRevokeTrustedDevice",
  "useAdminLoginAttempts",
  "useAdminUserSecurity",
  "useAdminUnlockUser",
  "useAdminForceDisableTwoFactor",
  // key factories
  "jwtMultiauthKeys",
  "jwtMultiauthAdminKeys",
  // token-manager trio + refresh wiring
  "useAuthState",
  "authHeaderSource",
  "withAuthRetry",
  "configureAuth",
].sort();

describe("index.ts public surface", () => {
  it("exports exactly the documented set — nothing more, nothing less", () => {
    expect(Object.keys(mod).sort()).toEqual(EXPECTED_EXPORTS);
  });

  it("never leaks either manager or either config hook", () => {
    expect("JwtMultiauthManager" in mod).toBe(false);
    expect("JwtMultiauthAdminManager" in mod).toBe(false);
    expect("useJwtMultiauthConfig" in mod).toBe(false);
    expect("useJwtMultiauthAdminConfig" in mod).toBe(false);
  });

  it("authHeaderSource is a stable, module-scope function reference", () => {
    expect(typeof mod.authHeaderSource).toBe("function");
  });
});
