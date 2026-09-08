// The only file a host ever imports from — the "one entrypoint" rule. Both managers
// (JwtMultiauthManager/JwtMultiauthAdminManager) and both config hooks
// (useJwtMultiauthConfig/useJwtMultiauthAdminConfig) are never exported here, only hooks, both
// key factories, and types. A host mounts appkit's ApiClientProvider once and adds BOTH this
// app's basePath entries to its `basePaths` map: `jwt_multiauth` -> "/api/v1/auth" and
// `jwt_multiauth_admin` -> "/api/v1/admin/auth" (see README.md's "Usage" section).

// --- self-service hooks -------------------------------------------------------------------
export { useLogin } from "./hooks/useLogin.js";
export { useOtpRequest } from "./hooks/useOtpRequest.js";
export { useOtpVerify } from "./hooks/useOtpVerify.js";
export { useOtpResend } from "./hooks/useOtpResend.js";
export { usePasswordChange } from "./hooks/usePasswordChange.js";
export { usePasswordResetRequest } from "./hooks/usePasswordResetRequest.js";
export { usePasswordResetConfirm } from "./hooks/usePasswordResetConfirm.js";
export { useLogout } from "./hooks/useLogout.js";
export { useLogoutAll } from "./hooks/useLogoutAll.js";
export { useSessions } from "./hooks/useSessions.js";
export { useRevokeSession } from "./hooks/useRevokeSession.js";
export { useTrustedDevices } from "./hooks/useTrustedDevices.js";
export { useRevokeTrustedDevice } from "./hooks/useRevokeTrustedDevice.js";
export { useAuthMethods } from "./hooks/useAuthMethods.js";
export { useTwoFactorStatus } from "./hooks/useTwoFactorStatus.js";
export { useEnrollTotp } from "./hooks/useEnrollTotp.js";
export { useConfirmTotp } from "./hooks/useConfirmTotp.js";
export { useDisableTwoFactor } from "./hooks/useDisableTwoFactor.js";
export { useRegenerateRecoveryCodes } from "./hooks/useRegenerateRecoveryCodes.js";
export { useRequestTwoFactorOtp } from "./hooks/useRequestTwoFactorOtp.js";
export { useVerifyTwoFactor } from "./hooks/useVerifyTwoFactor.js";
export { useRequestContactVerification } from "./hooks/useRequestContactVerification.js";
export { useConfirmContactVerification } from "./hooks/useConfirmContactVerification.js";
export { useVerifyToken } from "./hooks/useVerifyToken.js";
export { useRefreshToken } from "./hooks/useRefreshToken.js";

// --- admin hooks ----------------------------------------------------------------------------
export { useAdminSessions } from "./hooks/useAdminSessions.js";
export { useAdminRevokeSession } from "./hooks/useAdminRevokeSession.js";
export { useAdminTrustedDevices } from "./hooks/useAdminTrustedDevices.js";
export { useAdminRevokeTrustedDevice } from "./hooks/useAdminRevokeTrustedDevice.js";
export { useAdminLoginAttempts } from "./hooks/useAdminLoginAttempts.js";
export { useAdminUserSecurity } from "./hooks/useAdminUserSecurity.js";
export { useAdminUnlockUser } from "./hooks/useAdminUnlockUser.js";
export { useAdminForceDisableTwoFactor } from "./hooks/useAdminForceDisableTwoFactor.js";

// --- key factories ----------------------------------------------------------------------------
export { jwtMultiauthKeys, jwtMultiauthAdminKeys } from "./hooks/keys.js";

// --- the token-manager trio (+ its refresh-wiring entry point) --------------------------------
// The DELIBERATE, DOCUMENTED exception to "never export the manager/config hook" above: these
// four are host wiring a host cannot construct itself (unlike the managers, which are pure
// internals a host never needs directly), so they're exported here even though nothing else in
// this file breaks that "only hooks/keys/types" pattern. Do NOT "fix" this into full symmetry
// with every other app's index.ts in this ecosystem — docs/CONTRACT.md §7 states this exception
// explicitly, and configureAuth exists because authHeaderSource/withAuthRetry run outside React
// and cannot read the host's chosen mount point off useApiClient the way a hook would.
export { useAuthState } from "./authStore.js";
export { authHeaderSource } from "./authHeaderSource.js";
export { withAuthRetry } from "./withAuthRetry.js";
export { configureAuth } from "./refresh.js";
export type { AuthConfig } from "./refresh.js";

// --- types ------------------------------------------------------------------------------------
export type {
  AdminLoginAttemptsParams,
  AdminSessionsParams,
  AdminTrustedDevicesParams,
  AdminUserSecurityResponse,
  AuthMethodsResponse,
  AuthSession,
  HttpClient,
  LockStatusResponse,
  LoginAttempt,
  LoginInput,
  LoginPendingTwoFactorResponse,
  LoginResponse,
  LoginTokensResponse,
  LogoutAllResponse,
  OtpChannel,
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
  TrustedDevice,
  TrustedDevicesParams,
  TwoFactorDisableInput,
  TwoFactorMethod,
  TwoFactorOtpMethod,
  TwoFactorOtpRequestInput,
  TwoFactorOtpRequestResponse,
  TwoFactorStatusResponse,
  TwoFactorVerifyInput,
  TwoFactorVerifyResponse,
  VerifyContactConfirmInput,
  VerifyContactRequestInput,
} from "./types.js";
