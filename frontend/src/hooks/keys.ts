import type {
  AdminLoginAttemptsParams,
  AdminSessionsParams,
  AdminTrustedDevicesParams,
  SessionsParams,
  TrustedDevicesParams,
} from "../types.js";

/**
 * Exported from src/index.ts — a host sometimes needs to invalidate this app's cache from its
 * own composed code (docs/CONTRACT.md §7).
 *
 * `sessions(params)`/`trustedDevices(params)` deliberately drop the `params` slot from the key
 * entirely when called with no argument, rather than emitting `[...all, "sessions", undefined]`.
 * React Query's `invalidateQueries` matches by prefix with partial deep equality — a length-N key
 * ending in a literal `undefined` would compare that `undefined` against every filtered query's
 * own `{page, page_size}` object and never match, silently defeating every
 * `invalidateQueries({ queryKey: jwtMultiauthKeys.sessions() })`-style call a mutation hook makes
 * (see tests/frontend/invalidation.test.tsx for the regression this guards against — the same
 * convention ../django-dynamic-user/frontend/src/hooks/keys.ts uses, for the same reason).
 */
export const jwtMultiauthKeys = {
  all: ["jwt_multiauth"] as const,
  sessions: (params?: SessionsParams) =>
    params === undefined
      ? ([...jwtMultiauthKeys.all, "sessions"] as const)
      : ([...jwtMultiauthKeys.all, "sessions", params] as const),
  trustedDevices: (params?: TrustedDevicesParams) =>
    params === undefined
      ? ([...jwtMultiauthKeys.all, "trusted-devices"] as const)
      : ([...jwtMultiauthKeys.all, "trusted-devices", params] as const),
  methods: () => [...jwtMultiauthKeys.all, "methods"] as const,
  twoFactorStatus: () => [...jwtMultiauthKeys.all, "two-factor-status"] as const,
};

/**
 * Under a separate root (`"jwt_multiauth_admin"`, not `"jwt_multiauth"`) from
 * {@link jwtMultiauthKeys} on purpose — an admin mutation invalidates only this factory's keys,
 * never the self-service surface's; an admin revoking user 42's session has no reason to bust the
 * current operator's own self-service session list, and there is no reliable way to target "that
 * other user's session" from a mutation's own `onSuccess` anyway.
 */
export const jwtMultiauthAdminKeys = {
  all: ["jwt_multiauth_admin"] as const,
  sessions: (params?: AdminSessionsParams) =>
    params === undefined
      ? ([...jwtMultiauthAdminKeys.all, "sessions"] as const)
      : ([...jwtMultiauthAdminKeys.all, "sessions", params] as const),
  trustedDevices: (params?: AdminTrustedDevicesParams) =>
    params === undefined
      ? ([...jwtMultiauthAdminKeys.all, "trusted-devices"] as const)
      : ([...jwtMultiauthAdminKeys.all, "trusted-devices", params] as const),
  loginAttempts: (params?: AdminLoginAttemptsParams) =>
    params === undefined
      ? ([...jwtMultiauthAdminKeys.all, "login-attempts"] as const)
      : ([...jwtMultiauthAdminKeys.all, "login-attempts", params] as const),
  userSecurity: (userId?: number) =>
    userId === undefined
      ? ([...jwtMultiauthAdminKeys.all, "users", "security"] as const)
      : ([...jwtMultiauthAdminKeys.all, "users", userId, "security"] as const),
};
