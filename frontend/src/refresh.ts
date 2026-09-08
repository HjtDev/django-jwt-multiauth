// Internal — never re-exported from index.ts (configureAuth is the one piece of this module a
// host touches directly, re-exported from index.ts separately). Owns the actual
// `POST /token/refresh/` call and its single-flight deduplication; authStore.ts holds the
// resulting token, authHeaderSource.ts and withAuthRetry.ts are this module's two callers.
//
// Cookie transport only (docs/README's "Transport" section) — this SDK never reads or sends a
// refresh token itself. The request below carries no body; the browser attaches the HttpOnly
// refresh cookie automatically because `credentials` defaults to `"include"`.

import { clear, setAccessToken } from "./authStore.js";

export interface AuthConfig {
  /**
   * The mount-relative or absolute URL for `POST /token/refresh/`. Must match wherever the host
   * actually mounted this app's self-service surface — the default assumes the app's own
   * suggested basePath (`/api/v1/auth`), which a host that mounted elsewhere MUST override via
   * {@link configureAuth}. authHeaderSource.ts/withAuthRetry.ts run outside React and can't read
   * this off `useApiClient`'s `basePaths` map the way a hook would, which is why this exists as
   * an explicit config call rather than being inferred.
   */
  refreshUrl: string;
  /** Passed straight through to `fetch`'s `credentials` option — `"include"` by default, so the
   * HttpOnly refresh cookie actually reaches the request under a cross-origin API setup. */
  credentials: RequestCredentials;
  /** How many seconds before the access token's known/derived expiry authHeaderSource.ts starts
   * treating it as "expiring soon" and proactively refreshes rather than waiting for a 401. */
  skewSeconds: number;
  /** Injectable for tests; defaults to the global `fetch`. */
  fetch: typeof fetch;
}

const DEFAULT_CONFIG: AuthConfig = {
  refreshUrl: "/api/v1/auth/token/refresh/",
  credentials: "include",
  skewSeconds: 30,
  fetch: (...args: Parameters<typeof fetch>) => globalThis.fetch(...args),
};

let config: AuthConfig = { ...DEFAULT_CONFIG };

/**
 * Configures the refresh manager — a host calls this once, next to where it mounts
 * `ApiClientProvider`, whenever it mounted this app's self-service surface anywhere other than
 * the default `/api/v1/auth` (see README's "Usage" section). Any field omitted keeps its current
 * value; call with `{}` to reset nothing.
 */
export function configureAuth(overrides: Partial<AuthConfig>): void {
  config = { ...config, ...overrides };
}

/** Internal — read by authHeaderSource.ts for the skew check. */
export function getAuthConfig(): Readonly<AuthConfig> {
  return config;
}

let inFlightRefresh: Promise<string | null> | null = null;

interface TokenRefreshBody {
  access: string;
  session_id: string;
}

/**
 * Calls `POST /token/refresh/` and updates authStore on success. Single-flight: N concurrent
 * callers while a refresh is already in progress all resolve from the same underlying request —
 * exactly one network call reaches the wire, never N (docs/CONTRACT.md §7's authHeaderSource
 * requirement, and the same guarantee withAuthRetry.ts relies on for its own retry).
 *
 * Resolves `null` when there is genuinely no session (the refresh endpoint itself returned 401 —
 * missing/expired/revoked/reused cookie) — this is not a bug, and authStore.clear() +
 * "logged-out" already ran by the time this resolves. Any other failure (network error, a 5xx,
 * a misconfigured refreshUrl) REJECTS instead — the caller (authHeaderSource.ts, per appkit
 * CONTRACT §16 rule 4) must fail loudly on a real bug rather than silently degrading to "logged
 * out," which would make an outage indistinguishable from an expired session.
 */
export function refreshAccessToken(): Promise<string | null> {
  if (!inFlightRefresh) {
    inFlightRefresh = performRefresh().finally(() => {
      inFlightRefresh = null;
    });
  }
  return inFlightRefresh;
}

async function performRefresh(): Promise<string | null> {
  const response = await config.fetch(config.refreshUrl, {
    method: "POST",
    credentials: config.credentials,
    headers: { Accept: "application/json" },
  });

  if (response.status === 401) {
    clear();
    return null;
  }

  if (!response.ok) {
    throw new Error(`Token refresh failed with status ${response.status}`);
  }

  const body = (await response.json()) as TokenRefreshBody;
  // expiresAt: null — authStore derives it from the token's own `exp` claim (jwt.ts), since no
  // response field carries it (docs/CONTRACT.md §11 item 17).
  setAccessToken(body.access, null);
  return body.access;
}
