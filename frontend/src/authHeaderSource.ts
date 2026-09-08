import type { HeaderSource } from "@hjtdev/appkit";
import { getAccessToken, peekExpiresAt } from "./authStore.js";
import { getAuthConfig, refreshAccessToken } from "./refresh.js";

function isExpiringSoon(expiresAt: number | null, skewSeconds: number): boolean {
  // No known expiry (a malformed token, or one whose `exp` claim couldn't be decoded) is treated
  // as "expiring" — the conservative default, since refreshing unnecessarily costs one extra
  // round trip while treating an actually-expired token as fresh would send a doomed request.
  if (expiresAt === null) return true;
  return Date.now() >= expiresAt - skewSeconds * 1000;
}

/**
 * A stable, module-scope `HeaderSource` (appkit's own type, verbatim — docs/CONTRACT.md §7) for
 * a host to drop into `ApiClientProvider({ headerSources: [authHeaderSource, ...] })`. Reads
 * authStore's current token; if it's missing or inside the configured skew window of expiring,
 * calls the refresh manager BEFORE returning headers (appkit CONTRACT §16 rule 5's "a source
 * doing a synchronous refresh-if-expired check before returning" is the literal shape this
 * implements) — refresh.ts's single-flight dedup means N concurrent requests during a refresh
 * trigger exactly one network call, not N.
 *
 * Returns `{}` (no `Authorization` header) when there is genuinely no session — refreshAccessToken
 * resolving `null` means the refresh endpoint itself said "no session," which is not a bug. A
 * REJECTED refresh (network failure, 5xx, misconfiguration) is NOT caught here — it propagates,
 * per appkit CONTRACT §16 rule 4: a header source must fail LOUDLY on a real bug. The two cases
 * are deliberately not conflated: one is "you're logged out," the other is "something is broken."
 *
 * Must stay a stable reference — appkit's `ApiClientProvider` memoises its decorated client on
 * `[client, headerSources]` (docs/CONTRACT.md §15); this being a `const` at module scope, not
 * something constructed per-render, is what keeps that memoisation intact.
 */
export const authHeaderSource: HeaderSource = async () => {
  let token = getAccessToken();

  if (token === null || isExpiringSoon(peekExpiresAt(), getAuthConfig().skewSeconds)) {
    token = await refreshAccessToken();
  }

  // A single Record<string, string>, built conditionally, rather than two differently-shaped
  // object literals returned from two branches — keeps the return type a plain HeadersInit
  // instead of a union TypeScript can't structurally match against HeadersInit's index signature.
  const headers: Record<string, string> = {};
  if (token !== null) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
};
