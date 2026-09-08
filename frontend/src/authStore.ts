"use client";

import { useSyncExternalStore } from "react";
import { readTokenExpiry } from "./jwt.js";

// A MODULE SINGLETON — not a hook, not context. Deliberately: authHeaderSource.ts (client.ts's
// import of this module) runs outside React entirely, invoked by appkit's decorated HttpClient
// before every request, so there is no component tree to hang a context on. The access token
// lives in these closure variables — never `localStorage`/`sessionStorage`, never a cookie this
// package sets itself (the refresh cookie is HttpOnly and backend-set only; this app never reads
// or writes it directly). Public shape is exactly four functions plus `useAuthState`
// (docs/CONTRACT.md §7's "token-manager trio" contract) — everything else in this file is
// internal wiring for refresh.ts/authHeaderSource.ts, never re-exported from index.ts.

let accessToken: string | null = null;
let expiresAt: number | null = null;
const listeners = new Set<() => void>();

type AuthStoreEvent = "logged-out" | "token-refreshed";
const CHANNEL_NAME = "jwt_multiauth_auth";

// `typeof BroadcastChannel === "undefined"` guards SSR (Next.js server render, where no
// BroadcastChannel global exists) — this module must be importable there even though it's a
// no-op until the client mounts.
const channel: BroadcastChannel | null =
  typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel(CHANNEL_NAME);

if (channel) {
  // Cross-tab awareness broadcasts EVENTS, never the token itself — every tab re-derives its own
  // access token by calling refresh against the shared HttpOnly cookie (docs/CONTRACT.md §7).
  //
  // "logged-out": another tab logged out or hit an unrecoverable 401 — clear locally too.
  // clearLocal() (not the public clear()) so a receiving tab never re-broadcasts what it just
  // received; each tab's own clear() call is the only thing that ever posts to the channel.
  //
  // "token-refreshed": another tab rotated its own token. This tab's own token is unaffected —
  // BroadcastChannel deliberately never carries the token itself, so there is nothing for this
  // tab to adopt. Notifying subscribers only (not re-deriving) is the correct behaviour: a UI
  // wired to useAuthState may want to react to "some tab is authenticated" without every tab
  // stampeding the refresh endpoint the moment one of them rotates.
  channel.onmessage = (event: MessageEvent<{ type: AuthStoreEvent }>) => {
    if (event.data?.type === "logged-out") {
      clearLocal();
    } else if (event.data?.type === "token-refreshed") {
      notify();
    }
  };
}

function notify(): void {
  for (const listener of listeners) listener();
}

/** Clears local state and notifies subscribers, without touching the BroadcastChannel.
 * Idempotent — a second call while already cleared is a silent no-op, so a "logged-out" message
 * arriving after this tab already cleared itself notifies nothing further. */
function clearLocal(): void {
  if (accessToken === null && expiresAt === null) return;
  accessToken = null;
  expiresAt = null;
  notify();
}

function broadcast(type: AuthStoreEvent): void {
  channel?.postMessage({ type });
}

/** Returns the current access token, or `null` if there is no session. */
export function getAccessToken(): string | null {
  return accessToken;
}

/**
 * Sets (or clears, via `token: null`) the current access token. Notifies subscribers and
 * broadcasts the corresponding cross-tab event — `"token-refreshed"` on a real token,
 * `"logged-out"` on `null` (equivalent to calling {@link clear}).
 *
 * `expiresAt` is milliseconds since epoch; pass `null` to have it derived automatically from the
 * token's own `exp` claim (`jwt.ts`'s `readTokenExpiry`) — no backend response actually carries
 * this value (docs/CONTRACT.md §11 item 17), so every real caller passes `null` here in practice.
 *
 * The only callers outside this trio are `useLogin`/`useOtpVerify`/`useVerifyTwoFactor`
 * (docs/CONTRACT.md §7) on their token-bearing branch, and refresh.ts's own success path.
 */
export function setAccessToken(token: string | null, expiresAt_: number | null): void {
  if (token === null) {
    clear();
    return;
  }
  accessToken = token;
  expiresAt = expiresAt_ ?? readTokenExpiry(token);
  notify();
  broadcast("token-refreshed");
}

/** Internal-only — never re-exported from index.ts. Read by authHeaderSource.ts to decide
 * whether the current token is missing or inside the configured skew window. */
export function peekExpiresAt(): number | null {
  return expiresAt;
}

/** Clears the session locally and broadcasts `"logged-out"` to every other open tab. A no-op
 * (no broadcast) if there was nothing to clear. */
export function clear(): void {
  const hadToken = accessToken !== null;
  clearLocal();
  if (hadToken) broadcast("logged-out");
}

/** For `useSyncExternalStore` — registers `listener`, returns the unsubscribe function. */
export function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/**
 * Reactive logged-in/out state for a host UI, wrapping {@link subscribe} via
 * `useSyncExternalStore`. Exported from index.ts (docs/CONTRACT.md §11 item 13 — the guide's
 * item 7 hook enumeration omits it, but Phase 10 mandates it).
 */
export function useAuthState(): { isAuthenticated: boolean } {
  const token = useSyncExternalStore(
    subscribe,
    getAccessToken,
    // getServerSnapshot — SSR never has a session (the access token lives only in this closure,
    // freshly initialised per request on the server), so the server-rendered snapshot is always
    // "logged out" and the client reconciles once it mounts and derives its own token.
    () => null,
  );
  return { isAuthenticated: token !== null };
}
