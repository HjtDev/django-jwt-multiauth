import { isApiError, type HttpClient } from "@hjtdev/appkit";
import { clear } from "./authStore.js";
import { refreshAccessToken } from "./refresh.js";

function isUnauthorized(error: unknown): boolean {
  if (isApiError(error)) return error.status === 401;
  // Structural fallback — a host's own HttpClient implementation isn't required to throw
  // appkit's ApiError specifically, only something error-shaped; any thrown value carrying a
  // numeric `status: 401` is treated the same way.
  return (
    typeof error === "object" &&
    error !== null &&
    "status" in error &&
    (error as { status: unknown }).status === 401
  );
}

/** Returns `init` with its `Authorization` header replaced by `token` — never a stale one. In
 * the real composition (`decorateClient(withAuthRetry(apiClient), [authHeaderSource])`, per
 * appkit CONTRACT §15), appkit merges `authHeaderSource`'s headers into `init` BEFORE calling
 * into this decorator, once, at the start of the request — so the `init` a retry would otherwise
 * reuse still carries whatever token was current before this 401 happened. Building the retry's
 * own `Authorization` from the token `refreshAccessToken()` just produced is what makes the
 * retry able to succeed at all, rather than deterministically repeating the same 401. */
function withFreshAuthorization(init: RequestInit | undefined, token: string): RequestInit {
  const headers = new Headers(init?.headers);
  headers.set("Authorization", `Bearer ${token}`);
  return { ...init, headers };
}

/**
 * `withAuthRetry(client)` — an `HttpClient` DECORATOR (docs/CONTRACT.md §7): a `401` triggers
 * exactly one refresh attempt and one retry of the original call. This is the concrete
 * satisfaction of appkit CONTRACT §J's explicit assignment of retry-on-401 to "the host's
 * concrete client" — appkit itself contains no such mechanism anywhere (§16 rule 6).
 *
 * The retry calls the RAW, undecorated `client` directly — never the returned wrapper — so an
 * infinite retry loop is structurally impossible rather than merely counter-guarded: there is no
 * code path by which this function can call itself.
 *
 * - If `refreshAccessToken()` resolves `null` (no session — refresh.ts already ran
 *   `authStore.clear()` and broadcast `"logged-out"` on its own 401), the retry is skipped
 *   entirely and the ORIGINAL error propagates.
 * - If `refreshAccessToken()` REJECTS (a real failure, not "no session"), that rejection
 *   propagates instead — it is not caught here, matching authHeaderSource.ts's own "fail loudly
 *   on a real bug" rule.
 * - If the retry itself also 401s, `authStore.clear()` runs (broadcasting `"logged-out"`) and the
 *   retry's error propagates. A non-401 retry error propagates as-is, with no `clear()` call —
 *   an unrelated failure (validation, a 500) is not evidence the session is dead.
 */
export function withAuthRetry(client: HttpClient): HttpClient {
  async function attempt<T>(
    call: (init?: RequestInit) => Promise<T>,
    init?: RequestInit,
  ): Promise<T> {
    try {
      return await call(init);
    } catch (error) {
      if (!isUnauthorized(error)) throw error;

      const token = await refreshAccessToken();
      if (token === null) {
        throw error;
      }

      try {
        return await call(withFreshAuthorization(init, token));
      } catch (retryError) {
        if (isUnauthorized(retryError)) {
          clear();
        }
        throw retryError;
      }
    }
  }

  return {
    get: <T>(path: string, init?: RequestInit) => attempt<T>((i) => client.get<T>(path, i), init),
    post: <T>(path: string, body?: unknown, init?: RequestInit) =>
      attempt<T>((i) => client.post<T>(path, body, i), init),
    put: <T>(path: string, body?: unknown, init?: RequestInit) =>
      attempt<T>((i) => client.put<T>(path, body, i), init),
    patch: <T>(path: string, body?: unknown, init?: RequestInit) =>
      attempt<T>((i) => client.patch<T>(path, body, i), init),
    delete: <T>(path: string, init?: RequestInit) =>
      attempt<T>((i) => client.delete<T>(path, i), init),
  };
}
