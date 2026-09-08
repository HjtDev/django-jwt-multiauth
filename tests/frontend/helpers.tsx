import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiClientProvider, apiErrorFromEnvelope } from "@hjtdev/appkit";
import type { HttpClient } from "@hjtdev/appkit";

/**
 * appkit ships no client implementation of its own (docs/CONTRACT.md §13) — this is a minimal,
 * test-only `fetch`-based `HttpClient` so MSW has something real to intercept, modelled on
 * ../../../django-dynamic-user/tests/frontend/helpers.tsx's own `makeFetchClient`.
 *
 * Unlike the sibling's version, a non-OK response is turned into a REAL appkit `ApiError` via
 * `apiErrorFromEnvelope` rather than a bare `Error` — this package's own `withAuthRetry.ts`
 * detects a 401 by inspecting `ApiError.status`, so the test double needs to actually produce
 * one for that detection to be exercised realistically rather than by a structural-fallback path
 * that would pass even if the real `isApiError` branch were broken.
 */
export function makeFetchClient(baseUrl: string): HttpClient {
  async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(`${baseUrl}${path}`, init);
    if (!response.ok) {
      let body: unknown = null;
      try {
        body = await response.json();
      } catch {
        body = null;
      }
      throw apiErrorFromEnvelope({
        status: response.status,
        body,
        requestId: response.headers.get("x-request-id"),
        retryAfter: response.headers.get("retry-after"),
      });
    }
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }

  return {
    get: (path, init) => request(path, init),
    post: (path, body, init) =>
      request(path, {
        ...init,
        method: "POST",
        headers: { "Content-Type": "application/json", ...init?.headers },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      }),
    put: (path, body, init) =>
      request(path, {
        ...init,
        method: "PUT",
        headers: { "Content-Type": "application/json", ...init?.headers },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      }),
    patch: (path, body, init) =>
      request(path, {
        ...init,
        method: "PATCH",
        headers: { "Content-Type": "application/json", ...init?.headers },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      }),
    delete: (path, init) => request(path, { ...init, method: "DELETE" }),
  };
}

export const TEST_BASE_URL = "https://api.test";

/**
 * Wraps a `renderHook` call in `QueryClientProvider` (retry disabled on both queries and
 * mutations, per docs/APP-DESIGN.md §7.7's "retry: false stops react-query's default retry from
 * making a failure-path test take three seconds") plus appkit's `ApiClientProvider`, bound to
 * BOTH this app's namespaces — `jwt_multiauth` at `/api/v1/auth` and `jwt_multiauth_admin` at
 * `/api/v1/admin/auth`, the same defaults `useJwtMultiauthConfig`/`useJwtMultiauthAdminConfig`
 * themselves use. Every hook test in this directory, self-service or admin, shares this one
 * wrapper rather than two separate ones, so a test can never accidentally pass by having the
 * "wrong" surface's basePath simply be absent.
 */
export function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const client = makeFetchClient(TEST_BASE_URL);

  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <ApiClientProvider
          client={client}
          basePaths={{
            jwt_multiauth: "/api/v1/auth",
            jwt_multiauth_admin: "/api/v1/admin/auth",
          }}
        >
          {children}
        </ApiClientProvider>
      </QueryClientProvider>
    );
  }

  return { Wrapper, queryClient };
}
