import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeAuthMethodsResponse, makePaginatedAuthSessionList } from "./fixtures.js";
import { useAuthMethods } from "../../frontend/src/hooks/useAuthMethods.js";
import { useAdminSessions } from "../../frontend/src/hooks/useAdminSessions.js";

/** Proves both basePath keys (`jwt_multiauth` -> /api/v1/auth, `jwt_multiauth_admin` ->
 * /api/v1/admin/auth) are actually used by real hooks, routing independently — not merely
 * declared in api/config.ts and never exercised. */
describe("basePath routing", () => {
  it("useAuthMethods (self-service surface) hits /api/v1/auth/methods/", async () => {
    let hitUrl: string | null = null;
    server.use(
      http.get(`${TEST_BASE_URL}/api/v1/auth/methods/`, ({ request }) => {
        hitUrl = request.url;
        return HttpResponse.json(makeAuthMethodsResponse());
      }),
    );

    const { result } = renderHook(() => useAuthMethods(), { wrapper: createWrapper().Wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(hitUrl).toBe(`${TEST_BASE_URL}/api/v1/auth/methods/`);
  });

  it("useAdminSessions (admin surface) hits /api/v1/admin/auth/sessions/ — a DIFFERENT basePath", async () => {
    let hitUrl: string | null = null;
    server.use(
      http.get(`${TEST_BASE_URL}/api/v1/admin/auth/sessions/`, ({ request }) => {
        hitUrl = request.url;
        return HttpResponse.json(makePaginatedAuthSessionList());
      }),
    );

    const { result } = renderHook(() => useAdminSessions(), { wrapper: createWrapper().Wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(hitUrl).toBe(`${TEST_BASE_URL}/api/v1/admin/auth/sessions/`);
  });
});
