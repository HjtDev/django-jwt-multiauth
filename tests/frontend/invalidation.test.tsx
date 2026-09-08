import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeFakeJwt, makePaginatedAuthSessionList } from "./fixtures.js";
import { useSessions } from "../../frontend/src/hooks/useSessions.js";
import { useLogout } from "../../frontend/src/hooks/useLogout.js";
import { clear, setAccessToken } from "../../frontend/src/authStore.js";

/**
 * Proves `jwtMultiauthKeys.sessions()` (no-params form) actually matches a no-params
 * `useSessions()` query when a mutation hook invalidates it — the regression this guards against
 * is a key factory emitting a trailing literal `undefined` (`[...all, "sessions", undefined]`)
 * instead of dropping the params slot entirely, which would make `invalidateQueries` silently
 * never match the real query (docs/CONTRACT.md §7, hooks/keys.ts's own doc comment).
 */
describe("query-key invalidation", () => {
  it("useLogout's invalidation of jwtMultiauthKeys.sessions() refetches a no-params useSessions() query", async () => {
    let sessionsCalls = 0;
    server.use(
      http.get(`${TEST_BASE_URL}/api/v1/auth/sessions/`, () => {
        sessionsCalls += 1;
        return HttpResponse.json(makePaginatedAuthSessionList());
      }),
      http.post(
        `${TEST_BASE_URL}/api/v1/auth/logout/`,
        () => new HttpResponse(null, { status: 204 }),
      ),
    );
    setAccessToken(makeFakeJwt(), null);

    const { Wrapper } = createWrapper();
    const sessions = renderHook(() => useSessions(), { wrapper: Wrapper });
    await waitFor(() => expect(sessions.result.current.isSuccess).toBe(true));
    expect(sessionsCalls).toBe(1);

    const logout = renderHook(() => useLogout(), { wrapper: Wrapper });
    logout.result.current.mutate();
    await waitFor(() => expect(logout.result.current.isSuccess).toBe(true));

    await waitFor(() => expect(sessionsCalls).toBe(2));
    clear();
  });
});
