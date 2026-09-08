import { beforeEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { server, localStorageSpies } from "./setup.js";
import { TEST_BASE_URL } from "./helpers.js";
import { makeFakeJwt, makeTokenRefreshResponse } from "./fixtures.js";
import { authHeaderSource } from "../../frontend/src/authHeaderSource.js";
import { withAuthRetry } from "../../frontend/src/withAuthRetry.js";
import { configureAuth } from "../../frontend/src/refresh.js";
import { clear, setAccessToken } from "../../frontend/src/authStore.js";
import { makeFetchClient } from "./helpers.js";

const REFRESH_URL = `${TEST_BASE_URL}/api/v1/auth/token/refresh/`;

beforeEach(() => {
  clear();
  configureAuth({ refreshUrl: REFRESH_URL, skewSeconds: 30, credentials: "include" });
});

/**
 * A dedicated, representative exercise of the whole token-manager trio — login-shaped
 * setAccessToken, a proactive refresh, a withAuthRetry retry cycle, and a logout-shaped clear —
 * asserting zero localStorage/sessionStorage calls in-file. The REAL suite-wide guarantee is
 * setup.ts's own afterEach (a spy on Storage.prototype asserted empty after every single test in
 * every file, not just this one) — this file exists to prove the guarantee holds across a
 * realistic multi-step flow, not just for a single isolated call.
 */
describe("no package code ever touches Web Storage", () => {
  it("survives a login -> proactive refresh -> 401 retry -> logout cycle untouched", async () => {
    const loginToken = makeFakeJwt({ exp: Math.floor(Date.now() / 1000) + 5 });
    const refreshedToken = makeFakeJwt();
    let refreshCalls = 0;
    server.use(
      http.post(REFRESH_URL, () => {
        refreshCalls += 1;
        return HttpResponse.json(makeTokenRefreshResponse({ access: refreshedToken }));
      }),
      http.get(`${TEST_BASE_URL}/api/v1/auth/sessions/`, ({ request }) => {
        if (request.headers.get("Authorization") === "Bearer stale") {
          return new HttpResponse(null, { status: 401 });
        }
        return HttpResponse.json({ count: 0, next: null, previous: null, results: [] });
      }),
    );

    // "login" — the one place outside the trio that calls setAccessToken directly.
    setAccessToken(loginToken, null);

    // authHeaderSource's proactive refresh (token expires in 5s, skew is 30s).
    const headers = await authHeaderSource();
    expect(headers).toEqual({ Authorization: `Bearer ${refreshedToken}` });
    expect(refreshCalls).toBe(1);

    // withAuthRetry's 401-triggered retry cycle.
    const client = withAuthRetry(makeFetchClient(TEST_BASE_URL));
    await client.get("/api/v1/auth/sessions/", { headers: { Authorization: "Bearer stale" } });

    // "logout".
    clear();

    expect(localStorageSpies.getItem).not.toHaveBeenCalled();
    expect(localStorageSpies.setItem).not.toHaveBeenCalled();
    expect(localStorageSpies.removeItem).not.toHaveBeenCalled();
  });
});
