import { beforeEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { TEST_BASE_URL } from "./helpers.js";
import { makeFakeJwt, makeTokenRefreshResponse, makeUndecodableJwt } from "./fixtures.js";
import { authHeaderSource } from "../../frontend/src/authHeaderSource.js";
import { configureAuth } from "../../frontend/src/refresh.js";
import { clear, getAccessToken, setAccessToken } from "../../frontend/src/authStore.js";

const REFRESH_URL = `${TEST_BASE_URL}/api/v1/auth/token/refresh/`;

beforeEach(() => {
  clear();
  configureAuth({ refreshUrl: REFRESH_URL, skewSeconds: 30, credentials: "include" });
});

describe("authHeaderSource", () => {
  it("returns {} (no Authorization header) when there is genuinely no session", async () => {
    server.use(http.post(REFRESH_URL, () => new HttpResponse(null, { status: 401 })));

    const headers = await authHeaderSource();

    expect(headers).toEqual({});
  });

  it("returns an Authorization header for a live, non-expiring token without calling refresh", async () => {
    let refreshCalls = 0;
    server.use(
      http.post(REFRESH_URL, () => {
        refreshCalls += 1;
        return HttpResponse.json(makeTokenRefreshResponse());
      }),
    );
    const token = makeFakeJwt({ exp: Math.floor(Date.now() / 1000) + 900 });
    setAccessToken(token, null);

    const headers = await authHeaderSource();

    expect(headers).toEqual({ Authorization: `Bearer ${token}` });
    expect(refreshCalls).toBe(0);
  });

  it("proactively refreshes when the token is inside the skew window", async () => {
    const freshToken = makeFakeJwt({ exp: Math.floor(Date.now() / 1000) + 900 });
    let refreshCalls = 0;
    server.use(
      http.post(REFRESH_URL, () => {
        refreshCalls += 1;
        return HttpResponse.json(makeTokenRefreshResponse({ access: freshToken }));
      }),
    );
    // Expires in 5s; skew is configured at 30s, so this must be treated as "expiring soon".
    setAccessToken(makeFakeJwt({ exp: Math.floor(Date.now() / 1000) + 5 }), null);

    const headers = await authHeaderSource();

    expect(headers).toEqual({ Authorization: `Bearer ${freshToken}` });
    expect(refreshCalls).toBe(1);
    expect(getAccessToken()).toBe(freshToken);
  });

  it("dedupes 5 concurrent calls into exactly ONE refresh network call (single-flight)", async () => {
    const freshToken = makeFakeJwt();
    let refreshCalls = 0;
    server.use(
      http.post(REFRESH_URL, async () => {
        refreshCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 20));
        return HttpResponse.json(makeTokenRefreshResponse({ access: freshToken }));
      }),
    );
    // No token at all — every one of the 5 concurrent callers must want to refresh.
    clear();

    const results = await Promise.all([
      authHeaderSource(),
      authHeaderSource(),
      authHeaderSource(),
      authHeaderSource(),
      authHeaderSource(),
    ]);

    expect(refreshCalls).toBe(1);
    for (const headers of results) {
      expect(headers).toEqual({ Authorization: `Bearer ${freshToken}` });
    }
  });

  it("treats a token with an undecodable exp claim as expiring, and refreshes", async () => {
    const freshToken = makeFakeJwt();
    let refreshCalls = 0;
    server.use(
      http.post(REFRESH_URL, () => {
        refreshCalls += 1;
        return HttpResponse.json(makeTokenRefreshResponse({ access: freshToken }));
      }),
    );
    // A real (non-null) token, but one whose expiry can't be derived — this is the one case
    // where isExpiringSoon's `expiresAt === null` branch runs without the `token === null`
    // short-circuit having already decided the outcome.
    setAccessToken(makeUndecodableJwt(), null);

    const headers = await authHeaderSource();

    expect(headers).toEqual({ Authorization: `Bearer ${freshToken}` });
    expect(refreshCalls).toBe(1);
  });

  it("propagates a real failure (a 500) rather than degrading to {}", async () => {
    server.use(http.post(REFRESH_URL, () => new HttpResponse(null, { status: 500 })));
    clear();

    await expect(authHeaderSource()).rejects.toThrow();
  });
});
