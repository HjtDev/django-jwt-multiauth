import { beforeEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import type { HttpClient } from "@hjtdev/appkit";
import { server } from "./setup.js";
import { TEST_BASE_URL, makeFetchClient } from "./helpers.js";
import { makeFakeJwt, makeTokenRefreshResponse } from "./fixtures.js";
import { withAuthRetry } from "../../frontend/src/withAuthRetry.js";
import { configureAuth } from "../../frontend/src/refresh.js";
import { clear, getAccessToken } from "../../frontend/src/authStore.js";

const REFRESH_URL = `${TEST_BASE_URL}/api/v1/auth/token/refresh/`;
const PROTECTED_PATH = "/api/v1/auth/sessions/";
const PROTECTED_URL = `${TEST_BASE_URL}${PROTECTED_PATH}`;
const EMPTY_LIST = { count: 0, next: null, previous: null, results: [] };

beforeEach(() => {
  clear();
  configureAuth({ refreshUrl: REFRESH_URL, skewSeconds: 30, credentials: "include" });
});

describe("withAuthRetry", () => {
  it("retries exactly once after a single 401, sending the freshly refreshed token", async () => {
    const freshToken = makeFakeJwt();
    let protectedCalls = 0;
    server.use(
      http.post(REFRESH_URL, () =>
        HttpResponse.json(makeTokenRefreshResponse({ access: freshToken })),
      ),
      http.get(PROTECTED_URL, ({ request }) => {
        protectedCalls += 1;
        if (protectedCalls === 1) {
          expect(request.headers.get("Authorization")).toBe("Bearer stale-token");
          return new HttpResponse(null, { status: 401 });
        }
        expect(request.headers.get("Authorization")).toBe(`Bearer ${freshToken}`);
        return HttpResponse.json(EMPTY_LIST);
      }),
    );

    const client = withAuthRetry(makeFetchClient(TEST_BASE_URL));
    const result = await client.get(PROTECTED_PATH, {
      headers: { Authorization: "Bearer stale-token" },
    });

    expect(protectedCalls).toBe(2);
    expect(result).toEqual(EMPTY_LIST);
    expect(getAccessToken()).toBe(freshToken);
  });

  it("never calls the endpoint more than twice on a PERSISTENTLY 401ing endpoint", async () => {
    let protectedCalls = 0;
    server.use(
      http.post(REFRESH_URL, () => HttpResponse.json(makeTokenRefreshResponse())),
      http.get(PROTECTED_URL, () => {
        protectedCalls += 1;
        return new HttpResponse(null, { status: 401 });
      }),
    );

    const client = withAuthRetry(makeFetchClient(TEST_BASE_URL));

    await expect(client.get(PROTECTED_PATH)).rejects.toThrow();
    // Exactly one original attempt + one retry — never an infinite (or even a third) call.
    expect(protectedCalls).toBe(2);
    expect(getAccessToken()).toBeNull();
  });

  it("skips the retry and clears the session when refresh itself has no session", async () => {
    let protectedCalls = 0;
    server.use(
      http.post(REFRESH_URL, () => new HttpResponse(null, { status: 401 })),
      http.get(PROTECTED_URL, () => {
        protectedCalls += 1;
        return new HttpResponse(null, { status: 401 });
      }),
    );

    const client = withAuthRetry(makeFetchClient(TEST_BASE_URL));

    await expect(client.get(PROTECTED_PATH)).rejects.toThrow();
    expect(protectedCalls).toBe(1);
    expect(getAccessToken()).toBeNull();
  });

  it("does not retry a non-401 error", async () => {
    let protectedCalls = 0;
    server.use(
      http.get(PROTECTED_URL, () => {
        protectedCalls += 1;
        return new HttpResponse(null, { status: 500 });
      }),
    );

    const client = withAuthRetry(makeFetchClient(TEST_BASE_URL));

    await expect(client.get(PROTECTED_PATH)).rejects.toThrow();
    expect(protectedCalls).toBe(1);
  });

  it("does not clear the session when the RETRY fails with a non-401 error", async () => {
    let protectedCalls = 0;
    server.use(
      http.post(REFRESH_URL, () => HttpResponse.json(makeTokenRefreshResponse())),
      http.get(PROTECTED_URL, () => {
        protectedCalls += 1;
        if (protectedCalls === 1) {
          return new HttpResponse(null, { status: 401 });
        }
        return new HttpResponse(null, { status: 500 });
      }),
    );

    const client = withAuthRetry(makeFetchClient(TEST_BASE_URL));

    await expect(client.get(PROTECTED_PATH)).rejects.toThrow();
    expect(protectedCalls).toBe(2);
    // The retry's failure was unrelated to auth (a 500, not a 401) — the freshly refreshed
    // session is still good and must not be thrown away.
    expect(getAccessToken()).not.toBeNull();
  });

  it("also detects a 401 via a structural status property, not only appkit's ApiError", async () => {
    let calls = 0;
    const stubClient: HttpClient = {
      get: async <T>() => {
        calls += 1;
        if (calls === 1) {
          const err = new Error("nope") as Error & { status: number };
          err.status = 401;
          throw err;
        }
        return { ok: true } as T;
      },
      post: async () => {
        throw new Error("unused");
      },
      put: async () => {
        throw new Error("unused");
      },
      patch: async () => {
        throw new Error("unused");
      },
      delete: async () => {
        throw new Error("unused");
      },
    };
    server.use(http.post(REFRESH_URL, () => HttpResponse.json(makeTokenRefreshResponse())));

    const client = withAuthRetry(stubClient);
    const result = await client.get("/whatever");

    expect(result).toEqual({ ok: true });
    expect(calls).toBe(2);
  });

  it("passes post/put/patch/delete calls through unchanged on success (no 401)", async () => {
    server.use(
      http.post(`${TEST_BASE_URL}/post-path`, () => HttpResponse.json({ ok: "post" })),
      http.put(`${TEST_BASE_URL}/put-path`, () => HttpResponse.json({ ok: "put" })),
      http.patch(`${TEST_BASE_URL}/patch-path`, () => HttpResponse.json({ ok: "patch" })),
      http.delete(`${TEST_BASE_URL}/delete-path`, () => new HttpResponse(null, { status: 204 })),
    );

    const client = withAuthRetry(makeFetchClient(TEST_BASE_URL));

    await expect(client.post("/post-path", { a: 1 })).resolves.toEqual({ ok: "post" });
    await expect(client.put("/put-path", { a: 1 })).resolves.toEqual({ ok: "put" });
    await expect(client.patch("/patch-path", { a: 1 })).resolves.toEqual({ ok: "patch" });
    await expect(client.delete("/delete-path")).resolves.toBeUndefined();
  });
});
