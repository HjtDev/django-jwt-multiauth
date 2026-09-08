import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeTokenVerifyResponse } from "./fixtures.js";
import { useVerifyToken } from "../../frontend/src/hooks/useVerifyToken.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/token/verify/`;

describe("useVerifyToken", () => {
  it("resolves {valid: true, claims} for a good token", async () => {
    const body = makeTokenVerifyResponse();
    server.use(http.post(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useVerifyToken(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ token: "some-token" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("resolves {valid: false} — never a 401 — for a bad token", async () => {
    const body = makeTokenVerifyResponse({ valid: false, claims: undefined });
    server.use(http.post(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useVerifyToken(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ token: "garbage" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.valid).toBe(false);
  });
});
