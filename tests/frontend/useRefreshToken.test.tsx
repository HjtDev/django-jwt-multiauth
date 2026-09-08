import { beforeEach, describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeTokenRefreshResponse } from "./fixtures.js";
import { useRefreshToken } from "../../frontend/src/hooks/useRefreshToken.js";
import { clear, getAccessToken } from "../../frontend/src/authStore.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/token/refresh/`;

beforeEach(() => {
  clear();
});

describe("useRefreshToken", () => {
  it("sets authStore's access token on success", async () => {
    const body = makeTokenRefreshResponse();
    server.use(http.post(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useRefreshToken(), { wrapper: createWrapper().Wrapper });
    result.current.mutate();

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(getAccessToken()).toBe(body.access);
  });

  it("surfaces an error on a missing/expired/reused refresh token", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 401 })));

    const { result } = renderHook(() => useRefreshToken(), { wrapper: createWrapper().Wrapper });
    result.current.mutate();

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(getAccessToken()).toBeNull();
  });
});
