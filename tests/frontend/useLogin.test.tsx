import { beforeEach, describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeLoginPendingTwoFactorResponse, makeLoginTokensResponse } from "./fixtures.js";
import { useLogin } from "../../frontend/src/hooks/useLogin.js";
import { clear, getAccessToken } from "../../frontend/src/authStore.js";

const LOGIN_URL = `${TEST_BASE_URL}/api/v1/auth/login/`;

beforeEach(() => {
  clear();
});

describe("useLogin", () => {
  it("sets authStore's access token on a token-bearing success", async () => {
    const body = makeLoginTokensResponse();
    server.use(http.post(LOGIN_URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useLogin(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ identifier: "alice", password: "hunter2", remember_me: false });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
    expect(getAccessToken()).toBe(body.access);
  });

  it("leaves authStore untouched on the 2FA-pending branch", async () => {
    const body = makeLoginPendingTwoFactorResponse();
    server.use(http.post(LOGIN_URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useLogin(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ identifier: "alice", password: "hunter2", remember_me: false });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
    expect(getAccessToken()).toBeNull();
  });

  it("surfaces an error on invalid credentials, without touching authStore", async () => {
    server.use(http.post(LOGIN_URL, () => new HttpResponse(null, { status: 401 })));

    const { result } = renderHook(() => useLogin(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ identifier: "alice", password: "wrong", remember_me: false });

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(getAccessToken()).toBeNull();
  });
});
