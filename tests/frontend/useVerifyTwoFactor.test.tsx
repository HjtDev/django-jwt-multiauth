import { beforeEach, describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeLoginTokensResponse } from "./fixtures.js";
import { useVerifyTwoFactor } from "../../frontend/src/hooks/useVerifyTwoFactor.js";
import { clear, getAccessToken } from "../../frontend/src/authStore.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/2fa/verify/`;

beforeEach(() => {
  clear();
});

describe("useVerifyTwoFactor", () => {
  it("always sets authStore's access token on success (no pending-again branch)", async () => {
    const body = makeLoginTokensResponse();
    server.use(http.post(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useVerifyTwoFactor(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({
      pending_token: "pending-1",
      method: "totp",
      code: "123456",
      trust_device: false,
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(getAccessToken()).toBe(body.access);
  });

  it("surfaces an error on an invalid code, without touching authStore", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 401 })));

    const { result } = renderHook(() => useVerifyTwoFactor(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({
      pending_token: "pending-1",
      method: "totp",
      code: "000000",
      trust_device: false,
    });

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(getAccessToken()).toBeNull();
  });
});
