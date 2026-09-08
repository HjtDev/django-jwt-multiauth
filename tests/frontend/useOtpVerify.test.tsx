import { beforeEach, describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeLoginPendingTwoFactorResponse, makeLoginTokensResponse } from "./fixtures.js";
import { useOtpVerify } from "../../frontend/src/hooks/useOtpVerify.js";
import { clear, getAccessToken } from "../../frontend/src/authStore.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/otp/verify/`;

beforeEach(() => {
  clear();
});

describe("useOtpVerify", () => {
  it("sets authStore's access token on a token-bearing success (including auto-provisioning)", async () => {
    const body = makeLoginTokensResponse({ created: true });
    server.use(http.post(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useOtpVerify(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ challenge_id: "challenge-1", code: "123456" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
    expect(getAccessToken()).toBe(body.access);
  });

  it("leaves authStore untouched on the 2FA-pending branch", async () => {
    const body = makeLoginPendingTwoFactorResponse();
    server.use(http.post(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useOtpVerify(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ challenge_id: "challenge-1", code: "123456" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(getAccessToken()).toBeNull();
  });

  it("surfaces an error on an invalid challenge", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 400 })));

    const { result } = renderHook(() => useOtpVerify(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ challenge_id: "bad", code: "000000" });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
