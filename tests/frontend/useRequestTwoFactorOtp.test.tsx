import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeOtpRequestResponse } from "./fixtures.js";
import { useRequestTwoFactorOtp } from "../../frontend/src/hooks/useRequestTwoFactorOtp.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/2fa/otp/request/`;

describe("useRequestTwoFactorOtp", () => {
  it("returns the challenge on success — the gap CONTRACT §7 didn't originally list a hook for", async () => {
    const body = makeOtpRequestResponse();
    server.use(http.post(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useRequestTwoFactorOtp(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({ pending_token: "pending-1", method: "email_otp" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces an error on an invalid/expired pending token", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 401 })));

    const { result } = renderHook(() => useRequestTwoFactorOtp(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({ pending_token: "bad", method: "email_otp" });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
