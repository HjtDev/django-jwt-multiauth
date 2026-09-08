import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeOtpRequestResponse } from "./fixtures.js";
import { useOtpResend } from "../../frontend/src/hooks/useOtpResend.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/otp/resend/`;

describe("useOtpResend", () => {
  it("returns a fresh challenge on success", async () => {
    const body = makeOtpRequestResponse();
    server.use(http.post(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useOtpResend(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ challenge_id: "challenge-1" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces an error when the cooldown hasn't elapsed", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 400 })));

    const { result } = renderHook(() => useOtpResend(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ challenge_id: "challenge-1" });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
