import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeOtpRequestResponse } from "./fixtures.js";
import { useOtpRequest } from "../../frontend/src/hooks/useOtpRequest.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/otp/request/`;

describe("useOtpRequest", () => {
  it("returns the challenge on success", async () => {
    const body = makeOtpRequestResponse();
    server.use(http.post(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useOtpRequest(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ identifier: "alice@example.com", channel: "email" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces an error when the channel isn't allowed", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 400 })));

    const { result } = renderHook(() => useOtpRequest(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ identifier: "alice@example.com", channel: "phone" });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
