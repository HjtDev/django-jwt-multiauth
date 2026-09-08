import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeOtpRequestResponse } from "./fixtures.js";
import { useRequestContactVerification } from "../../frontend/src/hooks/useRequestContactVerification.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/account/verify-contact/request/`;

describe("useRequestContactVerification", () => {
  it("returns the challenge on success", async () => {
    const body = makeOtpRequestResponse();
    server.use(http.post(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useRequestContactVerification(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({ field: "email" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces an error when the field isn't configured", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 400 })));

    const { result } = renderHook(() => useRequestContactVerification(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({ field: "phone" });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
