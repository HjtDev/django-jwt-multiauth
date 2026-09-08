import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { useConfirmContactVerification } from "../../frontend/src/hooks/useConfirmContactVerification.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/account/verify-contact/confirm/`;

describe("useConfirmContactVerification", () => {
  it("succeeds with a 204", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 204 })));

    const { result } = renderHook(() => useConfirmContactVerification(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({ challenge_id: "challenge-1", code: "123456" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
  });

  it("surfaces an error on an invalid code", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 400 })));

    const { result } = renderHook(() => useConfirmContactVerification(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({ challenge_id: "challenge-1", code: "000000" });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
