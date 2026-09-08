import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeRecoveryCodesResponse } from "./fixtures.js";
import { useRegenerateRecoveryCodes } from "../../frontend/src/hooks/useRegenerateRecoveryCodes.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/2fa/recovery-codes/regenerate/`;

describe("useRegenerateRecoveryCodes", () => {
  it("returns the fresh plaintext codes on success", async () => {
    const body = makeRecoveryCodesResponse();
    server.use(http.post(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useRegenerateRecoveryCodes(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({ password: "hunter2" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces an error on an incorrect password", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 400 })));

    const { result } = renderHook(() => useRegenerateRecoveryCodes(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({ password: "wrong" });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
