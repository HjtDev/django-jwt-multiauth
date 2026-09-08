import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { useDisableTwoFactor } from "../../frontend/src/hooks/useDisableTwoFactor.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/2fa/disable/`;

describe("useDisableTwoFactor", () => {
  it("succeeds with a 204", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 204 })));

    const { result } = renderHook(() => useDisableTwoFactor(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({ method: "totp", password: "hunter2" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
  });

  it("surfaces an error on an incorrect password", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 400 })));

    const { result } = renderHook(() => useDisableTwoFactor(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({ method: "totp", password: "wrong" });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
