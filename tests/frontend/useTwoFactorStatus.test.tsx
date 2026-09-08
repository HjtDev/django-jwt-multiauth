import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeTwoFactorStatusResponse } from "./fixtures.js";
import { useTwoFactorStatus } from "../../frontend/src/hooks/useTwoFactorStatus.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/2fa/status/`;

describe("useTwoFactorStatus", () => {
  it("returns the caller's 2FA status on success", async () => {
    const body = makeTwoFactorStatusResponse();
    server.use(http.get(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useTwoFactorStatus(), { wrapper: createWrapper().Wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces an error on a failed request", async () => {
    server.use(http.get(URL, () => new HttpResponse(null, { status: 500 })));

    const { result } = renderHook(() => useTwoFactorStatus(), { wrapper: createWrapper().Wrapper });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
