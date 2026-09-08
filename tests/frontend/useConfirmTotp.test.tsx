import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { useConfirmTotp } from "../../frontend/src/hooks/useConfirmTotp.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/2fa/totp/confirm/`;

describe("useConfirmTotp", () => {
  it("succeeds with a 204", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 204 })));

    const { result } = renderHook(() => useConfirmTotp(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ code: "123456" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
  });

  it("surfaces an error on an invalid code", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 400 })));

    const { result } = renderHook(() => useConfirmTotp(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ code: "000000" });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
