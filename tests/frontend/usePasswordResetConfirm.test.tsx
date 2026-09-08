import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { usePasswordResetConfirm } from "../../frontend/src/hooks/usePasswordResetConfirm.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/password/reset/confirm/`;

describe("usePasswordResetConfirm", () => {
  it("succeeds with a 204", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 204 })));

    const { result } = renderHook(() => usePasswordResetConfirm(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({
      challenge_id: "challenge-1",
      code: "123456",
      new_password: "new-password-123",
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
  });

  it("surfaces an error on an invalid/expired challenge", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 400 })));

    const { result } = renderHook(() => usePasswordResetConfirm(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({
      challenge_id: "bad",
      code: "000000",
      new_password: "new-password-123",
    });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
