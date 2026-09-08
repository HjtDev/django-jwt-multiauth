import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { usePasswordChange } from "../../frontend/src/hooks/usePasswordChange.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/password/change/`;

describe("usePasswordChange", () => {
  it("succeeds with a 204", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 204 })));

    const { result } = renderHook(() => usePasswordChange(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ old_password: "old", new_password: "new-password-123" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
  });

  it("surfaces an error on a wrong old_password", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 400 })));

    const { result } = renderHook(() => usePasswordChange(), { wrapper: createWrapper().Wrapper });
    result.current.mutate({ old_password: "wrong", new_password: "new-password-123" });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
