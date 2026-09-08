import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { usePasswordResetRequest } from "../../frontend/src/hooks/usePasswordResetRequest.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/password/reset/request/`;

describe("usePasswordResetRequest", () => {
  it("succeeds unconditionally, even for an unknown identifier (enumeration resistance)", async () => {
    server.use(http.post(URL, () => HttpResponse.json({})));

    const { result } = renderHook(() => usePasswordResetRequest(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({ identifier: "nobody@example.com" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
  });

  it("surfaces a transport-level error (e.g. a 500)", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 500 })));

    const { result } = renderHook(() => usePasswordResetRequest(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate({ identifier: "alice@example.com" });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
