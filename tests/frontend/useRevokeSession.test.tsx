import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { useRevokeSession } from "../../frontend/src/hooks/useRevokeSession.js";

const SESSION_ID = "11111111-1111-1111-1111-111111111111";
const URL = `${TEST_BASE_URL}/api/v1/auth/sessions/${SESSION_ID}/`;

describe("useRevokeSession", () => {
  it("succeeds with a 204", async () => {
    server.use(http.delete(URL, () => new HttpResponse(null, { status: 204 })));

    const { result } = renderHook(() => useRevokeSession(), { wrapper: createWrapper().Wrapper });
    result.current.mutate(SESSION_ID);

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
  });

  it("surfaces a 404 when the session isn't the caller's own", async () => {
    server.use(http.delete(URL, () => new HttpResponse(null, { status: 404 })));

    const { result } = renderHook(() => useRevokeSession(), { wrapper: createWrapper().Wrapper });
    result.current.mutate(SESSION_ID);

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
