import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { useAdminRevokeSession } from "../../frontend/src/hooks/useAdminRevokeSession.js";

const SESSION_ID = "11111111-1111-1111-1111-111111111111";
const URL = `${TEST_BASE_URL}/api/v1/admin/auth/sessions/${SESSION_ID}/`;

describe("useAdminRevokeSession", () => {
  it("succeeds with a 204, revoking any user's session", async () => {
    server.use(http.delete(URL, () => new HttpResponse(null, { status: 204 })));

    const { result } = renderHook(() => useAdminRevokeSession(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate(SESSION_ID);

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
  });

  it("surfaces a 403 for a non-admin caller", async () => {
    server.use(http.delete(URL, () => new HttpResponse(null, { status: 403 })));

    const { result } = renderHook(() => useAdminRevokeSession(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate(SESSION_ID);

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
