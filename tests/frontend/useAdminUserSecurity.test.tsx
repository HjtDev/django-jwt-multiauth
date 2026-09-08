import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeAdminUserSecurityResponse } from "./fixtures.js";
import { useAdminUserSecurity } from "../../frontend/src/hooks/useAdminUserSecurity.js";

const URL = `${TEST_BASE_URL}/api/v1/admin/auth/users/1/security/`;

describe("useAdminUserSecurity", () => {
  it("returns the read-only security aggregate on success", async () => {
    const body = makeAdminUserSecurityResponse();
    server.use(http.get(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useAdminUserSecurity(1), {
      wrapper: createWrapper().Wrapper,
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces a 404 for an unknown user", async () => {
    server.use(http.get(URL, () => new HttpResponse(null, { status: 404 })));

    const { result } = renderHook(() => useAdminUserSecurity(1), {
      wrapper: createWrapper().Wrapper,
    });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
