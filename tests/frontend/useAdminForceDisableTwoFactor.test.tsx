import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { useAdminForceDisableTwoFactor } from "../../frontend/src/hooks/useAdminForceDisableTwoFactor.js";

const URL = `${TEST_BASE_URL}/api/v1/admin/auth/users/1/2fa/force-disable/`;

describe("useAdminForceDisableTwoFactor", () => {
  it("succeeds with a 204 for a superuser caller", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 204 })));

    const { result } = renderHook(() => useAdminForceDisableTwoFactor(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate(1);

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
  });

  it("surfaces a 403 for a non-superuser caller — never loosened by ADMIN_REQUIRES_SUPERUSER", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 403 })));

    const { result } = renderHook(() => useAdminForceDisableTwoFactor(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate(1);

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
