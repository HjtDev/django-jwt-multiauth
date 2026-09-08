import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { useAdminRevokeTrustedDevice } from "../../frontend/src/hooks/useAdminRevokeTrustedDevice.js";

const URL = `${TEST_BASE_URL}/api/v1/admin/auth/trusted-devices/1/`;

describe("useAdminRevokeTrustedDevice", () => {
  it("succeeds with a 204, revoking any user's device", async () => {
    server.use(http.delete(URL, () => new HttpResponse(null, { status: 204 })));

    const { result } = renderHook(() => useAdminRevokeTrustedDevice(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate(1);

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
  });

  it("surfaces a 403 for a non-admin caller", async () => {
    server.use(http.delete(URL, () => new HttpResponse(null, { status: 403 })));

    const { result } = renderHook(() => useAdminRevokeTrustedDevice(), {
      wrapper: createWrapper().Wrapper,
    });
    result.current.mutate(1);

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
