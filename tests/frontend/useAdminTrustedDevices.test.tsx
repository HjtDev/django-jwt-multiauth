import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makePaginatedTrustedDeviceList } from "./fixtures.js";
import { useAdminTrustedDevices } from "../../frontend/src/hooks/useAdminTrustedDevices.js";

const URL = `${TEST_BASE_URL}/api/v1/admin/auth/trusted-devices/`;

describe("useAdminTrustedDevices", () => {
  it("returns paginated trusted devices across all users on success", async () => {
    const body = makePaginatedTrustedDeviceList();
    server.use(http.get(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useAdminTrustedDevices(), {
      wrapper: createWrapper().Wrapper,
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces a 403 for a non-admin caller", async () => {
    server.use(http.get(URL, () => new HttpResponse(null, { status: 403 })));

    const { result } = renderHook(() => useAdminTrustedDevices(), {
      wrapper: createWrapper().Wrapper,
    });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
