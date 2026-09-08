import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makePaginatedTrustedDeviceList } from "./fixtures.js";
import { useTrustedDevices } from "../../frontend/src/hooks/useTrustedDevices.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/trusted-devices/`;

describe("useTrustedDevices", () => {
  it("returns the caller's own paginated trusted devices on success", async () => {
    const body = makePaginatedTrustedDeviceList();
    server.use(http.get(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useTrustedDevices(), { wrapper: createWrapper().Wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces an error on a failed request", async () => {
    server.use(http.get(URL, () => new HttpResponse(null, { status: 500 })));

    const { result } = renderHook(() => useTrustedDevices(), { wrapper: createWrapper().Wrapper });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
