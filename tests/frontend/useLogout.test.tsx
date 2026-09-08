import { beforeEach, describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeFakeJwt } from "./fixtures.js";
import { useLogout } from "../../frontend/src/hooks/useLogout.js";
import { clear, getAccessToken, setAccessToken } from "../../frontend/src/authStore.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/logout/`;

beforeEach(() => {
  clear();
});

describe("useLogout", () => {
  it("clears authStore's access token on success", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 204 })));
    setAccessToken(makeFakeJwt(), null);

    const { result } = renderHook(() => useLogout(), { wrapper: createWrapper().Wrapper });
    result.current.mutate();

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(getAccessToken()).toBeNull();
  });

  it("surfaces an error without crashing", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 500 })));

    const { result } = renderHook(() => useLogout(), { wrapper: createWrapper().Wrapper });
    result.current.mutate();

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
