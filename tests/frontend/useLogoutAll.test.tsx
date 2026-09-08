import { beforeEach, describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeFakeJwt, makeLogoutAllResponse } from "./fixtures.js";
import { useLogoutAll } from "../../frontend/src/hooks/useLogoutAll.js";
import { clear, getAccessToken, setAccessToken } from "../../frontend/src/authStore.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/logout/all/`;

beforeEach(() => {
  clear();
});

describe("useLogoutAll", () => {
  it("clears authStore's access token on success", async () => {
    const body = makeLogoutAllResponse();
    server.use(http.post(URL, () => HttpResponse.json(body)));
    setAccessToken(makeFakeJwt(), null);

    const { result } = renderHook(() => useLogoutAll(), { wrapper: createWrapper().Wrapper });
    result.current.mutate();

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
    expect(getAccessToken()).toBeNull();
  });

  it("surfaces an error without crashing", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 500 })));

    const { result } = renderHook(() => useLogoutAll(), { wrapper: createWrapper().Wrapper });
    result.current.mutate();

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
