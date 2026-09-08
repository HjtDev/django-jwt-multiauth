import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeAuthMethodsResponse } from "./fixtures.js";
import { useAuthMethods } from "../../frontend/src/hooks/useAuthMethods.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/methods/`;

describe("useAuthMethods", () => {
  it("returns the deployment's allowed auth methods on success", async () => {
    const body = makeAuthMethodsResponse();
    server.use(http.get(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useAuthMethods(), { wrapper: createWrapper().Wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces an error on a failed request", async () => {
    server.use(http.get(URL, () => new HttpResponse(null, { status: 500 })));

    const { result } = renderHook(() => useAuthMethods(), { wrapper: createWrapper().Wrapper });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
