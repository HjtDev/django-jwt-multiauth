import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makePaginatedLoginAttemptList } from "./fixtures.js";
import { useAdminLoginAttempts } from "../../frontend/src/hooks/useAdminLoginAttempts.js";

const URL = `${TEST_BASE_URL}/api/v1/admin/auth/login-attempts/`;

describe("useAdminLoginAttempts", () => {
  it("returns the paginated login-attempt audit log on success", async () => {
    const body = makePaginatedLoginAttemptList();
    server.use(http.get(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useAdminLoginAttempts(), {
      wrapper: createWrapper().Wrapper,
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces a 403 for a non-admin caller", async () => {
    server.use(http.get(URL, () => new HttpResponse(null, { status: 403 })));

    const { result } = renderHook(() => useAdminLoginAttempts(), {
      wrapper: createWrapper().Wrapper,
    });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });

  it("builds a query string from provided params, skipping any that are undefined", async () => {
    let hitUrl: string | null = null;
    server.use(
      http.get(URL, ({ request }) => {
        hitUrl = request.url;
        return HttpResponse.json(makePaginatedLoginAttemptList());
      }),
    );

    const { result } = renderHook(
      () => useAdminLoginAttempts({ user: 5, identifier: undefined, success: true }),
      { wrapper: createWrapper().Wrapper },
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(hitUrl).toBe(`${URL}?user=5&success=true`);
  });

  it("omits the query string entirely when every provided param is undefined/null", async () => {
    let hitUrl: string | null = null;
    server.use(
      http.get(URL, ({ request }) => {
        hitUrl = request.url;
        return HttpResponse.json(makePaginatedLoginAttemptList());
      }),
    );

    const { result } = renderHook(() => useAdminLoginAttempts({ identifier: undefined }), {
      wrapper: createWrapper().Wrapper,
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(hitUrl).toBe(URL);
  });
});
