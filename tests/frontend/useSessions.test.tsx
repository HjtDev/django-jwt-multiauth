import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makePaginatedAuthSessionList } from "./fixtures.js";
import { useSessions } from "../../frontend/src/hooks/useSessions.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/sessions/`;

describe("useSessions", () => {
  it("returns the caller's own paginated sessions on success", async () => {
    const body = makePaginatedAuthSessionList();
    server.use(http.get(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useSessions(), { wrapper: createWrapper().Wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces an error on a failed request", async () => {
    server.use(http.get(URL, () => new HttpResponse(null, { status: 500 })));

    const { result } = renderHook(() => useSessions(), { wrapper: createWrapper().Wrapper });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });

  it("builds a query string when params are provided", async () => {
    let hitUrl: string | null = null;
    server.use(
      http.get(URL, ({ request }) => {
        hitUrl = request.url;
        return HttpResponse.json(makePaginatedAuthSessionList());
      }),
    );

    const { result } = renderHook(() => useSessions({ page: 2, page_size: 10 }), {
      wrapper: createWrapper().Wrapper,
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(hitUrl).toBe(`${URL}?page=2&page_size=10`);
  });
});
