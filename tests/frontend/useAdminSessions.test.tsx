import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makePaginatedAuthSessionList } from "./fixtures.js";
import { useAdminSessions } from "../../frontend/src/hooks/useAdminSessions.js";

const URL = `${TEST_BASE_URL}/api/v1/admin/auth/sessions/`;

describe("useAdminSessions", () => {
  it("returns paginated sessions across all users on success", async () => {
    const body = makePaginatedAuthSessionList();
    server.use(http.get(URL, () => HttpResponse.json(body)));

    const { result } = renderHook(() => useAdminSessions(), { wrapper: createWrapper().Wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces a 403 for a non-admin caller", async () => {
    server.use(http.get(URL, () => new HttpResponse(null, { status: 403 })));

    const { result } = renderHook(() => useAdminSessions(), { wrapper: createWrapper().Wrapper });

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
