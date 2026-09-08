import { describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "./setup.js";
import { createWrapper, TEST_BASE_URL } from "./helpers.js";
import { makeTotpEnrollResponse } from "./fixtures.js";
import { useEnrollTotp } from "../../frontend/src/hooks/useEnrollTotp.js";

const URL = `${TEST_BASE_URL}/api/v1/auth/2fa/totp/enroll/`;

describe("useEnrollTotp", () => {
  it("returns the plaintext secret and otpauth URI on success, sending no body", async () => {
    const body = makeTotpEnrollResponse();
    server.use(
      http.post(URL, async ({ request }) => {
        const text = await request.text();
        expect(text).toBe("");
        return HttpResponse.json(body);
      }),
    );

    const { result } = renderHook(() => useEnrollTotp(), { wrapper: createWrapper().Wrapper });
    result.current.mutate();

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(body);
  });

  it("surfaces an error on a failed request", async () => {
    server.use(http.post(URL, () => new HttpResponse(null, { status: 500 })));

    const { result } = renderHook(() => useEnrollTotp(), { wrapper: createWrapper().Wrapper });
    result.current.mutate();

    await waitFor(() => expect(result.current.isError).toBe(true));
  });
});
