import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { createElement } from "react";
import { renderToString } from "react-dom/server";
import { makeFakeJwt } from "./fixtures.js";
import {
  clear,
  getAccessToken,
  peekExpiresAt,
  setAccessToken,
  subscribe,
  useAuthState,
} from "../../frontend/src/authStore.js";

const CHANNEL_NAME = "jwt_multiauth_auth";

beforeEach(() => {
  clear();
});

describe("authStore", () => {
  it("holds the access token only in a closure — getAccessToken/clear round-trip", () => {
    expect(getAccessToken()).toBeNull();

    const token = makeFakeJwt();
    setAccessToken(token, null);
    expect(getAccessToken()).toBe(token);

    clear();
    expect(getAccessToken()).toBeNull();
  });

  it("setAccessToken(null, ...) is equivalent to calling clear()", () => {
    setAccessToken(makeFakeJwt(), null);
    expect(getAccessToken()).not.toBeNull();

    setAccessToken(null, null);
    expect(getAccessToken()).toBeNull();
  });

  it("useAuthState's getServerSnapshot returns logged-out without throwing, under SSR", () => {
    setAccessToken(makeFakeJwt(), null);

    function Probe() {
      const { isAuthenticated } = useAuthState();
      return createElement("span", null, isAuthenticated ? "in" : "out");
    }

    // react-dom/server never calls the client `getSnapshot` — only `getServerSnapshot` — so this
    // is the one path that actually exercises useAuthState's third useSyncExternalStore argument.
    const html = renderToString(createElement(Probe));
    expect(html).toContain("out");
  });

  it("derives expiresAt from the token's own exp claim when not given one explicitly", () => {
    const expSeconds = Math.floor(Date.now() / 1000) + 123;
    setAccessToken(makeFakeJwt({ exp: expSeconds }), null);

    expect(peekExpiresAt()).toBe(expSeconds * 1000);
  });

  it("honours an explicit expiresAt over the derived one", () => {
    setAccessToken(makeFakeJwt(), 999);

    expect(peekExpiresAt()).toBe(999);
  });

  it("notifies subscribers on setAccessToken and clear, and stops after unsubscribe", () => {
    const listener = vi.fn();
    const unsubscribe = subscribe(listener);

    setAccessToken(makeFakeJwt(), null);
    expect(listener).toHaveBeenCalledTimes(1);

    clear();
    expect(listener).toHaveBeenCalledTimes(2);

    unsubscribe();
    setAccessToken(makeFakeJwt(), null);
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it("useAuthState reflects logged-in/out state reactively", () => {
    const { result } = renderHook(() => useAuthState());
    expect(result.current.isAuthenticated).toBe(false);

    act(() => {
      setAccessToken(makeFakeJwt(), null);
    });
    expect(result.current.isAuthenticated).toBe(true);

    act(() => {
      clear();
    });
    expect(result.current.isAuthenticated).toBe(false);
  });

  it("never includes the token itself in a cross-tab broadcast message", async () => {
    const external = new BroadcastChannel(CHANNEL_NAME);
    const received: unknown[] = [];
    external.onmessage = (event) => received.push(event.data);

    const token = makeFakeJwt();
    setAccessToken(token, null);
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(received).toEqual([{ type: "token-refreshed" }]);
    expect(JSON.stringify(received)).not.toContain(token);
    external.close();
  });

  it('clear() broadcasts "logged-out" to other tabs', async () => {
    setAccessToken(makeFakeJwt(), null);
    const external = new BroadcastChannel(CHANNEL_NAME);
    const received: unknown[] = [];
    external.onmessage = (event) => received.push(event.data);

    clear();
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(received).toEqual([{ type: "logged-out" }]);
    external.close();
  });

  it("clear() is idempotent — a second call with nothing left to clear does not broadcast again", async () => {
    clear();
    const external = new BroadcastChannel(CHANNEL_NAME);
    const received: unknown[] = [];
    external.onmessage = (event) => received.push(event.data);

    clear();
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(received).toEqual([]);
    external.close();
  });

  it('clears locally without RE-BROADCASTING when it receives "logged-out" from another tab', async () => {
    setAccessToken(makeFakeJwt(), null);
    const external = new BroadcastChannel(CHANNEL_NAME);
    const received: unknown[] = [];
    external.onmessage = (event) => received.push(event.data);

    external.postMessage({ type: "logged-out" });
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(getAccessToken()).toBeNull();
    // If this module's onmessage handler called the broadcasting clear() instead of the
    // non-broadcasting clearLocal(), `external` (a distinct BroadcastChannel instance from the
    // module's own) would receive a second "logged-out" message here. It doesn't.
    expect(received).toEqual([]);
    external.close();
  });

  it('notifies (without clearing) when it receives "token-refreshed" from another tab', async () => {
    const listener = vi.fn();
    subscribe(listener);
    const external = new BroadcastChannel(CHANNEL_NAME);

    const ownToken = makeFakeJwt();
    setAccessToken(ownToken, null);
    listener.mockClear();

    external.postMessage({ type: "token-refreshed" });
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(listener).toHaveBeenCalledTimes(1);
    // This tab's own token is unaffected — BroadcastChannel never carries another tab's token.
    expect(getAccessToken()).toBe(ownToken);
    external.close();
  });

  it("ignores an unrecognized cross-tab message type", async () => {
    const listener = vi.fn();
    subscribe(listener);
    const external = new BroadcastChannel(CHANNEL_NAME);

    external.postMessage({ type: "something-else" });
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(listener).not.toHaveBeenCalled();
    external.close();
  });

  it("stays importable, and fully functional, when BroadcastChannel is unavailable (SSR)", async () => {
    const original = globalThis.BroadcastChannel;
    // @ts-expect-error — simulating an environment (Next.js server render) with no
    // BroadcastChannel global at all, which the module-scope guard must tolerate.
    delete globalThis.BroadcastChannel;
    vi.resetModules();

    try {
      // Same specifier as this file's own top-level import — vi.resetModules() busts Vitest's
      // module cache for the NEXT import, static or dynamic, so this genuinely re-evaluates
      // authStore.ts fresh, with the BroadcastChannel global already removed, rather than
      // returning the already-cached instance bound at the top of this file.
      const ssrAuthStore = await import("../../frontend/src/authStore.js");
      expect(ssrAuthStore.getAccessToken()).toBeNull();

      const token = makeFakeJwt();
      ssrAuthStore.setAccessToken(token, null);
      expect(ssrAuthStore.getAccessToken()).toBe(token);
    } finally {
      globalThis.BroadcastChannel = original;
      vi.resetModules();
    }
  });
});
