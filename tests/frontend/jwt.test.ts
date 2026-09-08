import { describe, expect, it } from "vitest";
import { readTokenExpiry } from "../../frontend/src/jwt.js";
import { makeFakeJwt, makeUndecodableJwt } from "./fixtures.js";

describe("readTokenExpiry", () => {
  it("decodes a well-formed token's exp claim as milliseconds since epoch", () => {
    const expSeconds = Math.floor(Date.now() / 1000) + 42;
    const token = makeFakeJwt({ exp: expSeconds });

    expect(readTokenExpiry(token)).toBe(expSeconds * 1000);
  });

  it("returns null for a token that isn't three dot-separated segments", () => {
    expect(readTokenExpiry("not-a-jwt")).toBeNull();
  });

  it("returns null — never throws — for a token whose payload doesn't decode to JSON", () => {
    expect(readTokenExpiry(makeUndecodableJwt())).toBeNull();
  });

  it("returns null when the payload carries no numeric exp claim", () => {
    const token = makeFakeJwt({ exp: "not-a-number" });

    expect(readTokenExpiry(token)).toBeNull();
  });

  it("falls back to a Buffer-based decode when atob is unavailable (SSR/Node)", () => {
    const expSeconds = Math.floor(Date.now() / 1000) + 42;
    const token = makeFakeJwt({ exp: expSeconds });
    const originalAtob = globalThis.atob;
    // @ts-expect-error — simulating a non-browser environment with no atob global at all.
    delete globalThis.atob;

    try {
      expect(readTokenExpiry(token)).toBe(expSeconds * 1000);
    } finally {
      globalThis.atob = originalAtob;
    }
  });
});
