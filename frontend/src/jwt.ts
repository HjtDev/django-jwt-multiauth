// Read-only JWT introspection — decodes the `exp` claim off an access token's payload segment,
// never verifies a signature. The backend stays the sole verifier of every token
// (docs/CONTRACT.md §11 item 17: neither this app's own README nor CONTRACT documents a response
// field carrying the access token's expiry, so the SDK derives it client-side rather than
// trusting an unsigned value from a response body it can't check). Used only to schedule
// authHeaderSource.ts's skew-window refresh — a wrong or missing `exp` here degrades to "refresh
// more eagerly than strictly necessary," never to a security decision, since the backend still
// rejects an actually-expired token outright.

function base64UrlDecode(segment: string): string {
  const padLength = (4 - (segment.length % 4)) % 4;
  const padded = segment.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padLength);
  if (typeof atob === "function") {
    return atob(padded);
  }
  // SSR/Node fallback — no `atob` global outside a browser/jsdom environment.
  return Buffer.from(padded, "base64").toString("binary");
}

/** Returns the access token's `exp` claim as milliseconds since epoch, or `null` if the token
 * isn't a well-formed three-segment JWT or carries no numeric `exp`. Never throws. */
export function readTokenExpiry(token: string): number | null {
  try {
    const segments = token.split(".");
    if (segments.length !== 3) return null;
    const payloadSegment = segments[1];
    if (!payloadSegment) return null;
    const payload = JSON.parse(base64UrlDecode(payloadSegment)) as { exp?: unknown };
    if (typeof payload.exp !== "number") return null;
    return payload.exp * 1000;
  } catch {
    return null;
  }
}
