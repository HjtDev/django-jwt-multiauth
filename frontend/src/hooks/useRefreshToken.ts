"use client";

import { useMemo } from "react";
import { useMutation } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import { setAccessToken } from "../authStore.js";
import type { TokenRefreshResponse } from "../types.js";

/**
 * Wraps `POST /token/refresh/` directly through the manager — exposed for completeness, but this
 * bypasses refresh.ts's single-flight deduplication that authHeaderSource.ts relies on. Calling
 * this from application code alongside normal request traffic can trigger a second, redundant
 * refresh network call concurrently with one authHeaderSource.ts already started. Prefer letting
 * authHeaderSource.ts refresh automatically; reach for this hook only for an explicit
 * "refresh now" UI action, not as part of an app's regular request flow.
 */
export function useRefreshToken() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);

  return useMutation({
    mutationFn: () => manager.tokenRefresh(),
    onSuccess: (response: TokenRefreshResponse) => {
      setAccessToken(response.access, null);
    },
  });
}
