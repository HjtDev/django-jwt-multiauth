"use client";

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import { jwtMultiauthKeys } from "./keys.js";

/** Wraps `GET /methods/` — unauthenticated discovery, cached server-side per deployment
 * (`appkit.mixins.CachedListMixin`, docs/CONTRACT.md §5). */
export function useAuthMethods() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);

  return useQuery({
    queryKey: jwtMultiauthKeys.methods(),
    queryFn: () => manager.authMethods(),
  });
}
