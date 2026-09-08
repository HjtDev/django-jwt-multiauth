"use client";

import { useMemo } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import { clear } from "../authStore.js";
import { jwtMultiauthKeys } from "./keys.js";

/**
 * Wraps `POST /logout/`. Calls `authStore.clear()` (broadcasting `"logged-out"` to every other
 * open tab) alongside the actual API call, and invalidates this surface's session list.
 * `mutationFn` only ever runs from an explicit `mutate()`/`mutateAsync()` call — see
 * tests/frontend/mutations-do-not-fire-on-mount.test.tsx.
 */
export function useLogout() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: () => manager.logout(),
    onSuccess: () => {
      clear();
      void queryClient.invalidateQueries({ queryKey: jwtMultiauthKeys.sessions() });
    },
  });
}
