"use client";

import { useMemo } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import { clear } from "../authStore.js";
import { jwtMultiauthKeys } from "./keys.js";

/** Wraps `POST /logout/all/`. Same `authStore.clear()` + `"logged-out"` broadcast as `useLogout`
 * — revoking every session (including the caller's own current one) makes the local token dead
 * regardless of which session id it belonged to. */
export function useLogoutAll() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: () => manager.logoutAll(),
    onSuccess: () => {
      clear();
      void queryClient.invalidateQueries({ queryKey: jwtMultiauthKeys.sessions() });
    },
  });
}
