"use client";

import { useMemo } from "react";
import { useMutation } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import { setAccessToken } from "../authStore.js";
import type { LoginInput, LoginResponse } from "../types.js";

/**
 * Wraps `POST /login/`. On a token-bearing success (the `access` branch of
 * {@link LoginResponse}), calls `authStore.setAccessToken` as a side effect before resolving —
 * this is one of the few places outside the token-manager trio that ever touches the access
 * token directly (docs/CONTRACT.md §7). The 2FA-pending branch (`pending_token`) is left
 * untouched — the caller drives `useVerifyTwoFactor` next.
 */
export function useLogin() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);

  return useMutation({
    mutationFn: (data: LoginInput) => manager.login(data),
    onSuccess: (response: LoginResponse) => {
      if ("access" in response) {
        setAccessToken(response.access, null);
      }
    },
  });
}
