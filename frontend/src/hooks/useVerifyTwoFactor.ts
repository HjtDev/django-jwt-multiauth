"use client";

import { useMemo } from "react";
import { useMutation } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import { setAccessToken } from "../authStore.js";
import type { TwoFactorVerifyInput, TwoFactorVerifyResponse } from "../types.js";

/** Wraps `POST /2fa/verify/`. Always token-bearing on success (unlike `useLogin`/`useOtpVerify`,
 * there is no pending-again branch) — calls `authStore.setAccessToken` unconditionally. */
export function useVerifyTwoFactor() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);

  return useMutation({
    mutationFn: (data: TwoFactorVerifyInput) => manager.verifyTwoFactor(data),
    onSuccess: (response: TwoFactorVerifyResponse) => {
      setAccessToken(response.access, null);
    },
  });
}
