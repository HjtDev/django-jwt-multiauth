"use client";

import { useMemo } from "react";
import { useMutation } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import { setAccessToken } from "../authStore.js";
import type { OtpVerifyInput, OtpVerifyResponse } from "../types.js";

/**
 * Wraps `POST /otp/verify/`. Same token-bearing side effect as `useLogin` — calls
 * `authStore.setAccessToken` when the response carries `access`. `response.created === true` on
 * this branch means the call just auto-provisioned a new account (docs/CONTRACT.md §11 item 19)
 * — the host UI decides what to do with that (e.g. route to onboarding); this hook doesn't.
 */
export function useOtpVerify() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);

  return useMutation({
    mutationFn: (data: OtpVerifyInput) => manager.otpVerify(data),
    onSuccess: (response: OtpVerifyResponse) => {
      if ("access" in response) {
        setAccessToken(response.access, null);
      }
    },
  });
}
