"use client";

import { useMemo } from "react";
import { useMutation } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import type { TwoFactorOtpRequestInput } from "../types.js";

/**
 * Wraps `POST /2fa/otp/request/` — not in docs/CONTRACT.md §7's frozen hook table, added in
 * Phase 10 (§11 deviation) because without it `email_otp`/`phone_otp` as a SECOND factor is
 * unreachable: `useVerifyTwoFactor` needs a `challenge_id` only this endpoint issues. Call this
 * first when `useTwoFactorStatus`'s `eligible_methods` names an OTP-based method, then pass the
 * returned `challenge_id` into `useVerifyTwoFactor`.
 */
export function useRequestTwoFactorOtp() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);

  return useMutation({
    mutationFn: (data: TwoFactorOtpRequestInput) => manager.requestTwoFactorOtp(data),
  });
}
