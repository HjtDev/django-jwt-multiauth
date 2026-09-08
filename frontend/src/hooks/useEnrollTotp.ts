"use client";

import { useMemo } from "react";
import { useMutation } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";

/** Wraps `POST /2fa/totp/enroll/` — the ONE moment the plaintext TOTP secret is ever returned;
 * rendering the `otpauth_uri` as a QR code is the host's job, not this SDK's
 * (docs/APP-DESIGN.md's scope boundary). */
export function useEnrollTotp() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);

  return useMutation({
    mutationFn: () => manager.enrollTotp(),
  });
}
