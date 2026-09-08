"use client";

import { useMemo } from "react";
import { useMutation } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import type { TokenVerifyInput } from "../types.js";

/** Wraps `POST /token/verify/` — docs/CONTRACT.md §5 frames this as service-to-service ("lets
 * another service validate a token it received"), so a typical host UI has little use for it;
 * exposed for completeness. Never 401s — a bad token resolves `{valid: false}`, not an error. */
export function useVerifyToken() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);

  return useMutation({
    mutationFn: (data: TokenVerifyInput) => manager.tokenVerify(data),
  });
}
