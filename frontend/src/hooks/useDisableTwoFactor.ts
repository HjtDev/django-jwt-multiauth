"use client";

import { useMemo } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import { jwtMultiauthKeys } from "./keys.js";
import type { TwoFactorDisableInput } from "../types.js";

/** Wraps `POST /2fa/disable/` — requires password re-entry regardless of which method is being
 * disabled (docs/CONTRACT.md §5). `mutationFn` only ever runs from an explicit `mutate()` call —
 * see tests/frontend/mutations-do-not-fire-on-mount.test.tsx. */
export function useDisableTwoFactor() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: TwoFactorDisableInput) => manager.disableTwoFactor(data),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: jwtMultiauthKeys.twoFactorStatus() });
    },
  });
}
