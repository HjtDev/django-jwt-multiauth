"use client";

import { useMemo } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { JwtMultiauthAdminManager } from "../api/manager.js";
import { useJwtMultiauthAdminConfig } from "../api/config.js";
import { jwtMultiauthAdminKeys } from "./keys.js";

/** Wraps `POST /admin/users/{id}/2fa/force-disable/` — always superuser-gated server-side,
 * unconditionally, never loosened by `ADMIN_REQUIRES_SUPERUSER` (docs/CONTRACT.md §5). An
 * irreversible privilege action; `mutationFn` only ever runs from an explicit `mutate()` call —
 * see tests/frontend/mutations-do-not-fire-on-mount.test.tsx. */
export function useAdminForceDisableTwoFactor() {
  const { client, basePath } = useJwtMultiauthAdminConfig();
  const manager = useMemo(() => new JwtMultiauthAdminManager(client, basePath), [client, basePath]);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (userId: number) => manager.forceDisableTwoFactor(userId),
    onSuccess: (_data, userId) => {
      void queryClient.invalidateQueries({ queryKey: jwtMultiauthAdminKeys.userSecurity(userId) });
    },
  });
}
