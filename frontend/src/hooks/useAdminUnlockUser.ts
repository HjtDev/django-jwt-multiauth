"use client";

import { useMemo } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { JwtMultiauthAdminManager } from "../api/manager.js";
import { useJwtMultiauthAdminConfig } from "../api/config.js";
import { jwtMultiauthAdminKeys } from "./keys.js";

/** `mutationFn` only ever runs from an explicit `mutate()` call. */
export function useAdminUnlockUser() {
  const { client, basePath } = useJwtMultiauthAdminConfig();
  const manager = useMemo(() => new JwtMultiauthAdminManager(client, basePath), [client, basePath]);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (userId: number) => manager.unlockUser(userId),
    onSuccess: (_data, userId) => {
      void queryClient.invalidateQueries({ queryKey: jwtMultiauthAdminKeys.userSecurity(userId) });
    },
  });
}
