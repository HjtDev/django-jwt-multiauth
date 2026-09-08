"use client";

import { useMemo } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { JwtMultiauthAdminManager } from "../api/manager.js";
import { useJwtMultiauthAdminConfig } from "../api/config.js";
import { jwtMultiauthAdminKeys } from "./keys.js";

/** `id` is a UUID string. `mutationFn` only ever runs from an explicit `mutate()` call. */
export function useAdminRevokeSession() {
  const { client, basePath } = useJwtMultiauthAdminConfig();
  const manager = useMemo(() => new JwtMultiauthAdminManager(client, basePath), [client, basePath]);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => manager.revokeSession(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: jwtMultiauthAdminKeys.sessions() });
    },
  });
}
