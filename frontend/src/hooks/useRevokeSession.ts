"use client";

import { useMemo } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import { jwtMultiauthKeys } from "./keys.js";

/** Wraps `DELETE /sessions/{id}/`. `id` is a UUID string, not a number — see
 * `JwtMultiauthManager.revokeSession`'s own doc comment. `mutationFn` only ever runs from an
 * explicit `mutate()` call. */
export function useRevokeSession() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => manager.revokeSession(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: jwtMultiauthKeys.sessions() });
    },
  });
}
