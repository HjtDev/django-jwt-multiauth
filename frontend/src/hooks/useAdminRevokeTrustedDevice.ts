"use client";

import { useMemo } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { JwtMultiauthAdminManager } from "../api/manager.js";
import { useJwtMultiauthAdminConfig } from "../api/config.js";
import { jwtMultiauthAdminKeys } from "./keys.js";

/** `id` is a plain integer. `mutationFn` only ever runs from an explicit `mutate()` call. */
export function useAdminRevokeTrustedDevice() {
  const { client, basePath } = useJwtMultiauthAdminConfig();
  const manager = useMemo(() => new JwtMultiauthAdminManager(client, basePath), [client, basePath]);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: number) => manager.revokeTrustedDevice(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: jwtMultiauthAdminKeys.trustedDevices() });
    },
  });
}
