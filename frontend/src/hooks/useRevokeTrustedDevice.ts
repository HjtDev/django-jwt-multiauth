"use client";

import { useMemo } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import { jwtMultiauthKeys } from "./keys.js";

/** Wraps `DELETE /trusted-devices/{id}/`. `id` is a plain integer — see
 * `JwtMultiauthManager.revokeTrustedDevice`'s own doc comment. `mutationFn` only ever runs from
 * an explicit `mutate()` call. */
export function useRevokeTrustedDevice() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: number) => manager.revokeTrustedDevice(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: jwtMultiauthKeys.trustedDevices() });
    },
  });
}
