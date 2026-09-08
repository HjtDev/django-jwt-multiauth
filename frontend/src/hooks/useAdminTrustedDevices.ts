"use client";

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { JwtMultiauthAdminManager } from "../api/manager.js";
import { useJwtMultiauthAdminConfig } from "../api/config.js";
import { jwtMultiauthAdminKeys } from "./keys.js";
import type { AdminTrustedDevicesParams } from "../types.js";

export function useAdminTrustedDevices(params?: AdminTrustedDevicesParams) {
  const { client, basePath } = useJwtMultiauthAdminConfig();
  const manager = useMemo(() => new JwtMultiauthAdminManager(client, basePath), [client, basePath]);

  return useQuery({
    queryKey: jwtMultiauthAdminKeys.trustedDevices(params),
    queryFn: () => manager.trustedDevices(params),
  });
}
