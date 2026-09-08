"use client";

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { JwtMultiauthAdminManager } from "../api/manager.js";
import { useJwtMultiauthAdminConfig } from "../api/config.js";
import { jwtMultiauthAdminKeys } from "./keys.js";
import type { AdminLoginAttemptsParams } from "../types.js";

export function useAdminLoginAttempts(params?: AdminLoginAttemptsParams) {
  const { client, basePath } = useJwtMultiauthAdminConfig();
  const manager = useMemo(() => new JwtMultiauthAdminManager(client, basePath), [client, basePath]);

  return useQuery({
    queryKey: jwtMultiauthAdminKeys.loginAttempts(params),
    queryFn: () => manager.loginAttempts(params),
  });
}
