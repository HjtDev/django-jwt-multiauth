"use client";

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { JwtMultiauthAdminManager } from "../api/manager.js";
import { useJwtMultiauthAdminConfig } from "../api/config.js";
import { jwtMultiauthAdminKeys } from "./keys.js";
import type { AdminSessionsParams } from "../types.js";

export function useAdminSessions(params?: AdminSessionsParams) {
  const { client, basePath } = useJwtMultiauthAdminConfig();
  const manager = useMemo(() => new JwtMultiauthAdminManager(client, basePath), [client, basePath]);

  return useQuery({
    queryKey: jwtMultiauthAdminKeys.sessions(params),
    queryFn: () => manager.sessions(params),
  });
}
