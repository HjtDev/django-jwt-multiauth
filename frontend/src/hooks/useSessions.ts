"use client";

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import { jwtMultiauthKeys } from "./keys.js";
import type { SessionsParams } from "../types.js";

export function useSessions(params?: SessionsParams) {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);

  return useQuery({
    queryKey: jwtMultiauthKeys.sessions(params),
    queryFn: () => manager.sessions(params),
  });
}
