"use client";

import { useMemo } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { JwtMultiauthManager } from "../api/manager.js";
import { useJwtMultiauthConfig } from "../api/config.js";
import { jwtMultiauthKeys } from "./keys.js";
import type { TotpConfirmInput } from "../types.js";

export function useConfirmTotp() {
  const { client, basePath } = useJwtMultiauthConfig();
  const manager = useMemo(() => new JwtMultiauthManager(client, basePath), [client, basePath]);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: TotpConfirmInput) => manager.confirmTotp(data),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: jwtMultiauthKeys.twoFactorStatus() });
    },
  });
}
