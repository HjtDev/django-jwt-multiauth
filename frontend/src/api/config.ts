"use client";

// Internal — never exported from src/index.ts. Every real app SDK's api/config.ts follows this
// exact shape: a thin call to appkit's useApiClient(key, defaultBasePath), never anything
// host-specific. This app registers TWO surfaces, each with its own namespace key and default
// basePath (docs/CONTRACT.md §0) — a host must add both entries to its own `basePaths` map.
import { useApiClient } from "@hjtdev/appkit";

export const useJwtMultiauthConfig = () => useApiClient("jwt_multiauth", "/api/v1/auth");

export const useJwtMultiauthAdminConfig = () =>
  useApiClient("jwt_multiauth_admin", "/api/v1/admin/auth");
