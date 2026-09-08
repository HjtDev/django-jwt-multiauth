import { describe, expect, it } from "vitest";
import { renderHook } from "@testing-library/react";
import { createWrapper } from "./helpers.js";
import { useLogout } from "../../frontend/src/hooks/useLogout.js";
import { useLogoutAll } from "../../frontend/src/hooks/useLogoutAll.js";
import { useDisableTwoFactor } from "../../frontend/src/hooks/useDisableTwoFactor.js";
import { useRevokeSession } from "../../frontend/src/hooks/useRevokeSession.js";
import { useRevokeTrustedDevice } from "../../frontend/src/hooks/useRevokeTrustedDevice.js";
import { useRegenerateRecoveryCodes } from "../../frontend/src/hooks/useRegenerateRecoveryCodes.js";
import { useAdminRevokeSession } from "../../frontend/src/hooks/useAdminRevokeSession.js";
import { useAdminRevokeTrustedDevice } from "../../frontend/src/hooks/useAdminRevokeTrustedDevice.js";
import { useAdminUnlockUser } from "../../frontend/src/hooks/useAdminUnlockUser.js";
import { useAdminForceDisableTwoFactor } from "../../frontend/src/hooks/useAdminForceDisableTwoFactor.js";

interface MinimalMutationResult {
  isIdle: boolean;
  isPending: boolean;
}

const MUTATION_HOOKS: Array<[string, () => MinimalMutationResult]> = [
  ["useLogout", useLogout],
  ["useLogoutAll", useLogoutAll],
  ["useDisableTwoFactor", useDisableTwoFactor],
  ["useRevokeSession", useRevokeSession],
  ["useRevokeTrustedDevice", useRevokeTrustedDevice],
  ["useRegenerateRecoveryCodes", useRegenerateRecoveryCodes],
  ["useAdminRevokeSession", useAdminRevokeSession],
  ["useAdminRevokeTrustedDevice", useAdminRevokeTrustedDevice],
  ["useAdminUnlockUser", useAdminUnlockUser],
  ["useAdminForceDisableTwoFactor", useAdminForceDisableTwoFactor],
];

/**
 * Every state-changing mutation hook must stay idle — and fire ZERO network calls — until an
 * explicit `mutate()`/`mutateAsync()` call. No MSW handler is registered for any of these
 * endpoints in this file; setup.ts's `onUnhandledRequest: "error"` means an eager fire on mount
 * would fail the test outright, not merely go unnoticed (docs/APP-DESIGN.md §12's frontend
 * security checklist: "a mutation hook for a destructive or sensitive action never fires on mount
 * or on a passive render").
 */
describe("state-changing mutation hooks never fire on mount", () => {
  it.each(MUTATION_HOOKS)(
    "%s renders idle, with zero network calls, until mutate() is called",
    async (_name, useHook) => {
      const { Wrapper } = createWrapper();
      const { result } = renderHook(() => useHook(), { wrapper: Wrapper });

      // A brief tick — if the hook fired eagerly, the unhandled-request error would already
      // have surfaced by now.
      await new Promise((resolve) => setTimeout(resolve, 10));

      expect(result.current.isIdle).toBe(true);
      expect(result.current.isPending).toBe(false);
    },
  );
});
