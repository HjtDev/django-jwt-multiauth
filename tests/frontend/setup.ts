import "@testing-library/jest-dom/vitest";
import { afterAll, afterEach, beforeAll, beforeEach, expect, vi } from "vitest";
import { setupServer } from "msw/node";

// Mock the HTTP layer, never a live backend, and fail loudly on any request nobody set up a
// handler for rather than silently letting it through — mirrors ../../../appkit's and
// ../../../django-dynamic-user's own tests/frontend/setup.ts (docs/APP-DESIGN.md §7.7).
export const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// Suite-wide proof that this package never touches localStorage/sessionStorage
// (docs/APP-DESIGN.md §12's frontend security checklist, CLAUDE.md rule 4's "no secret stored
// recoverably" carried into the frontend half). Spying here, not just in one dedicated test
// file, is what makes the guarantee suite-wide rather than local to whichever file remembered to
// check — see tests/frontend/no-web-storage.test.ts for the actual assertions.
export const localStorageSpies = {
  getItem: vi.spyOn(Storage.prototype, "getItem"),
  setItem: vi.spyOn(Storage.prototype, "setItem"),
  removeItem: vi.spyOn(Storage.prototype, "removeItem"),
};

beforeEach(() => {
  localStorageSpies.getItem.mockClear();
  localStorageSpies.setItem.mockClear();
  localStorageSpies.removeItem.mockClear();
});

// The actual suite-wide guarantee: every test in every file, not just a dedicated one, fails
// immediately if anything in this package touched Web Storage.
afterEach(() => {
  expect(localStorageSpies.getItem).not.toHaveBeenCalled();
  expect(localStorageSpies.setItem).not.toHaveBeenCalled();
  expect(localStorageSpies.removeItem).not.toHaveBeenCalled();
});
