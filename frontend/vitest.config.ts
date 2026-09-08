import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["../tests/frontend/setup.ts"],
    include: ["../tests/frontend/**/*.test.{ts,tsx}"],
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/**/*.d.ts"],
      // Raised from the ecosystem's standard 85% (see ../django-dynamic-user's own
      // vitest.config.ts) — this app's CLAUDE.md sets the coverage gate at 90% because this
      // package holds credentials.
      thresholds: {
        lines: 90,
        functions: 90,
        branches: 90,
        statements: 90,
      },
    },
  },
});
