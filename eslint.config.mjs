import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import prettierConfig from "eslint-config-prettier";

// Lives at the repo root, not frontend/, because ESLint 9's flat config treats any file outside
// the directory containing the config as ignored by default — and tests/frontend/ (this repo's
// shared test tree, outside frontend/ itself, same layout as ../appkit and ../django-dynamic-user)
// needs linting too. frontend/package.json's `lint` script points here via `cd .. && eslint
// frontend/src tests/frontend`.
//
// No eslint-config-next here — this package ships no Next.js code of its own, only the hooks a
// Next.js (or any React) host consumes. react-hooks catches the memoisation footguns the
// manager/hook conventions call out (a stale dependency array in a hook's useMemo) — load-bearing
// here, since authHeaderSource/withAuthRetry/authStore run outside React and a memoisation bug in
// a hook wrapping them would be easy to miss without this.
// prettierConfig goes last so formatting rules never fight Prettier — Prettier owns formatting,
// ESLint owns everything else, matching appkit's own split.
export default tseslint.config(
  {
    ignores: ["frontend/dist/**", "**/node_modules/**", "**/coverage/**", "backend/**", "docs/**"],
  },
  ...tseslint.configs.recommended,
  {
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // An underscore-prefixed parameter names an intentionally-unused argument (an interface
      // slot a stub/mock must declare to match a signature but doesn't need) — used in
      // tests/frontend/'s stub HttpClient implementation.
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    },
  },
  prettierConfig,
);
