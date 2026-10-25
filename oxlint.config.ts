import { defineConfig } from "oxlint";

export default defineConfig({
  env: {
    browser: true,
    builtin: true,
    node: true,
  },
  ignorePatterns: ["**/dist/**", "helper/**", "service/**", "spec/**"],
  plugins: ["typescript", "unicorn", "oxc"],
  categories: {
    correctness: "error",
  },
  overrides: [
    {
      // @keyseal/server runs on any Fetch runtime: Web APIs only.
      files: ["packages/server/src/**"],
      rules: {
        "no-restricted-globals": [
          "error",
          {
            name: "Buffer",
            message: "Use Uint8Array and the helpers in encoding.ts.",
          },
          { name: "process", message: "Take configuration through options." },
        ],
      },
    },
  ],
});
