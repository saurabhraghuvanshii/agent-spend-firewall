// @ts-check
import eslint from "@eslint/js";
import prettierConfig from "eslint-config-prettier";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["**/dist/**", "**/coverage/**", "**/node_modules/**", ".claude/**", ".plan/**"],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "no-empty": "error",
    },
  },
  {
    // packages/core keeps Node types out of src: its tsconfig.json covers only non-test src files,
    // so tests and the vitest config are linted against tsconfig.test.json instead.
    files: ["packages/core/src/**/*.test.ts", "packages/core/vitest.config.ts"],
    languageOptions: {
      parserOptions: {
        projectService: false,
        project: "./packages/core/tsconfig.test.json",
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs"],
    ...tseslint.configs.disableTypeChecked,
  },
  prettierConfig,
);
