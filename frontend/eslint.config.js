import js from "@eslint/js";
import jsxA11y from "eslint-plugin-jsx-a11y";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "dist-harness", "node_modules"] },
  { settings: { react: { version: "19.1" } } },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  react.configs.flat.recommended,
  react.configs.flat["jsx-runtime"],
  jsxA11y.flatConfigs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { ecmaVersion: 2022, globals: { ...globals.browser } },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react/no-danger": "error",
      "react/prop-types": "off",
      "no-restricted-syntax": [
        "error",
        {
          selector: "AssignmentExpression[left.property.name=/^(inner|outer)HTML$/]",
          message: "Assigning innerHTML/outerHTML is forbidden; render text through React.",
        },
        {
          selector: "AssignmentExpression[left.computed=true][left.property.value=/^(inner|outer)HTML$/]",
          message: "Assigning innerHTML/outerHTML is forbidden; render text through React.",
        },
        {
          selector:
            "CallExpression[callee.property.name=/^(insertAdjacentHTML|setHTMLUnsafe|parseHTMLUnsafe|createContextualFragment)$/]",
          message: "Raw HTML insertion APIs are forbidden; render text through React.",
        },
        {
          selector: "CallExpression[callee.object.name='document'][callee.property.name=/^write(ln)?$/]",
          message: "document.write/writeln is forbidden; render text through React.",
        },
        {
          selector:
            "CallExpression[callee.object.name='Object'][callee.property.name='assign'] > ObjectExpression > Property:matches([key.name=/^(inner|outer)HTML$/], [key.value=/^(inner|outer)HTML$/])",
          message: "Object.assign of innerHTML/outerHTML is forbidden; render text through React.",
        },
      ],
    },
  },
  {
    files: ["*.config.{js,ts}", "src/test/**", "**/*.test.{ts,tsx}"],
    languageOptions: { globals: { ...globals.node } },
  },
);
