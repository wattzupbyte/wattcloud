import js from '@eslint/js';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';
import sveltePlugin from 'eslint-plugin-svelte';
import svelteParser from 'svelte-eslint-parser';
import globals from 'globals';

const sharedRules = {
  'no-unused-vars': 'off',
  'no-undef': 'off',
  'no-empty': 'off',
  'no-console': 'off',
  'no-useless-escape': 'off',
  'no-constant-condition': 'off',
  'prefer-const': 'warn',
  '@typescript-eslint/no-unused-vars': [
    'warn',
    { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
  ],
  '@typescript-eslint/no-explicit-any': 'off',
  '@typescript-eslint/no-empty-function': 'off',
  '@typescript-eslint/no-non-null-assertion': 'off',
  '@typescript-eslint/no-this-alias': 'off',
  '@typescript-eslint/no-inferrable-types': 'off',
  '@typescript-eslint/no-unused-expressions': 'off',
};

const sharedGlobals = {
  ...globals.browser,
  ...globals.node,
  ...globals.worker,
};

export default [
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      '**/*.config.js',
      '**/*.config.ts',
      'src/pkg/**',
      'public/**',
      'tests/**',
    ],
  },
  js.configs.recommended,
  ...sveltePlugin.configs['flat/recommended'],
  {
    files: ['**/*.{ts,js,mjs,cjs}'],
    languageOptions: {
      parser: tsParser,
      parserOptions: { ecmaVersion: 'latest', sourceType: 'module' },
      globals: sharedGlobals,
    },
    plugins: { '@typescript-eslint': tsPlugin },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      ...sharedRules,
    },
  },
  {
    files: ['**/*.svelte'],
    languageOptions: {
      parser: svelteParser,
      parserOptions: {
        parser: tsParser,
        ecmaVersion: 'latest',
        sourceType: 'module',
        extraFileExtensions: ['.svelte'],
      },
      globals: sharedGlobals,
    },
    plugins: { '@typescript-eslint': tsPlugin },
    rules: {
      ...sharedRules,
      // Svelte 5 props destructuring uses `let` — prefer-const fires
      // constantly on patterns like `let { foo } = $props()`. Off in
      // .svelte to match the legacy .eslintrc override.
      'prefer-const': 'off',
      'svelte/no-at-html-tags': 'error',
      // Demote v3-default-error rules that catalogue style violations,
      // not bugs. Mirrors the legacy .eslintrc 'warn' severity for
      // svelte/no-unused-svelte-ignore. require-each-key surfaces a real
      // perf concern; keep it visible as a warning.
      'svelte/no-unused-svelte-ignore': 'warn',
      'svelte/require-each-key': 'warn',
      'svelte/prefer-writable-derived': 'warn',
      // New in eslint-plugin-svelte 3: stricter Svelte-5-runes rules that
      // fight existing patterns in this codebase. Treat as off until we
      // do a focused pass to adopt them.
      'svelte/no-useless-mustaches': 'off',
      'svelte/prefer-svelte-reactivity': 'off',
    },
  },
];
