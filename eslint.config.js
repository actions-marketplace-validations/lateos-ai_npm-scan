import js from '@eslint/js';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';

export default [
  {
    ignores: [
      'node_modules/',
      'dist/',
      'coverage/',
      '.git/',
      '.github/',
      'fixtures/campaigns/',
      'fixtures/**/*.json',
      'tests/corpus/',
      'tests/corpus/**',
    ],
  },
  js.configs.recommended,
  eslintPluginPrettierRecommended,
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        process: 'readonly',
        Buffer: 'readonly',
        console: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        fetch: 'readonly',
        Response: 'readonly',
        Headers: 'readonly',
        TextDecoder: 'readonly',
        AbortSignal: 'readonly',
        URL: 'readonly',
        atob: 'readonly',
        btoa: 'readonly',
        global: 'readonly',
      },
    },
    rules: {
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-console': ['warn', { allow: ['error', 'warn', 'info'] }],
      eqeqeq: ['error', 'always'],
      curly: ['error', 'multi-line'],
      'no-var': 'error',
      'prefer-const': 'error',
      'no-async-promise-executor': 'error',
      'require-await': 'warn',
      'no-return-await': 'warn',
      'no-undef': 'error',
    },
  },
  {
    files: ['**/*.test.js', '**/*.spec.js', 'test/**', 'tests/**'],
    rules: {
      'no-console': 'off',
      'require-await': 'off',
    },
  },
  {
    files: ['**/scripts/**'],
    rules: {
      'no-console': 'off',
      'require-await': 'off',
    },
  },
];
