import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

/// Vitest configuration for the Patch Manager UI.
///
/// - Uses jsdom for a browser-like environment (needed for MUI + React
///   Testing Library).
/// - The `react()` plugin is required for JSX in test files.
/// - `globals: true` lets tests use `describe`, `it`, `expect` without
///   imports (matches the existing frontend conventions).
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
  },
})
