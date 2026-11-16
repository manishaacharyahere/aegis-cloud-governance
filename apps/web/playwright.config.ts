import { defineConfig } from '@playwright/test'

// End-to-end journeys against a running stack (see e2e/README.md):
// API in OIDC mode, Dex, the IaC worker and `npm run dev`.
export default defineConfig({
  testDir: 'e2e',
  timeout: 240_000,
  workers: 1,
  fullyParallel: false,
  reporter: [['list']],
  use: {
    baseURL: process.env.AEGIS_WEB_URL ?? 'http://127.0.0.1:5173',
    viewport: { width: 1440, height: 900 },
    video: process.env.AEGIS_E2E_VIDEO ? 'on' : 'off',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
})
