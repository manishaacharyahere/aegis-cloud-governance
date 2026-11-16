import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// The dev server proxies API calls to the Go API on localhost.
const apiTarget = 'http://127.0.0.1:8080'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    proxy: {
      '/api': apiTarget,
      '/readyz': apiTarget,
      '/healthz': apiTarget,
    },
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
