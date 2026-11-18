import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The dev server proxies API calls to the Go API on localhost.
const apiTarget = 'http://127.0.0.1:8080'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': '/src' }, // root-relative: '@/x' -> <root>/src/x
  },
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
