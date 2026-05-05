import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],

  test: {
    environment: 'node',
    setupFiles: './src/tests/setupTests.js',
    globals: true,
  },
})