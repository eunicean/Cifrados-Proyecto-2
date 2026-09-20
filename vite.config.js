import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

function cspPlugin(apiUrl) {
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    `connect-src 'self' ${new URL(apiUrl).origin} https://*.supabase.co wss://*.supabase.co`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ')

  return {
    name: 'inject-csp',
    apply: 'build',
    transformIndexHtml() {
      return [
        {
          tag: 'meta',
          attrs: { 'http-equiv': 'Content-Security-Policy', content: csp },
          injectTo: 'head-prepend',
        },
      ]
    },
  }
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_')
  const apiUrl = env.VITE_API_URL || 'https://cifrados-proyecto-2.onrender.com'

  return {
    plugins: [react(), cspPlugin(apiUrl)],

    test: {
      environment: 'node',
      setupFiles: './src/tests/setupTests.js',
      globals: true,
    },
  }
})
