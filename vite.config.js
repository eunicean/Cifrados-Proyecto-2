import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export function buildCsp(apiUrl) {
  return [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    `connect-src 'self' ${new URL(apiUrl).origin} https://*.supabase.co wss://*.supabase.co`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ')
}

// Encabezados HTTP de seguridad (hallazgos #6, #7 y #11 de ZAP).
// frame-ancestors solo funciona como encabezado, no dentro de <meta>.
export function securityHeaders(csp) {
  return {
    'Content-Security-Policy': `${csp}; frame-ancestors 'none'`,
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  }
}

function cspPlugin(csp) {
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
  const apiUrl = env.VITE_API_URL || 'https://cifrados-proyecto-2-1.onrender.com'
  const csp = buildCsp(apiUrl)

  return {
    plugins: [react(), cspPlugin(csp)],

    // `vite preview` sirve el build de produccion con la CSP completa.
    preview: { headers: securityHeaders(csp) },

    // El servidor de desarrollo usa un script inline de React Refresh, asi que
    // aqui solo se bloquea el iframe; la CSP completa aplica al build.
    server: {
      headers: {
        'Content-Security-Policy': "frame-ancestors 'none'",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
      },
    },

    test: {
      environment: 'node',
      setupFiles: './src/tests/setupTests.js',
      globals: true,
      coverage: {
        provider: 'v8',
        reporter: ['text', 'lcov'],
        reportsDirectory: './coverage',
        // Cuenta todo el codigo fuente, aunque un archivo no tenga pruebas
        include: ['app.js', 'src/**/*.{js,jsx}'],
        exclude: ['src/tests/**'],
      },
    },
  }
})
