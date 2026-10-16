import { vi } from 'vitest'
import { issueJwt } from '../../utils/jwt.js'

export const TEST_JWT_SECRET = 'x'.repeat(32)

export const TEST_ENV = {
  JWT_SECRET: TEST_JWT_SECRET,
  SUPABASE_URL: 'http://supabase.test',
  SUPABASE_SERVICE_ROLE_KEY: 'test-service-role-key',
  CLIENT_ORIGIN: 'http://localhost:5173',
  BLOCKCHAIN_ADMIN_IDS: 'admin-1',
}

// Importa app.js desde cero con las variables indicadas (requiere vi.mock de Supabase en el test)
export async function importApp(env = TEST_ENV) {
  vi.resetModules()
  Object.entries(env).forEach(([key, value]) => vi.stubEnv(key, value))

  const module = await import('../../../app.js')
  return module
}

export async function startApi(env = TEST_ENV) {
  const { default: app } = await importApp(env)
  const server = await new Promise((resolve) => {
    const listening = app.listen(0, () => resolve(listening))
  })
  const baseUrl = `http://127.0.0.1:${server.address().port}`

  return {
    baseUrl,
    close: () => new Promise((resolve) => server.close(resolve)),
    tokenFor: (sub, secret = TEST_JWT_SECRET) =>
      issueJwt({ sub, email: `${sub}@example.com`, name: sub }, secret, { expiresIn: '5m' }),
    async request(path, { token, method = 'GET', body, headers = {} } = {}) {
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers: {
          ...(body ? { 'Content-Type': 'application/json' } : {}),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...headers,
        },
        body: body ? JSON.stringify(body) : undefined,
      })
      const text = await response.text()
      let json = null
      try {
        json = JSON.parse(text)
      } catch {
        json = null
      }
      return { status: response.status, headers: response.headers, json }
    },
  }
}
