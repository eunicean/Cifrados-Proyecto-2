import { afterAll, beforeAll, describe, expect, test, vi } from 'vitest'

// La API no debe conectarse a Supabase real durante las pruebas
vi.mock('@supabase/supabase-js', () => ({
  createClient: vi.fn(() => ({ from: vi.fn() })),
}))

const TEST_ENV = {
  JWT_SECRET: 'x'.repeat(32),
  SUPABASE_URL: 'http://supabase.test',
  SUPABASE_SERVICE_ROLE_KEY: 'test-service-role-key',
}

async function importApp(env = TEST_ENV) {
  vi.resetModules()
  Object.entries(env).forEach(([key, value]) => vi.stubEnv(key, value))

  const { default: app } = await import('../../app.js')
  return app
}

describe('API Express — se puede importar sin abrir el puerto', () => {
  let server
  let baseUrl

  beforeAll(async () => {
    const app = await importApp()

    await new Promise((resolve) => {
      server = app.listen(0, resolve)
    })

    baseUrl = `http://127.0.0.1:${server.address().port}`
  })

  afterAll(() => {
    server?.close()
    vi.unstubAllEnvs()
  })

  test('rechaza una ruta protegida sin token', async () => {
    const response = await fetch(`${baseUrl}/groups`)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ message: 'JWT invalido.' })
  })

  test('responde al preflight de CORS con 204', async () => {
    const response = await fetch(`${baseUrl}/groups`, { method: 'OPTIONS' })

    expect(response.status).toBe(204)
  })
})

describe('API Express — configuracion obligatoria', () => {
  afterAll(() => {
    vi.unstubAllEnvs()
  })

  test('no inicia con un JWT_SECRET corto', async () => {
    await expect(
      importApp({ ...TEST_ENV, JWT_SECRET: 'corto' }),
    ).rejects.toThrow('JWT_SECRET debe estar definido')
  })
})
