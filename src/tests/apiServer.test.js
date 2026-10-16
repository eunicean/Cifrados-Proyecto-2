import { afterAll, beforeAll, describe, expect, test, vi } from 'vitest'
import { importApp, startApi, TEST_ENV } from './helpers/apiTestServer.js'

// La API no debe conectarse a Supabase real durante las pruebas
vi.mock('@supabase/supabase-js', async () => (await import('./helpers/supabaseMock.js')).supabaseModule)

describe('API Express — se puede importar sin abrir el puerto', () => {
  let api

  beforeAll(async () => {
    api = await startApi()
  })

  afterAll(async () => {
    await api.close()
    vi.unstubAllEnvs()
  })

  test('rechaza una ruta protegida sin token', async () => {
    const response = await api.request('/groups')

    expect(response.status).toBe(401)
    expect(response.json).toEqual({ message: 'JWT invalido.' })
  })

  test('responde al preflight de CORS con 204', async () => {
    const response = await api.request('/groups', { method: 'OPTIONS' })

    expect(response.status).toBe(204)
  })
})

describe('API Express — arranque del servidor', () => {
  afterAll(() => {
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
  })

  test('sale con codigo 1 si no puede abrir el puerto', async () => {
    const { handleListen } = await importApp()
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {})
    vi.spyOn(console, 'warn').mockImplementation(() => {})

    handleListen(new Error('EADDRINUSE'))

    expect(exit).toHaveBeenCalledWith(1)
  })

  test('registra el inicio cuando el puerto se abre', async () => {
    const { handleListen } = await importApp()
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})

    handleListen()

    expect(log).toHaveBeenCalledWith(
      expect.stringContaining('API REST escuchando'),
      expect.any(Object),
    )
  })
})
