import { afterEach, beforeAll, afterAll, describe, expect, test, vi } from 'vitest'
import { importApp, startApi, TEST_ENV } from './helpers/apiTestServer.js'

vi.mock('@supabase/supabase-js', async () => (await import('./helpers/supabaseMock.js')).supabaseModule)

// Hallazgo #12: secreto JWT por defecto en el codigo (CWE-798)
const OLD_DEFAULT_SECRET = 'dev-secret-change-me'

describe('#12: la API no usa un secreto JWT por defecto', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
  })

  test('no inicia si falta JWT_SECRET', async () => {
    await expect(importApp({ ...TEST_ENV, JWT_SECRET: '' })).rejects.toThrow(
      'JWT_SECRET debe estar definido',
    )
  })

  test('no inicia con un JWT_SECRET de menos de 32 caracteres', async () => {
    await expect(importApp({ ...TEST_ENV, JWT_SECRET: 'corto' })).rejects.toThrow(
      'JWT_SECRET debe estar definido',
    )
  })
})

describe('#12: un token firmado con el secreto viejo no sirve', () => {
  let api

  beforeAll(async () => {
    api = await startApi()
  })

  afterAll(async () => {
    await api.close()
    vi.unstubAllEnvs()
  })

  test('rechaza un JWT falsificado con dev-secret-change-me', async () => {
    const forged = api.tokenFor('cualquier-usuario', OLD_DEFAULT_SECRET)

    const response = await api.request('/groups', { token: forged })

    expect(response.status).toBe(401)
  })
})
