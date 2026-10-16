import { afterEach, describe, expect, test, vi } from 'vitest'
import { startApi, TEST_ENV } from './helpers/apiTestServer.js'

vi.mock('@supabase/supabase-js', async () => (await import('./helpers/supabaseMock.js')).supabaseModule)

// Hallazgo #16: CORS con Access-Control-Allow-Origin: * cuando faltaba CLIENT_ORIGIN (CWE-942)
describe('#16: politica de CORS', () => {
  let api

  afterEach(async () => {
    await api?.close()
    vi.unstubAllEnvs()
  })

  test('no autoriza a un sitio externo', async () => {
    api = await startApi()

    const { headers } = await api.request('/groups', {
      headers: { Origin: 'https://sitio-malicioso.example' },
    })

    expect(headers.get('access-control-allow-origin')).toBeNull()
  })

  test('autoriza solo al frontend configurado en CLIENT_ORIGIN', async () => {
    api = await startApi({
      ...TEST_ENV,
      CLIENT_ORIGIN: 'https://blu.example, http://localhost:5173',
    })

    const { headers } = await api.request('/groups', {
      headers: { Origin: 'https://blu.example' },
    })

    expect(headers.get('access-control-allow-origin')).toBe('https://blu.example')
    expect(headers.get('vary')).toContain('Origin')
  })

  test('sin CLIENT_ORIGIN no usa el comodin *', async () => {
    api = await startApi({ ...TEST_ENV, CLIENT_ORIGIN: '' })

    const { headers } = await api.request('/groups', {
      headers: { Origin: 'https://sitio-malicioso.example' },
    })

    expect(headers.get('access-control-allow-origin')).not.toBe('*')
    expect(headers.get('access-control-allow-origin')).toBeNull()
  })
})
