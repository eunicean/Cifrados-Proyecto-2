import { afterAll, beforeAll, describe, expect, test, vi } from 'vitest'
import { startApi } from './helpers/apiTestServer.js'

vi.mock('@supabase/supabase-js', async () => (await import('./helpers/supabaseMock.js')).supabaseModule)

// Hallazgos #1 (X-Powered-By, CWE-497) y #6/#11 en la API (clickjacking CWE-1021, nosniff CWE-693)
describe('Encabezados de seguridad de la API', () => {
  let api

  beforeAll(async () => {
    api = await startApi()
  })

  afterAll(async () => {
    await api.close()
    vi.unstubAllEnvs()
  })

  test('#1: no revela el framework en X-Powered-By', async () => {
    const { headers } = await api.request('/auth/login', {
      method: 'POST',
      body: { email: '', password: '' },
    })

    expect(headers.get('x-powered-by')).toBeNull()
  })

  test('#6: impide que la API se cargue dentro de un iframe', async () => {
    const { headers } = await api.request('/groups')

    expect(headers.get('x-frame-options')).toBe('DENY')
    expect(headers.get('content-security-policy')).toContain("frame-ancestors 'none'")
  })

  test('#11: desactiva el MIME sniffing', async () => {
    const { headers } = await api.request('/groups')

    expect(headers.get('x-content-type-options')).toBe('nosniff')
  })
})
