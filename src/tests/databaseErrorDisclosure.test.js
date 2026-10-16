import { afterAll, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest'
import { startApi } from './helpers/apiTestServer.js'
import { db, dbFailure } from './helpers/supabaseMock.js'

vi.mock('@supabase/supabase-js', async () => (await import('./helpers/supabaseMock.js')).supabaseModule)

vi.mock('../blockchain/blockchainService.js', () => ({
  registerMessageTransaction: vi.fn(async () => ({ index: 1, hash: 'b'.repeat(64) })),
  getFullBlockchain: vi.fn(async () => []),
  verifyFullBlockchain: vi.fn(async () => ({ valid: true })),
  tamperBlockForDemo: vi.fn(),
  resetBlockchainForDemo: vi.fn(),
}))

const routes = [
  ['POST', '/groups', { name: 'Grupo de prueba' }],
  ['GET', '/groups'],
  ['GET', '/direct-conversations'],
  ['POST', '/direct-conversations', { recipient_id: 'u2' }],
  ['GET', '/groups/search?name=Gru'],
  ['POST', '/groups/c1/join', { code: 'CODIGO01' }],
  ['GET', '/groups/c1/messages'],
  ['GET', '/groups/c1/members/keys'],
  [
    'POST',
    '/messages',
    {
      channel_id: 'c1',
      ciphertext_base64: 'Y2lwaGVy',
      nonce_base64: 'bm9uY2U=',
      auth_tag_base64: 'dGFn',
      encrypted_keys: [{ encrypted_key_base64: 'a2V5' }],
    },
  ],
  ['GET', '/messages/u1'],
  ['GET', '/users'],
]

// Hallazgo #15: la API devolvia al cliente el mensaje interno de Supabase (CWE-209)
describe('#15: los errores de base de datos no se filtran al cliente', () => {
  let api
  let token

  beforeAll(async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    api = await startApi()
    token = api.tokenFor('u1')
  })

  afterAll(async () => {
    await api.close()
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
  })

  beforeEach(() => {
    db.reset()
  })

  test.each(routes)('%s %s', async (method, path, body) => {
    let failures = 0

    // Hace fallar la 1.a consulta, luego la 2.a, etc., hasta que la ruta ya no consulta mas
    for (let okQueries = 0; okQueries < 12; okQueries += 1) {
      db.reset()
      db.queue = [...Array(okQueries).fill({}), dbFailure()]

      const response = await api.request(path, { method, body, token })

      if (db.queue.length > 0) break

      expect(JSON.stringify(response.json)).not.toContain('SECRETO_INTERNO')

      // Algunas consultas secundarias ignoran el error y la ruta responde 200
      if (response.status >= 400) {
        failures += 1
        expect(response.json.message).toBe('No se pudo completar la operacion.')
      }
    }

    expect(failures).toBeGreaterThan(0)
  })

  test('el detalle interno se conserva en el log del servidor', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    db.queue = [dbFailure()]

    await api.request('/groups', { token })

    expect(JSON.stringify(warn.mock.calls)).toContain('SECRETO_INTERNO')
  })
})
