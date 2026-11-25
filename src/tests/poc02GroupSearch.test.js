// H4 · PoC-02: la busqueda de grupos revelaba chats privados (CWE-200, RS-05).
// Reproduce las peticiones del PoC (?name=direct y ?name=%) y comprueba que ya no exponen nada.
import { afterAll, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest'
import { startApi } from './helpers/apiTestServer.js'
import { db } from './helpers/supabaseMock.js'

vi.mock('@supabase/supabase-js', async () => (await import('./helpers/supabaseMock.js')).supabaseModule)

vi.mock('../blockchain/blockchainService.js', () => ({
  registerMessageTransaction: vi.fn(),
  getFullBlockchain: vi.fn(async () => []),
  verifyFullBlockchain: vi.fn(async () => ({ valid: true })),
  tamperBlockForDemo: vi.fn(),
  resetBlockchainForDemo: vi.fn(),
}))

let api

beforeAll(async () => {
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  api = await startApi()
})

afterAll(async () => {
  await api.close()
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

beforeEach(() => {
  db.reset()
})

const search = (query, user = 'u1') =>
  api.request(`/groups/search?name=${query}`, { token: api.tokenFor(user) })

// Llamadas que la ruta hizo a la tabla channels con un metodo dado
const channelCalls = (method) =>
  db.calls.filter((call) => call.table === 'channels' && call.method === method)

describe('PoC-02 · busqueda de grupos', () => {
  // %25 = "%", %3A = ":"; "*" es comodin en PostgREST; "ab" es demasiado corto
  test.each(['%25', '%25%25%25', 'a%3Ab', 'abc*', 'ab'])(
    'rechaza ?name=%s sin consultar la base de datos',
    async (query) => {
      const response = await search(query)

      expect(response.status).toBe(400)
      expect(db.calls.filter((call) => call.table === 'channels')).toHaveLength(0)
    },
  )

  test('?name=direct excluye los canales direct: en la consulta', async () => {
    db.queue = [{ data: [] }]

    const response = await search('direct')

    expect(response.status).toBe(200)
    expect(channelCalls('not')[0].args).toEqual(['name', 'like', 'direct:%'])
  })

  test('el guion bajo se busca como texto, no como comodin', async () => {
    db.queue = [{ data: [] }]

    await search('Gru_po')

    expect(channelCalls('ilike')[0].args).toEqual(['name', '%Gru\\_po%'])
  })

  test('acepta nombres legitimos con signos basicos', async () => {
    db.queue = [{ data: [] }]

    const response = await search(encodeURIComponent("Proyecto (Fase 3) - O'Brien"))

    expect(response.status).toBe(200)
  })

  test('no revela quien creo un grupo ajeno, pero si el propio', async () => {
    db.queue = [
      {
        data: [
          { id: 'g1', name: 'Grupo ajeno', created_at: '2026-11-01', created_by: 'u9' },
          { id: 'g2', name: 'Grupo propio', created_at: '2026-11-02', created_by: 'u1' },
        ],
      },
      { data: [] },
    ]

    const response = await search('Grupo')

    expect(response.json.groups).toEqual([
      { id: 'g1', name: 'Grupo ajeno', created_at: '2026-11-01', created_by: null, is_member: false },
      { id: 'g2', name: 'Grupo propio', created_at: '2026-11-02', created_by: 'u1', is_member: false },
    ])
  })
})