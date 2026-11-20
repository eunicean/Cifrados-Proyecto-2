// H4 · PoC-01: GET /api/users exponia el nombre, correo y llave de TODOS los usuarios
// (A01:2025 Broken Access Control, CWE-359). Estas pruebas comprueban que ahora solo
// se devuelven los usuarios con los que se comparte un canal.
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

const listUsers = (user = 'u1') =>
  api.request('/users', { token: api.tokenFor(user) })

describe('PoC-01 · GET /users', () => {
  test('exige autenticacion', async () => {
    const response = await api.request('/users')

    expect(response.status).toBe(401)
  })

  test('solo devuelve a los usuarios con los que se comparte un canal', async () => {
    db.queue = [
      // mis membresias
      { data: [{ channel_id: 'c1' }] },
      // miembros de esos canales: yo (u1) y un contacto (u2)
      { data: [{ user_id: 'u1' }, { user_id: 'u2' }] },
      // la tabla user, filtrada por los ids de contacto
      { data: [{ id: 'u2', name: 'Bob', email: 'bob@example.com', key: 'K' }] },
    ]

    const response = await listUsers('u1')

    expect(response.status).toBe(200)
    expect(response.json.users).toHaveLength(1)
    expect(response.json.users[0].id).toBe('u2')

    // La consulta a user filtra por los ids de contacto (sin incluirme a mi)
    const userQuery = db.calls.find((call) => call.table === 'user' && call.method === 'in')
    expect(userQuery.args).toEqual(['id', ['u2']])
  })

  test('sin canales compartidos no lista a nadie ni consulta la tabla user', async () => {
    db.queue = [{ data: [] }] // sin membresias

    const response = await listUsers('u1')

    expect(response.status).toBe(200)
    expect(response.json.users).toEqual([])
    expect(db.calls.some((call) => call.table === 'user')).toBe(false)
  })
})
