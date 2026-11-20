// H4 · PoC-04: fuerza bruta del codigo de grupo (CWE-307).
// Reproduce el PoC del Red Team (codigos incorrectos seguidos) y comprueba que se corta.
import { afterAll, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest'
import { startApi } from './helpers/apiTestServer.js'
import { db, dbFailure } from './helpers/supabaseMock.js'

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

const join = (user, groupId, code) =>
  api.request(`/groups/${groupId}/join`, {
    method: 'POST',
    token: api.tokenFor(user),
    body: { code },
  })

describe('PoC-04 · fuerza bruta del codigo de grupo', () => {
  test('el intento 11 recibe 429, aunque traiga el codigo correcto', async () => {
    // Igual que el PoC: codigos incorrectos seguidos con la misma cuenta
    for (let attempt = 1; attempt <= 10; attempt += 1) {
      const response = await join('atacante', 'c1', `MALO${String(attempt).padStart(4, '0')}`)
      expect(response.status).toBe(400)
    }

    const blocked = await join('atacante', 'c1', 'CODIGO01')
    expect(blocked.status).toBe(429)
  })

  test('el bloqueo es por usuario: otra cuenta con el codigo correcto se une', async () => {
    db.queue = [{}, { data: null }, {}] // grupo, "no es miembro", insercion

    const response = await join('legitimo', 'c1', 'CODIGO01')

    expect(response.status).toBe(200)
    expect(response.json.joined).toBe(true)
  })

  test('un grupo inexistente responde igual que un codigo incorrecto', async () => {
    db.queue = [{ data: null }]

    const response = await join('sondeo', 'no-existe', 'CODIGO01')

    expect(response.status).toBe(400)
    expect(response.json.message).toBe('Código de grupo incorrecto.')
  })

  test('los errores de la base de datos no cuentan como intentos', async () => {
    for (let attempt = 1; attempt <= 12; attempt += 1) {
      db.queue = [dbFailure()]
      const response = await join('mala-red', 'c1', 'CODIGO01')
      expect(response.status).not.toBe(429)
    }
  })
})