import { afterAll, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest'
import { startApi } from './helpers/apiTestServer.js'

vi.mock('@supabase/supabase-js', async () => (await import('./helpers/supabaseMock.js')).supabaseModule)

const blockchain = vi.hoisted(() => ({
  tamperBlockForDemo: vi.fn(async (index) => ({ index: Number(index), hash: 'h'.repeat(64) })),
  resetBlockchainForDemo: vi.fn(async () => ({ index: 0, hash: 'g'.repeat(64) })),
  verifyFullBlockchain: vi.fn(async () => ({ valid: true, blocks: 1, invalid_index: null })),
  getFullBlockchain: vi.fn(async () => []),
  registerMessageTransaction: vi.fn(async () => ({ index: 1, hash: 'b'.repeat(64) })),
}))

vi.mock('../blockchain/blockchainService.js', () => blockchain)

// Hallazgo #13: cualquier usuario autenticado podia alterar o reiniciar la blockchain (CWE-862)
describe('#13: operaciones de demo de la blockchain', () => {
  let api

  beforeAll(async () => {
    api = await startApi()
  })

  afterAll(async () => {
    await api.close()
    vi.unstubAllEnvs()
  })

  beforeEach(() => {
    vi.clearAllMocks()
  })

  test('un usuario normal no puede alterar un bloque', async () => {
    const response = await api.request('/blockchain/tamper/1', {
      method: 'POST',
      token: api.tokenFor('usuario-normal'),
    })

    expect(response.status).toBe(403)
    expect(blockchain.tamperBlockForDemo).not.toHaveBeenCalled()
  })

  test('un usuario normal no puede reiniciar la cadena', async () => {
    const response = await api.request('/blockchain/reset', {
      method: 'POST',
      token: api.tokenFor('usuario-normal'),
    })

    expect(response.status).toBe(403)
    expect(blockchain.resetBlockchainForDemo).not.toHaveBeenCalled()
  })

  test('un administrador de la demo si puede alterar y reiniciar', async () => {
    const token = api.tokenFor('admin-1')

    const tamper = await api.request('/blockchain/tamper/1', { method: 'POST', token })
    const reset = await api.request('/blockchain/reset', { method: 'POST', token })

    expect(tamper.status).toBe(200)
    expect(reset.status).toBe(200)
    expect(blockchain.tamperBlockForDemo).toHaveBeenCalledWith('1')
  })

  test('cualquier usuario autenticado puede consultar y verificar la cadena', async () => {
    const token = api.tokenFor('usuario-normal')

    expect((await api.request('/blockchain', { token })).status).toBe(200)
    expect((await api.request('/blockchain/verify', { token })).status).toBe(200)
  })
})
