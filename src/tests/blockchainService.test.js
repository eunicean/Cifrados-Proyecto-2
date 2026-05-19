import { describe, expect, test, vi } from 'vitest'
import {
  calculateBlockHash,
  createGenesisBlock,
  createNextBlock,
  DEFAULT_DIFFICULTY,
  GENESIS_PREVIOUS_HASH,
  sha256Hex,
  verifyBlockchain,
} from '../blockchain/block.js'
import { getMessageHash } from '../blockchain/blockchainService.js'

// registro automático usa el hash del mensaje
describe('getMessageHash — extracción del hash para el bloque', () => {
  test('devuelve message_hash directamente si está presente', () => {
    const hash = 'a'.repeat(64)
    const message = { message_hash: hash, plaintext_hash: 'ignorado' }

    expect(getMessageHash(message)).toBe(hash)
  })

  test('usa plaintext_hash como fallback cuando no hay message_hash', () => {
    const hash = 'b'.repeat(64)
    const message = { plaintext_hash: hash }

    expect(getMessageHash(message)).toBe(hash)
  })

  test('calcula SHA-256 de los datos del ciphertext como último recurso', () => {
    const message = {
      ciphertext_base64: 'abc==',
      nonce_base64: 'nonce==',
      auth_tag_base64: 'tag==',
    }
    const expected = sha256Hex('abc==|nonce==|tag==')

    expect(getMessageHash(message)).toBe(expected)
    expect(getMessageHash(message)).toHaveLength(64)
  })

  test('el hash calculado desde un mensaje vacío es determinista', () => {
    const result1 = getMessageHash({})
    const result2 = getMessageHash({})

    expect(result1).toBe(result2)
    expect(result1).toHaveLength(64)
  })
})

// ---------------------------------------------------------------------------
// Estructura del bloque genesis — criterio 4
// ---------------------------------------------------------------------------
describe('Genesis block — criterio 4: estructura del bloque inicial', () => {
  test('tiene índice 0 y previous_hash de 64 ceros', () => {
    const genesis = createGenesisBlock()

    expect(genesis.index).toBe(0)
    expect(genesis.previous_hash).toBe(GENESIS_PREVIOUS_HASH)
    expect(genesis.previous_hash).toHaveLength(64)
    expect(genesis.previous_hash).toBe('0'.repeat(64))
  })

  test('contiene todos los campos requeridos por la estructura del bloque', () => {
    const genesis = createGenesisBlock()

    expect(genesis).toHaveProperty('index')
    expect(genesis).toHaveProperty('timestamp')
    expect(genesis).toHaveProperty('message_hash')
    expect(genesis).toHaveProperty('previous_hash')
    expect(genesis).toHaveProperty('nonce')
    expect(genesis).toHaveProperty('hash')
  })

  test('el hash del bloque genesis tiene el prefijo PoW requerido', () => {
    const genesis = createGenesisBlock()
    const prefix = '0'.repeat(DEFAULT_DIFFICULTY)

    expect(genesis.hash.startsWith(prefix)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Encadenamiento SHA-256 — criterio 5
// ---------------------------------------------------------------------------
describe('Encadenamiento de bloques — criterio 5: hashes SHA-256 correctos', () => {
  test('cada bloque apunta al hash exacto del bloque anterior', () => {
    const genesis = createGenesisBlock()
    const block1 = createNextBlock(genesis, {
      message_id: 'msg-1',
      sender_id: 'u1',
      recipient_id: null,
      group_id: 'g1',
      message_hash: sha256Hex('primer mensaje'),
    })
    const block2 = createNextBlock(block1, {
      message_id: 'msg-2',
      sender_id: 'u2',
      recipient_id: null,
      group_id: 'g1',
      message_hash: sha256Hex('segundo mensaje'),
    })

    expect(block1.previous_hash).toBe(genesis.hash)
    expect(block2.previous_hash).toBe(block1.hash)
    expect(block2.index).toBe(2)
  })

  test('recalcular el hash de un bloque produce el mismo resultado', () => {
    const genesis = createGenesisBlock()
    const block1 = createNextBlock(genesis, {
      message_id: 'msg-x',
      sender_id: 'user-a',
      recipient_id: null,
      group_id: null,
      message_hash: sha256Hex('mensaje de prueba'),
    })

    const recalculated = calculateBlockHash(block1)

    expect(recalculated).toBe(block1.hash)
  })

  test('cada bloque minado cumple el requisito de dificultad PoW', () => {
    const prefix = '0'.repeat(DEFAULT_DIFFICULTY)
    const genesis = createGenesisBlock()
    const block1 = createNextBlock(genesis, {
      message_id: 'msg-pow',
      sender_id: 'u1',
      recipient_id: null,
      group_id: null,
      message_hash: sha256Hex('pow test'),
    })

    expect(genesis.hash.startsWith(prefix)).toBe(true)
    expect(block1.hash.startsWith(prefix)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Verificación de integridad — criterio 6: endpoint de verificación
// ---------------------------------------------------------------------------
describe('verifyBlockchain — criterio 6: verificación de integridad de la cadena', () => {
  test('acepta una cadena de tres bloques correctamente encadenados', () => {
    const genesis = createGenesisBlock()
    const block1 = createNextBlock(genesis, {
      message_id: 'm1', sender_id: 'u1', recipient_id: null,
      group_id: null, message_hash: sha256Hex('msg 1'),
    })
    const block2 = createNextBlock(block1, {
      message_id: 'm2', sender_id: 'u2', recipient_id: null,
      group_id: null, message_hash: sha256Hex('msg 2'),
    })

    const result = verifyBlockchain([genesis, block1, block2])

    expect(result.valid).toBe(true)
    expect(result.blocks).toBe(3)
    expect(result.error).toBeNull()
  })

  test('rechaza una cadena donde se alteró el hash del mensaje de un bloque', () => {
    const genesis = createGenesisBlock()
    const block1 = createNextBlock(genesis, {
      message_id: 'm1', sender_id: 'u1', recipient_id: null,
      group_id: null, message_hash: sha256Hex('mensaje original'),
    })
    // Alteración: se cambia message_hash sin recalcular el hash del bloque
    const manipulated = { ...block1, message_hash: sha256Hex('mensaje falsificado') }

    const result = verifyBlockchain([genesis, manipulated])

    expect(result.valid).toBe(false)
    expect(result.invalid_index).toBe(1)
  })

  test('rechaza una cadena donde previous_hash no apunta al bloque correcto', () => {
    const genesis = createGenesisBlock()
    const block1 = createNextBlock(genesis, {
      message_id: 'm1', sender_id: 'u1', recipient_id: null,
      group_id: null, message_hash: sha256Hex('msg'),
    })
    // Rompe el enlace: apunta a un hash inventado
    const unlinked = { ...block1, previous_hash: 'f'.repeat(64) }

    const result = verifyBlockchain([genesis, unlinked])

    expect(result.valid).toBe(false)
  })

  test('rechaza una cadena vacía', () => {
    const result = verifyBlockchain([])

    expect(result.valid).toBe(false)
    expect(result.error).toBeTruthy()
  })
})
