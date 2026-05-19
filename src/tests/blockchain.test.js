import { describe, expect, test } from 'vitest'
import {
  calculateBlockHash,
  createGenesisBlock,
  createNextBlock,
  GENESIS_PREVIOUS_HASH,
  sha256Hex,
  verifyBlockchain,
} from '../blockchain/block.js'

describe('Mini blockchain', () => {
  test('crea un bloque genesis con previous_hash igual a 64 ceros', () => {
    const genesisBlock = createGenesisBlock()

    expect(genesisBlock.index).toBe(0)
    expect(genesisBlock.previous_hash).toBe(GENESIS_PREVIOUS_HASH)
    expect(genesisBlock.hash).toHaveLength(64)
    expect(genesisBlock.message_hash).toHaveLength(64)
  })

  test('calcula correctamente el hash SHA-256 de un bloque', () => {
    const genesisBlock = createGenesisBlock()
    const recalculatedHash = calculateBlockHash(genesisBlock)

    expect(recalculatedHash).toBe(genesisBlock.hash)
  })

  test('crea un nuevo bloque apuntando al hash del bloque anterior', () => {
    const genesisBlock = createGenesisBlock()

    const nextBlock = createNextBlock(genesisBlock, {
      message_id: 'msg-1',
      sender_id: 'user-1',
      recipient_id: 'user-2',
      group_id: null,
      message_hash: sha256Hex('mensaje secreto'),
    })

    expect(nextBlock.index).toBe(1)
    expect(nextBlock.previous_hash).toBe(genesisBlock.hash)
    expect(nextBlock.hash).toHaveLength(64)
  })

  test('verifica una cadena valida', () => {
    const genesisBlock = createGenesisBlock()

    const secondBlock = createNextBlock(genesisBlock, {
      message_id: 'msg-1',
      sender_id: 'user-1',
      recipient_id: 'user-2',
      group_id: null,
      message_hash: sha256Hex('mensaje secreto'),
    })

    const result = verifyBlockchain([genesisBlock, secondBlock])

    expect(result.valid).toBe(true)
    expect(result.blocks).toBe(2)
  })

  test('detecta una cadena manipulada', () => {
    const genesisBlock = createGenesisBlock()

    const secondBlock = createNextBlock(genesisBlock, {
      message_id: 'msg-1',
      sender_id: 'user-1',
      recipient_id: 'user-2',
      group_id: null,
      message_hash: sha256Hex('mensaje secreto'),
    })

    const tamperedBlock = {
      ...secondBlock,
      message_hash: sha256Hex('mensaje alterado'),
    }

    const result = verifyBlockchain([genesisBlock, tamperedBlock])

    expect(result.valid).toBe(false)
    expect(result.invalid_index).toBe(1)
  })
})