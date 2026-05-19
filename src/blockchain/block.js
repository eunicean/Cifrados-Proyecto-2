import crypto from 'node:crypto'

export const GENESIS_PREVIOUS_HASH = '0'.repeat(64)
export const DEFAULT_DIFFICULTY = 2

export function sha256Hex(value) {
  return crypto
    .createHash('sha256')
    .update(String(value))
    .digest('hex')
}

export function stableStringify(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value)
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`
  }

  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(',')}}`
}

export function calculateBlockHash(block) {
  const data = stableStringify({
    message_id: block.message_id || null,
    sender_id: block.sender_id || null,
    recipient_id: block.recipient_id || null,
    group_id: block.group_id || null,
    message_hash: block.message_hash,
  })

  return sha256Hex(
    `${block.index}${block.timestamp}${data}${block.previous_hash}${block.nonce}`,
  )
}

export function mineBlock(blockData, difficulty = DEFAULT_DIFFICULTY) {
  const prefix = '0'.repeat(difficulty)
  let nonce = 0

  while (true) {
    const candidateBlock = {
      ...blockData,
      nonce,
    }

    const hash = calculateBlockHash(candidateBlock)

    if (hash.startsWith(prefix)) {
      return {
        ...candidateBlock,
        hash,
      }
    }

    nonce += 1
  }
}

export function createGenesisBlock() {
  const timestamp = new Date().toISOString()

  return mineBlock({
    index: 0,
    timestamp,
    message_id: null,
    sender_id: null,
    recipient_id: null,
    group_id: null,
    message_hash: sha256Hex('GENESIS_BLOCK'),
    previous_hash: GENESIS_PREVIOUS_HASH,
  })
}

export function createNextBlock(previousBlock, transactionData) {
  if (!previousBlock) {
    throw new Error('Se requiere el bloque anterior.')
  }

  const timestamp = new Date().toISOString()

  return mineBlock({
    index: previousBlock.index + 1,
    timestamp,
    message_id: transactionData.message_id || null,
    sender_id: transactionData.sender_id || null,
    recipient_id: transactionData.recipient_id || null,
    group_id: transactionData.group_id || null,
    message_hash: transactionData.message_hash,
    previous_hash: previousBlock.hash,
  })
}

export function verifyBlockchain(chain) {
  if (!Array.isArray(chain) || chain.length === 0) {
    return {
      valid: false,
      error: 'La cadena esta vacia.',
      invalid_index: null,
    }
  }

  const [genesisBlock] = chain

  if (genesisBlock.index !== 0) {
    return {
      valid: false,
      error: 'El bloque genesis debe tener indice 0.',
      invalid_index: genesisBlock.index,
    }
  }

  if (genesisBlock.previous_hash !== GENESIS_PREVIOUS_HASH) {
    return {
      valid: false,
      error: 'El bloque genesis tiene previous_hash invalido.',
      invalid_index: genesisBlock.index,
    }
  }

  for (let i = 0; i < chain.length; i += 1) {
    const currentBlock = chain[i]
    const recalculatedHash = calculateBlockHash(currentBlock)

    if (currentBlock.hash !== recalculatedHash) {
      return {
        valid: false,
        error: 'El hash del bloque no coincide con su contenido.',
        invalid_index: currentBlock.index,
      }
    }

    if (i > 0) {
      const previousBlock = chain[i - 1]

      if (currentBlock.previous_hash !== previousBlock.hash) {
        return {
          valid: false,
          error: 'El bloque no apunta correctamente al bloque anterior.',
          invalid_index: currentBlock.index,
        }
      }
    }
  }

  return {
    valid: true,
    blocks: chain.length,
    error: null,
    invalid_index: null,
  }
}