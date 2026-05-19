import {
  createGenesisBlock,
  createNextBlock,
  sha256Hex,
  verifyBlockchain,
} from './block.js'
import {
  getBlockchain,
  getLastBlock,
  saveBlock,
} from './blockchainRepository.js'

function shortValue(value) {
  if (!value) return null
  return String(value).slice(0, 12)
}

function logBlockchain(message, details = {}) {
  console.log(`[blockchain] ${message}`, details)
}

export async function ensureGenesisBlock() {
  const lastBlock = await getLastBlock()

  if (lastBlock) {
    logBlockchain('Genesis existente encontrado', {
      index: lastBlock.index,
      hash: shortValue(lastBlock.hash),
    })
    return lastBlock
  }

  const genesisBlock = createGenesisBlock()
  const savedGenesisBlock = await saveBlock(genesisBlock)
  logBlockchain('Genesis creado', {
    index: savedGenesisBlock.index,
    hash: shortValue(savedGenesisBlock.hash),
  })
  return savedGenesisBlock
}

export async function registerMessageTransaction(message) {
  const lastBlock = await ensureGenesisBlock()

  const messageHash = getMessageHash(message)
  logBlockchain('Preparando transaccion de mensaje', {
    messageId: message.id,
    senderId: message.sender_id,
    groupId: message.group_id || null,
    messageHash: shortValue(messageHash),
    previousIndex: lastBlock.index,
  })

  const newBlock = createNextBlock(lastBlock, {
    message_id: message.id,
    sender_id: message.sender_id,
    recipient_id: message.recipient_id || null,
    group_id: message.group_id || null,
    message_hash: messageHash,
  })

  const savedBlock = await saveBlock(newBlock)
  logBlockchain('Bloque minado y guardado', {
    index: savedBlock.index,
    messageId: savedBlock.message_id,
    hash: shortValue(savedBlock.hash),
    previousHash: shortValue(savedBlock.previous_hash),
    nonce: savedBlock.nonce,
  })

  return savedBlock
}

export async function getFullBlockchain() {
  await ensureGenesisBlock()
  const chain = await getBlockchain()
  logBlockchain('Cadena cargada', { blocks: chain.length })
  return chain
}

export async function verifyFullBlockchain() {
  const chain = await getFullBlockchain()
  const verification = verifyBlockchain(chain)
  logBlockchain('Cadena verificada', {
    valid: verification.valid,
    blocks: verification.blocks,
    invalidIndex: verification.invalid_index,
  })
  return verification
}

export function getMessageHash(message) {
  if (message.message_hash) {
    return message.message_hash
  }

  if (message.plaintext_hash) {
    return message.plaintext_hash
  }

  const fallbackData = [
    message.ciphertext_base64 || message.ciphertext || '',
    message.nonce_base64 || message.nonce || message.iv || '',
    message.auth_tag_base64 || message.auth_tag || message.tag || '',
  ].join('|')

  return sha256Hex(fallbackData)
}
