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

export async function ensureGenesisBlock() {
  const lastBlock = await getLastBlock()

  if (lastBlock) {
    return lastBlock
  }

  const genesisBlock = createGenesisBlock()
  return await saveBlock(genesisBlock)
}

export async function registerMessageTransaction(message) {
  const lastBlock = await ensureGenesisBlock()

  const messageHash = getMessageHash(message)

  const newBlock = createNextBlock(lastBlock, {
    message_id: message.id,
    sender_id: message.sender_id,
    recipient_id: message.recipient_id || null,
    group_id: message.group_id || null,
    message_hash: messageHash,
  })

  return await saveBlock(newBlock)
}

export async function getFullBlockchain() {
  await ensureGenesisBlock()
  return await getBlockchain()
}

export async function verifyFullBlockchain() {
  const chain = await getFullBlockchain()
  return verifyBlockchain(chain)
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