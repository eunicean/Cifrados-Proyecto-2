import { arrayBufferToBase64, base64ToArrayBuffer } from './base64.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export function generateGroupCode(length = 8) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const bytes = window.crypto.getRandomValues(new Uint8Array(length))
  return Array.from(bytes, b => chars[b % chars.length]).join('')
}

// Deriva AES-256 del código usando PBKDF2; usa el groupId como salt
// para que el mismo código en grupos distintos produzca claves distintas
export async function deriveGroupAesKey(code, groupId) {
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    encoder.encode(code),
    'PBKDF2',
    false,
    ['deriveKey'],
  )

  return await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: encoder.encode(groupId),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

export async function encryptWithGroupKey(plaintext, groupAesKey) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12))

  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    groupAesKey,
    encoder.encode(plaintext),
  )

  const bytes = new Uint8Array(ciphertextBuffer)
  const ciphertextBytes = bytes.slice(0, -16)
  const authTagBytes = bytes.slice(-16)

  return {
    ciphertext_base64: arrayBufferToBase64(ciphertextBytes.buffer),
    nonce_base64: arrayBufferToBase64(iv),
    auth_tag_base64: arrayBufferToBase64(authTagBytes.buffer),
    encrypted_keys: [],
    timestamp: new Date().toISOString(),
  }
}

export async function decryptWithGroupKey(encryptedMessage, groupAesKey) {
  const ciphertextBytes = new Uint8Array(
    base64ToArrayBuffer(encryptedMessage.ciphertext_base64 || encryptedMessage.ciphertext),
  )
  const authTagBytes = new Uint8Array(
    base64ToArrayBuffer(encryptedMessage.auth_tag_base64 || encryptedMessage.auth_tag),
  )

  const fullBuffer = new Uint8Array(ciphertextBytes.length + authTagBytes.length)
  fullBuffer.set(ciphertextBytes)
  fullBuffer.set(authTagBytes, ciphertextBytes.length)

  const nonce = new Uint8Array(
    base64ToArrayBuffer(encryptedMessage.nonce_base64 || encryptedMessage.nonce),
  )

  const plaintextBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    groupAesKey,
    fullBuffer,
  )

  return decoder.decode(plaintextBuffer)
}
