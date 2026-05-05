import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  concatArrayBuffers,
} from './base64.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()
const GCM_TAG_LENGTH_BITS = 128
const GCM_TAG_LENGTH_BYTES = 16
const GCM_NONCE_LENGTH_BYTES = 12

function splitCiphertextAndTag(encryptedBuffer) {
  const encryptedBytes = new Uint8Array(encryptedBuffer)

  if (encryptedBytes.length <= GCM_TAG_LENGTH_BYTES) {
    throw new Error('El ciphertext AES-GCM no contiene datos suficientes.')
  }

  return {
    ciphertextBuffer: encryptedBytes.slice(0, -GCM_TAG_LENGTH_BYTES).buffer,
    authTagBuffer: encryptedBytes.slice(-GCM_TAG_LENGTH_BYTES).buffer,
  }
}

export async function encryptMessage(plaintext) {
  const aesKey = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  )

  const iv = window.crypto.getRandomValues(new Uint8Array(GCM_NONCE_LENGTH_BYTES))
  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: GCM_TAG_LENGTH_BITS },
    aesKey,
    encoder.encode(plaintext),
  )
  const { ciphertextBuffer: rawCiphertext, authTagBuffer } =
    splitCiphertextAndTag(ciphertextBuffer)
  const rawAesKey = await window.crypto.subtle.exportKey('raw', aesKey)

  return {
    ciphertext: arrayBufferToBase64(rawCiphertext),
    ciphertext_base64: arrayBufferToBase64(rawCiphertext),
    iv: arrayBufferToBase64(iv),
    nonce_base64: arrayBufferToBase64(iv),
    auth_tag_base64: arrayBufferToBase64(authTagBuffer),
    rawAesKey,
    timestamp: new Date().toISOString(),
  }
}

export async function decryptMessage(ciphertext, iv, rawAesKey, authTag) {
  const aesKey = await window.crypto.subtle.importKey(
    'raw',
    rawAesKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  )
  const encryptedPayload = authTag
    ? concatArrayBuffers(base64ToArrayBuffer(ciphertext), base64ToArrayBuffer(authTag))
    : base64ToArrayBuffer(ciphertext)

  const plaintextBuffer = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(base64ToArrayBuffer(iv)),
      tagLength: GCM_TAG_LENGTH_BITS,
    },
    aesKey,
    encryptedPayload,
  )

  return decoder.decode(plaintextBuffer)
}
