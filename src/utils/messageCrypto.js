const encoder = new TextEncoder()
const decoder = new TextDecoder()

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  bytes.forEach(b => { binary += String.fromCharCode(b) })
  return btoa(binary)
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

/**

 * @param {string} plaintext - Mensaje en texto plano.
 * @returns {{ ciphertext: string, iv: string, rawAesKey: ArrayBuffer, timestamp: string }}
 */
export async function encryptMessage(plaintext) {
//   Retorna el objeto listo para enviarse al servidor.
//   El campo rawAesKey se usa después para cifrarlo con RSA-OAEP.
//   Clave AES-256 efímera — extractable:true para poder exportarla y cifrarla con RSA
  const aesKey = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  )

  // Nonce único de 12 bytes — nunca reutilizar con la misma clave
  const iv = window.crypto.getRandomValues(new Uint8Array(12))

  // AES-256-GCM: cifra el mensaje e incluye 16 bytes de tag al final del ciphertext
  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    aesKey,
    encoder.encode(plaintext),
  )

  // Exportar la clave en bruto para cifrarla con RSA-OAEP en el paso siguiente
  const rawAesKey = await window.crypto.subtle.exportKey('raw', aesKey)

  return {
    ciphertext: arrayBufferToBase64(ciphertextBuffer), // incluye el tag GCM al final
    iv: arrayBufferToBase64(iv),
    rawAesKey,                                         // caller lo cifra con RSA-OAEP
    timestamp: new Date().toISOString(),
  }
}

/**
 * Descifra un mensaje cifrado con AES-256-GCM.
 *
 * @param {string} ciphertext - Base64 del ciphertext (con tag GCM al final).
 * @param {string} iv - Base64 del nonce usado al cifrar.
 * @param {ArrayBuffer} rawAesKey - Clave AES en bruto (ya descifrada con RSA).
 * @returns {string} Mensaje en texto plano.
 */
export async function decryptMessage(ciphertext, iv, rawAesKey) {
  const aesKey = await window.crypto.subtle.importKey(
    'raw',
    rawAesKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  )

  const plaintextBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(base64ToArrayBuffer(iv)), tagLength: 128 },
    aesKey,
    base64ToArrayBuffer(ciphertext),
  )

  return decoder.decode(plaintextBuffer)
}
