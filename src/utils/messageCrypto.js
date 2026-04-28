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

function pemToArrayBuffer(pem) {
  const base64 = pem
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s/g, '')

  return base64ToArrayBuffer(base64)
}

async function importRsaPublicKey(publicKeyPem) {
  return await window.crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(publicKeyPem),
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    false,
    ['encrypt'],
  )
}

async function importRsaPrivateKey(privateKeyPem) {
  return await window.crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(privateKeyPem),
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    false,
    ['decrypt'],
  )
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

/**
 * Cifra la clave AES efimera usando la llave publica RSA-OAEP del destinatario.
 *
 * @param {ArrayBuffer} rawAesKey - Clave AES exportada en bruto.
 * @param {string} publicKeyPem - Llave publica RSA en formato PEM.
 * @returns {string} Clave AES cifrada en Base64.
 */
export async function encryptAesKeyWithPublicKey(rawAesKey, publicKeyPem) {
  const publicKey = await importRsaPublicKey(publicKeyPem)

  const encryptedKey = await window.crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    rawAesKey,
  )

  return arrayBufferToBase64(encryptedKey)
}

/**
 * Recupera la clave AES usando la llave privada RSA-OAEP del destinatario.
 *
 * @param {string} encryptedKey - Clave AES cifrada en Base64.
 * @param {string} privateKeyPem - Llave privada RSA en formato PEM PKCS#8.
 * @returns {ArrayBuffer} Clave AES original en bruto.
 */
export async function decryptAesKeyWithPrivateKey(encryptedKey, privateKeyPem) {
  const privateKey = await importRsaPrivateKey(privateKeyPem)

  return await window.crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    base64ToArrayBuffer(encryptedKey),
  )
}

/**
 * Cifra un mensaje y protege su clave AES con RSA-OAEP.
 *
 * @param {string} plaintext - Mensaje en texto plano.
 * @param {string} recipientPublicKeyPem - Llave publica del destinatario.
 * @returns {{ ciphertext: string, encrypted_key: string, iv: string, timestamp: string }}
 */
export async function encryptMessageForRecipient(plaintext, recipientPublicKeyPem) {
  const encryptedMessage = await encryptMessage(plaintext)
  const encryptedKey = await encryptAesKeyWithPublicKey(
    encryptedMessage.rawAesKey,
    recipientPublicKeyPem,
  )

  return {
    ciphertext: encryptedMessage.ciphertext,
    encrypted_key: encryptedKey,
    iv: encryptedMessage.iv,
    timestamp: encryptedMessage.timestamp,
  }
}

/**
 * Descifra un mensaje recibido recuperando primero la clave AES con RSA-OAEP.
 *
 * @param {{ ciphertext: string, encrypted_key: string, iv: string }} encryptedMessage
 * @param {string} recipientPrivateKeyPem - Llave privada del destinatario.
 * @returns {string} Mensaje en texto plano.
 */
export async function decryptMessageForRecipient(encryptedMessage, recipientPrivateKeyPem) {
  const rawAesKey = await decryptAesKeyWithPrivateKey(
    encryptedMessage.encrypted_key,
    recipientPrivateKeyPem,
  )

  return await decryptMessage(
    encryptedMessage.ciphertext,
    encryptedMessage.iv,
    rawAesKey,
  )
}
