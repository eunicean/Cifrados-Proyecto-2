import { arrayBufferToBase64, base64ToArrayBuffer } from './base64.js'

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

export async function encryptAesKeyWithPublicKey(rawAesKey, publicKeyPem) {
  const publicKey = await importRsaPublicKey(publicKeyPem)

  const encryptedKey = await window.crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    rawAesKey,
  )

  return arrayBufferToBase64(encryptedKey)
}

export async function decryptAesKeyWithPrivateKey(encryptedKey, privateKeyPem) {
  const privateKey = await importRsaPrivateKey(privateKeyPem)

  return await window.crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    base64ToArrayBuffer(encryptedKey),
  )
}
