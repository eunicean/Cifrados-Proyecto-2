import { arrayBufferToBase64, base64ToArrayBuffer } from './base64.js'

const encoder = new TextEncoder()

function pemToArrayBuffer(pem) {
  const base64 = pem
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s/g, '')

  return base64ToArrayBuffer(base64)
}

async function importSigningPrivateKey(privateKeyPem) {
  return await crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(privateKeyPem),
    {
      name: 'RSA-PSS',
      hash: 'SHA-256',
    },
    false,
    ['sign'],
  )
}

async function importSigningPublicKey(publicKeyPem) {
  return await crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(publicKeyPem),
    {
      name: 'RSA-PSS',
      hash: 'SHA-256',
    },
    false,
    ['verify'],
  )
}

export async function signMessageHash(messageHashHex, privateKeyPem) {
  const privateKey = await importSigningPrivateKey(privateKeyPem)
  const signature = await crypto.subtle.sign(
    {
      name: 'RSA-PSS',
      saltLength: 32,
    },
    privateKey,
    encoder.encode(messageHashHex),
  )

  return arrayBufferToBase64(signature)
}

export async function verifyMessageHashSignature(
  messageHashHex,
  signatureBase64,
  publicKeyPem,
) {
  const publicKey = await importSigningPublicKey(publicKeyPem)

  return await crypto.subtle.verify(
    {
      name: 'RSA-PSS',
      saltLength: 32,
    },
    publicKey,
    base64ToArrayBuffer(signatureBase64),
    encoder.encode(messageHashHex),
  )
}
