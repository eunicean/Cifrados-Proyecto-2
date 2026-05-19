import { beforeAll, describe, expect, test } from 'vitest'
import {
  signMessageHash,
  verifyMessageHashSignature,
} from '../utils/crypto/digitalSignature.js'

// Genera un par de llaves RSA-PSS para todos los tests del módulo
async function generateRsaPssKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )

  const toBase64 = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf)))
  const chunkLines = (s) => s.match(/.{1,64}/g).join('\n')

  const pubBuf = await crypto.subtle.exportKey('spki', keyPair.publicKey)
  const privBuf = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)

  return {
    publicKeyPem: `-----BEGIN PUBLIC KEY-----\n${chunkLines(toBase64(pubBuf))}\n-----END PUBLIC KEY-----`,
    privateKeyPem: `-----BEGIN PRIVATE KEY-----\n${chunkLines(toBase64(privBuf))}\n-----END PRIVATE KEY-----`,
  }
}

// Hash SHA-256 de 64 caracteres hex (simula el hash de un mensaje real)
const SAMPLE_HASH = 'a'.repeat(64)
const OTHER_HASH = 'b'.repeat(64)

let keyPair
let altKeyPair

beforeAll(async () => {
  ;[keyPair, altKeyPair] = await Promise.all([
    generateRsaPssKeyPair(),
    generateRsaPssKeyPair(),
  ])
})

describe('Firma digital RSA-PSS — criterio 1: firma correcta sobre el hash', () => {
  test('signMessageHash produce una cadena base64 no vacía', async () => {
    const signature = await signMessageHash(SAMPLE_HASH, keyPair.privateKeyPem)

    expect(typeof signature).toBe('string')
    expect(signature.length).toBeGreaterThan(100)
    // Base64 solo contiene estos caracteres
    expect(/^[A-Za-z0-9+/=]+$/.test(signature)).toBe(true)
  })

  test('dos firmas del mismo hash con la misma llave son distintas (RSA-PSS usa sal aleatoria)', async () => {
    const sig1 = await signMessageHash(SAMPLE_HASH, keyPair.privateKeyPem)
    const sig2 = await signMessageHash(SAMPLE_HASH, keyPair.privateKeyPem)

    // RSA-PSS usa sal aleatoria, por lo que las firmas NO deben ser idénticas
    expect(sig1).not.toBe(sig2)
  })
})

describe('Firma digital RSA-PSS — criterio 2: verificación al recibir', () => {
  test('verifyMessageHashSignature retorna true para firma y hash correctos', async () => {
    const signature = await signMessageHash(SAMPLE_HASH, keyPair.privateKeyPem)
    const isValid = await verifyMessageHashSignature(
      SAMPLE_HASH,
      signature,
      keyPair.publicKeyPem,
    )

    expect(isValid).toBe(true)
  })

  test('el flujo completo firma → verifica funciona con un hash SHA-256 real', async () => {
    // Simula el hash que se calcula en messageService antes de enviar
    const encoder = new TextEncoder()
    const buf = await crypto.subtle.digest(
      'SHA-256',
      encoder.encode('Hola grupo, mensaje secreto'),
    )
    const hexHash = Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')

    const signature = await signMessageHash(hexHash, keyPair.privateKeyPem)
    const isValid = await verifyMessageHashSignature(
      hexHash,
      signature,
      keyPair.publicKeyPem,
    )

    expect(isValid).toBe(true)
  })
})

describe('Firma digital RSA-PSS — criterio 3: rechazo de firmas inválidas', () => {
  test('verifyMessageHashSignature retorna false si el hash fue alterado', async () => {
    const signature = await signMessageHash(SAMPLE_HASH, keyPair.privateKeyPem)
    const isValid = await verifyMessageHashSignature(
      OTHER_HASH, // hash distinto al que se firmó
      signature,
      keyPair.publicKeyPem,
    )

    expect(isValid).toBe(false)
  })

  test('verifyMessageHashSignature retorna false si se usa la llave pública equivocada', async () => {
    const signature = await signMessageHash(SAMPLE_HASH, keyPair.privateKeyPem)
    const isValid = await verifyMessageHashSignature(
      SAMPLE_HASH,
      signature,
      altKeyPair.publicKeyPem, // llave de otro usuario
    )

    expect(isValid).toBe(false)
  })

  test('verifyMessageHashSignature retorna false con firma base64 corrupta', async () => {
    // La Web Crypto API devuelve false (no lanza error) para firmas con bytes inválidos
    const corruptedSignature = btoa('esto-no-es-una-firma-valida-para-rsa-pss-x'.repeat(8))

    const isValid = await verifyMessageHashSignature(
      SAMPLE_HASH,
      corruptedSignature,
      keyPair.publicKeyPem,
    )

    expect(isValid).toBe(false)
  })
})
