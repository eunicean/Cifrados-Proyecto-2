import { describe, expect, test } from 'vitest'
import { generateRsaKeyPairPem } from '../utils/rsaKeyPair.js'

describe('RSA key pair generation', () => {
  test('genera un par de llaves RSA-2048 en formato PEM', async () => {
    const keyPair = await generateRsaKeyPairPem()

    expect(typeof keyPair.publicKeyPem).toBe('string')
    expect(typeof keyPair.privateKeyPem).toBe('string')

    expect(keyPair.publicKeyPem).toMatch(/^-----BEGIN PUBLIC KEY-----/)
    expect(keyPair.publicKeyPem).toMatch(/-----END PUBLIC KEY-----\n$/)

    expect(keyPair.privateKeyPem).toMatch(/^-----BEGIN PRIVATE KEY-----/)
    expect(keyPair.privateKeyPem).toMatch(/-----END PRIVATE KEY-----\n$/)
  })
})