import { describe, expect, test } from 'vitest'
import { generateRsaKeyPairPem } from '../utils/rsaKeyPair.js'
import {
  decryptPrivateKey,
  encryptPrivateKey,
} from '../utils/privateKeyEncryption.js'

describe('Private key encryption', () => {
  test('cifra y descifra una llave privada RSA usando PBKDF2 y AES-GCM', async () => {
    const password = 'Password-Segura-123'
    const { privateKeyPem } = await generateRsaKeyPairPem()

    const encryptedData = await encryptPrivateKey(privateKeyPem, password)
    const decryptedPrivateKey = await decryptPrivateKey(encryptedData, password)

    expect(decryptedPrivateKey).toBe(privateKeyPem)

    expect(encryptedData.algorithm).toBe('AES-GCM')
    expect(encryptedData.kdf).toBe('PBKDF2')
    expect(encryptedData.hash).toBe('SHA-256')
    expect(encryptedData.iterations).toBe(600000)

    expect(typeof encryptedData.salt).toBe('string')
    expect(typeof encryptedData.iv).toBe('string')
    expect(typeof encryptedData.encryptedPrivateKey).toBe('string')

    expect(encryptedData.encryptedPrivateKey).not.toBe(privateKeyPem)
  })

  test('falla al descifrar la llave privada con una contraseña incorrecta', async () => {
    const correctPassword = 'Password-Correcta-123'
    const wrongPassword = 'Password-Incorrecta-456'

    const { privateKeyPem } = await generateRsaKeyPairPem()
    const encryptedData = await encryptPrivateKey(privateKeyPem, correctPassword)

    await expect(
      decryptPrivateKey(encryptedData, wrongPassword),
    ).rejects.toThrow()
  })
})