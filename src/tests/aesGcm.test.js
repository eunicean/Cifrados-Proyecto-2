import { describe, expect, test } from 'vitest'
import { decryptMessage, encryptMessage } from '../utils/crypto/aesGcm.js'

describe('AES-256-GCM message encryption', () => {
  test('cifra y descifra un mensaje correctamente', async () => {
    const plaintext = 'Mensaje secreto para el grupo de Blu'

    const encrypted = await encryptMessage(plaintext)

    const decrypted = await decryptMessage(
      encrypted.ciphertext_base64,
      encrypted.nonce_base64,
      encrypted.rawAesKey,
      encrypted.auth_tag_base64,
    )

    expect(decrypted).toBe(plaintext)
    expect(encrypted.ciphertext_base64).toBeTruthy()
    expect(encrypted.nonce_base64).toBeTruthy()
    expect(encrypted.auth_tag_base64).toBeTruthy()
    expect(encrypted.timestamp).toBeTruthy()
  })

  test('genera nonces diferentes para mensajes diferentes', async () => {
    const first = await encryptMessage('Mensaje 1')
    const second = await encryptMessage('Mensaje 2')

    expect(first.nonce_base64).not.toBe(second.nonce_base64)
  })

  test('falla al descifrar si el auth tag fue alterado', async () => {
    const plaintext = 'Mensaje protegido con AES-GCM'
    const encrypted = await encryptMessage(plaintext)

    const tamperedAuthTag = encrypted.auth_tag_base64.slice(0, -2) + 'AA'

    await expect(
      decryptMessage(
        encrypted.ciphertext_base64,
        encrypted.nonce_base64,
        encrypted.rawAesKey,
        tamperedAuthTag,
      ),
    ).rejects.toThrow()
  })
})