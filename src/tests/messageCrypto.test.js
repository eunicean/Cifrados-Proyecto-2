import { describe, expect, test } from 'vitest'
import { generateRsaKeyPairPem } from '../utils/rsaKeyPair.js'
import {
  decryptStoredMessage,
  encryptMessage,
  encryptMessageForRecipients,
} from '../utils/messageCrypto.js'

describe('Message crypto module', () => {
  test('cifra AES-256-GCM separando nonce, ciphertext y auth tag para la BD', async () => {
    const encryptedMessage = await encryptMessage('mensaje secreto')

    expect(typeof encryptedMessage.ciphertext_base64).toBe('string')
    expect(typeof encryptedMessage.nonce_base64).toBe('string')
    expect(typeof encryptedMessage.auth_tag_base64).toBe('string')

    expect(encryptedMessage.ciphertext_base64).not.toBe('')
    expect(encryptedMessage.nonce_base64).not.toBe('')
    expect(encryptedMessage.auth_tag_base64).not.toBe('')

    expect(Buffer.from(encryptedMessage.nonce_base64, 'base64')).toHaveLength(12)
    expect(Buffer.from(encryptedMessage.auth_tag_base64, 'base64')).toHaveLength(16)
  })

  test('descifra end-to-end un mensaje grupal usando una llave privada RSA', async () => {
    const alice = await generateRsaKeyPairPem()
    const bob = await generateRsaKeyPairPem()
    const plaintext = 'hola equipo'

    const encryptedMessage = await encryptMessageForRecipients(plaintext, [
      {
        user_id: 'alice',
        public_key_pem: alice.publicKeyPem,
      },
      {
        user_id: 'bob',
        public_key_pem: bob.publicKeyPem,
      },
    ])

    const decryptedForBob = await decryptStoredMessage(
      encryptedMessage,
      bob.privateKeyPem,
    )

    expect(encryptedMessage.encrypted_keys).toHaveLength(2)
    expect(decryptedForBob).toBe(plaintext)
  })
})