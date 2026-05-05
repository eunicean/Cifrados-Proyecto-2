import { decryptMessage, encryptMessage } from './aesGcm.js'
import {
  decryptAesKeyWithPrivateKey,
  encryptAesKeyWithPublicKey,
} from './rsaOaep.js'

export async function encryptMessageForRecipient(plaintext, recipientPublicKeyPem) {
  const encryptedMessage = await encryptMessage(plaintext)
  const encryptedKey = await encryptAesKeyWithPublicKey(
    encryptedMessage.rawAesKey,
    recipientPublicKeyPem,
  )

  return {
    ciphertext: encryptedMessage.ciphertext,
    ciphertext_base64: encryptedMessage.ciphertext_base64,
    encrypted_key: encryptedKey,
    encrypted_key_base64: encryptedKey,
    iv: encryptedMessage.iv,
    nonce_base64: encryptedMessage.nonce_base64,
    auth_tag_base64: encryptedMessage.auth_tag_base64,
    timestamp: encryptedMessage.timestamp,
  }
}

export async function encryptMessageForRecipients(plaintext, recipients) {
  const encryptedMessage = await encryptMessage(plaintext)
  const encryptedKeys = await Promise.all(
    recipients.map(async (recipient) => ({
      user_id: recipient.user_id || recipient.id,
      encrypted_key_base64: await encryptAesKeyWithPublicKey(
        encryptedMessage.rawAesKey,
        recipient.public_key_pem || recipient.key,
      ),
    })),
  )

  return {
    ciphertext_base64: encryptedMessage.ciphertext_base64,
    nonce_base64: encryptedMessage.nonce_base64,
    auth_tag_base64: encryptedMessage.auth_tag_base64,
    encrypted_keys: encryptedKeys,
    timestamp: encryptedMessage.timestamp,
  }
}

export async function decryptMessageForRecipient(encryptedMessage, recipientPrivateKeyPem) {
  const rawAesKey = await decryptAesKeyWithPrivateKey(
    encryptedMessage.encrypted_key || encryptedMessage.encrypted_key_base64,
    recipientPrivateKeyPem,
  )

  return await decryptMessage(
    encryptedMessage.ciphertext || encryptedMessage.ciphertext_base64,
    encryptedMessage.iv || encryptedMessage.nonce_base64,
    rawAesKey,
    encryptedMessage.auth_tag || encryptedMessage.auth_tag_base64,
  )
}

export async function decryptStoredMessage(encryptedMessage, recipientPrivateKeyPem) {
  const encryptedKeys = encryptedMessage.encrypted_keys?.length
    ? encryptedMessage.encrypted_keys
    : [
        {
          encrypted_key_base64:
            encryptedMessage.encrypted_key_base64 || encryptedMessage.encrypted_key,
        },
      ]

  let lastError = null

  for (let i = 0; i < encryptedKeys.length; i++) {
    const messageKey = encryptedKeys[i]
    try {
      const plaintext = await decryptMessageForRecipient(
        {
          ciphertext_base64:
            encryptedMessage.ciphertext_base64 || encryptedMessage.ciphertext,
          nonce_base64:
            encryptedMessage.nonce_base64 || encryptedMessage.nonce || encryptedMessage.iv,
          auth_tag_base64:
            encryptedMessage.auth_tag_base64 || encryptedMessage.auth_tag || encryptedMessage.tag,
          encrypted_key_base64:
            messageKey.encrypted_key_base64 || messageKey.encrypted_key,
        },
        recipientPrivateKeyPem,
      )
      return plaintext
    } catch (error) {
      lastError = error
    }
  }

  throw lastError || new Error('No hay una clave cifrada para descifrar el mensaje.')
}
