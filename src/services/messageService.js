import { apiRequest } from '../utils/apiClient'
import {
  decryptStoredMessage,
  encryptMessageForRecipients,
} from '../utils/messageCrypto'

import {
  decryptWithGroupKey,
  deriveGroupAesKey,
  encryptWithGroupKey,
} from '../utils/crypto/groupKey'
import {
  signMessageHash,
  verifyMessageHashSignature,
} from '../utils/crypto/digitalSignature'

export { deriveGroupAesKey }

function shortValue(value) {
  if (!value) return null
  return String(value).slice(0, 12)
}

function logCrypto(message, details = {}) {
  console.log(`[crypto] ${message}`, details)
}

async function sha256HexBrowser(value) {
  const encodedValue = new TextEncoder().encode(value)
  const digest = await globalThis.crypto.subtle.digest('SHA-256', encodedValue)

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

export async function createGroup(name) {
  const data = await apiRequest('/groups', {
    method: 'POST',
    body: JSON.stringify({ name }),
  })
  return data
}

export async function searchGroupsByName(name) {
  const data = await apiRequest(`/groups/search?name=${encodeURIComponent(name)}`)
  return data.groups || []
}

export async function joinGroupWithCode(groupId, code) {
  return await apiRequest(`/groups/${groupId}/join`, {
    method: 'POST',
    body: JSON.stringify({ code }),
  })
}

export async function loadGroupMessages(groupId) {
  const data = await apiRequest(`/groups/${groupId}/messages`)
  return data.messages || []
}

export async function sendGroupMessage(
  groupId,
  plaintext,
  groupAesKey,
  signerPrivateKeyPem = '',
) {
  const cleanContent = plaintext?.trim()

  if (!groupId) {
    throw new Error('Se requiere el ID del grupo.')
  }

  if (!cleanContent) {
    throw new Error('El mensaje no puede estar vacio.')
  }

  const plaintextHash = await sha256HexBrowser(cleanContent)
  logCrypto('Hash SHA-256 de mensaje grupal generado', {
    groupId,
    plaintextHash: shortValue(plaintextHash),
  })

  const signatureBase64 = signerPrivateKeyPem
    ? await signMessageHash(plaintextHash, signerPrivateKeyPem)
    : ''
  logCrypto('Firma de mensaje grupal preparada', {
    groupId,
    signed: Boolean(signatureBase64),
    algorithm: signatureBase64 ? 'RSA-PSS-SHA-256' : 'none',
  })

  const encryptedPayload = await encryptWithGroupKey(cleanContent, groupAesKey)
  logCrypto('Mensaje grupal cifrado con AES-GCM', {
    groupId,
    hasCiphertext: Boolean(encryptedPayload.ciphertext_base64),
    hasNonce: Boolean(encryptedPayload.nonce_base64),
    hasAuthTag: Boolean(encryptedPayload.auth_tag_base64),
  })

  const data = await apiRequest('/messages', {
    method: 'POST',
    body: JSON.stringify({
      channel_id: groupId,
      plaintext_hash: plaintextHash,
      signature_base64: signatureBase64 || null,
      signature_algorithm: signatureBase64 ? 'RSA-PSS-SHA-256' : null,
      ...encryptedPayload,
    }),
  })
  logCrypto('Mensaje grupal enviado a API', {
    groupId,
    messageId: (data.message || data)?.id,
  })
  return data.message || data
}

export async function decryptGroupMessages(messages, groupAesKey) {
  return await Promise.all(
    messages.map(async (message) => {
      try {
        const plaintext = await decryptWithGroupKey(message, groupAesKey)
        const verifiedMessage = await verifyDecryptedMessageSignature({
          ...message,
          plaintext,
        })
        logCrypto('Mensaje grupal descifrado', {
          messageId: message.id,
          signatureStatus: verifiedMessage.signature_status,
        })
        return { ...verifiedMessage, decrypt_error: '' }
      } catch {
        return {
          ...message,
          plaintext: '',
          decrypt_error: 'No se pudo descifrar.',
          signature_status: 'unknown',
        }
      }
    }),
  )
}

export async function loadUserGroups() {
  const data = await apiRequest('/groups')
  return data.groups || data || []
}

export async function sendEncryptedGroupMessage(groupMessageForm) {
  const cleanContent = groupMessageForm.content?.trim()

  if (!groupMessageForm.group_id) {
    throw new Error('Se requiere el ID del grupo.')
  }

  if (!cleanContent) {
    throw new Error('El mensaje no puede estar vacio.')
  }

  const keysData = await apiRequest(
    `/groups/${groupMessageForm.group_id}/members/keys`,
  )
  const plaintextHash = await sha256HexBrowser(cleanContent)
  logCrypto('Hash SHA-256 de mensaje RSA grupal generado', {
    groupId: groupMessageForm.group_id,
    plaintextHash: shortValue(plaintextHash),
  })

  const signatureBase64 = groupMessageForm.signer_private_key_pem
    ? await signMessageHash(plaintextHash, groupMessageForm.signer_private_key_pem)
    : ''
  logCrypto('Firma de mensaje RSA grupal preparada', {
    groupId: groupMessageForm.group_id,
    signed: Boolean(signatureBase64),
  })

  const encryptedPayload = await encryptMessageForRecipients(
    cleanContent,
    keysData.members || [],
  )

  const data = await apiRequest('/messages', {
    method: 'POST',
    body: JSON.stringify({
      group_id: groupMessageForm.group_id,
      plaintext_hash: plaintextHash,
      signature_base64: signatureBase64 || null,
      signature_algorithm: signatureBase64 ? 'RSA-PSS-SHA-256' : null,
      ...encryptedPayload,
    }),
  })
  logCrypto('Mensaje RSA grupal enviado a API', {
    groupId: groupMessageForm.group_id,
    messageId: (data.message || data)?.id,
  })

  return data.message || data
}

export async function loadUserMessages(userId) {
  const data = await apiRequest(`/messages/${userId}`)
  return data.messages || data || []
}

export async function decryptMessagesWithPrivateKey(
  encryptedMessages,
  unlockedPrivateKeyPem,
) {
  if (!unlockedPrivateKeyPem) return encryptedMessages

  return await Promise.all(
    encryptedMessages.map(async (message) => {
      try {
        const plaintext = await decryptStoredMessage(message, unlockedPrivateKeyPem)
        const verifiedMessage = await verifyDecryptedMessageSignature({
          ...message,
          plaintext,
        })
        logCrypto('Mensaje RSA descifrado', {
          messageId: message.id,
          signatureStatus: verifiedMessage.signature_status,
        })
        return { ...verifiedMessage, decrypt_error: '' }
      } catch {
        return {
          ...message,
          plaintext: '',
          decrypt_error: 'No se pudo descifrar con esta llave privada.',
          signature_status: 'unknown',
        }
      }
    }),
  )
}
export async function loadContacts() {
  try {
    const [usersData, conversationsData] = await Promise.all([
      apiRequest('/users'),
      apiRequest('/direct-conversations'),
    ])
    const currentUser = JSON.parse(localStorage.getItem('blu_user') || '{}')
    const allUsers = usersData.users || usersData || []
    const conversations = conversationsData.conversations || conversationsData || []
    const conversationsByUserId = new Map(
      conversations.map((conversation) => [conversation.id, conversation]),
    )

    return allUsers
      .filter((user) => user.id !== currentUser.id)
      .map((user) => ({
        ...user,
        channel_id: conversationsByUserId.get(user.id)?.channel_id || '',
      }))
  } catch {
    return []
  }
}

export async function createDirectConversation(contactForm) {
  const data = await apiRequest('/direct-conversations', {
    method: 'POST',
    body: JSON.stringify({
      recipient_id: contactForm.recipient_id,
      recipient_email: contactForm.recipient_email,
    }),
  })

  return data.conversation || data
}

export async function sendEncryptedDirectMessage(directMessageForm) {
  const cleanContent = directMessageForm.content?.trim()

  if (!cleanContent) {
    throw new Error('El mensaje no puede estar vacio.')
  }

  const conversation = await createDirectConversation(directMessageForm)
  const keysData = await apiRequest(
    `/groups/${conversation.channel_id}/members/keys`,
  )
  const plaintextHash = await sha256HexBrowser(cleanContent)
  logCrypto('Hash SHA-256 de mensaje directo generado', {
    channelId: conversation.channel_id,
    recipientId: conversation.id,
    plaintextHash: shortValue(plaintextHash),
  })

  const signatureBase64 = directMessageForm.signer_private_key_pem
    ? await signMessageHash(plaintextHash, directMessageForm.signer_private_key_pem)
    : ''
  logCrypto('Firma de mensaje directo preparada', {
    channelId: conversation.channel_id,
    recipientId: conversation.id,
    signed: Boolean(signatureBase64),
  })

  const encryptedPayload = await encryptMessageForRecipients(
    cleanContent,
    keysData.members || [],
  )

  const data = await apiRequest('/messages', {
    method: 'POST',
    body: JSON.stringify({
      group_id: conversation.channel_id,
      plaintext_hash: plaintextHash,
      signature_base64: signatureBase64 || null,
      signature_algorithm: signatureBase64 ? 'RSA-PSS-SHA-256' : null,
      ...encryptedPayload,
    }),
  })
  logCrypto('Mensaje directo enviado a API', {
    channelId: conversation.channel_id,
    recipientId: conversation.id,
    messageId: (data.message || data)?.id,
  })

  return {
    ...(data.message || data),
    contact_id: conversation.id,
  }
}

async function verifyDecryptedMessageSignature(message) {
  if (!message.signature_base64) {
    logCrypto('Mensaje sin firma digital', { messageId: message.id })
    return { ...message, signature_status: 'unsigned' }
  }

  if (!message.sender_public_key) {
    logCrypto('No se pudo verificar firma: falta llave publica', {
      messageId: message.id,
    })
    return { ...message, signature_status: 'missing-public-key' }
  }

  const actualPlaintextHash = await sha256HexBrowser(message.plaintext)
  const plaintextHash = message.plaintext_hash || actualPlaintextHash

  if (message.plaintext_hash && actualPlaintextHash !== message.plaintext_hash) {
    logCrypto('Firma invalida: hash del plaintext no coincide', {
      messageId: message.id,
      expectedHash: shortValue(message.plaintext_hash),
      actualHash: shortValue(actualPlaintextHash),
    })
    return { ...message, signature_status: 'invalid' }
  }

  try {
    const isValid = await verifyMessageHashSignature(
      plaintextHash,
      message.signature_base64,
      message.sender_public_key,
    )

    logCrypto('Firma verificada', {
      messageId: message.id,
      valid: isValid,
      plaintextHash: shortValue(plaintextHash),
    })

    return {
      ...message,
      signature_status: isValid ? 'valid' : 'invalid',
    }
  } catch {
    logCrypto('Firma invalida: fallo la verificacion criptografica', {
      messageId: message.id,
    })
    return { ...message, signature_status: 'invalid' }
  }
}

export async function loadBlockchain() {
  const data = await apiRequest('/blockchain')
  return data.blocks || data || []
}

export async function verifyBlockchainIntegrity() {
  return await apiRequest('/blockchain/verify')
}

export async function tamperBlockchainBlock(blockIndex) {
  return await apiRequest(`/blockchain/tamper/${blockIndex}`, {
    method: 'POST',
  })
}