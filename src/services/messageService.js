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

export { deriveGroupAesKey }

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

export async function sendGroupMessage(groupId, plaintext, groupAesKey) {
  const cleanContent = plaintext?.trim()

  if (!groupId) {
    throw new Error('Se requiere el ID del grupo.')
  }

  if (!cleanContent) {
    throw new Error('El mensaje no puede estar vacio.')
  }

  const plaintextHash = await sha256HexBrowser(cleanContent)
  const encryptedPayload = await encryptWithGroupKey(cleanContent, groupAesKey)
  const data = await apiRequest('/messages', {
    method: 'POST',
    body: JSON.stringify({
      channel_id: groupId,
      plaintext_hash: plaintextHash,
      ...encryptedPayload,
    }),
  })
  return data.message || data
}

export async function decryptGroupMessages(messages, groupAesKey) {
  return await Promise.all(
    messages.map(async (message) => {
      try {
        const plaintext = await decryptWithGroupKey(message, groupAesKey)
        return { ...message, plaintext, decrypt_error: '' }
      } catch {
        return { ...message, plaintext: '', decrypt_error: 'No se pudo descifrar.' }
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
  const encryptedPayload = await encryptMessageForRecipients(
    cleanContent,
    keysData.members || [],
  )

  const data = await apiRequest('/messages', {
    method: 'POST',
    body: JSON.stringify({
      group_id: groupMessageForm.group_id,
      plaintext_hash: plaintextHash,
      ...encryptedPayload,
    }),
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
        return { ...message, plaintext, decrypt_error: '' }
      } catch {
        return {
          ...message,
          plaintext: '',
          decrypt_error: 'No se pudo descifrar con esta llave privada.',
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
  const encryptedPayload = await encryptMessageForRecipients(
    cleanContent,
    keysData.members || [],
  )

  const data = await apiRequest('/messages', {
    method: 'POST',
    body: JSON.stringify({
      group_id: conversation.channel_id,
      plaintext_hash: plaintextHash,
      ...encryptedPayload,
    }),
  })

  return {
    ...(data.message || data),
    contact_id: conversation.id,
  }
}