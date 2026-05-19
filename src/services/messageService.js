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
  const encryptedPayload = await encryptWithGroupKey(plaintext, groupAesKey)
  const data = await apiRequest('/messages', {
    method: 'POST',
    body: JSON.stringify({ channel_id: groupId, ...encryptedPayload }),
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
  const keysData = await apiRequest(
    `/groups/${groupMessageForm.group_id}/members/keys`,
  )
  const encryptedPayload = await encryptMessageForRecipients(
    groupMessageForm.content,
    keysData.members || [],
  )

  const data = await apiRequest('/messages', {
    method: 'POST',
    body: JSON.stringify({
      group_id: groupMessageForm.group_id,
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
