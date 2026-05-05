import { apiRequest } from '../utils/apiClient'
import {
  decryptStoredMessage,
  encryptMessageForRecipients,
} from '../utils/messageCrypto'

export async function createGroup(groupForm) {
  const memberIds = groupForm.member_ids
    .split(',')
    .map((member) => member.trim())
    .filter(Boolean)

  const data = await apiRequest('/groups', {
    method: 'POST',
    body: JSON.stringify({
      name: groupForm.name,
      member_ids: memberIds,
    }),
  })

  return data.group || data
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
