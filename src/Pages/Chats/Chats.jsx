import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  createGroup,
  decryptMessagesWithPrivateKey,
  loadUserGroups,
  loadUserMessages,
  sendEncryptedGroupMessage,
} from '../../services/messageService'
import { decryptPrivateKey } from '../../utils/privateKeyEncryption'
import './Chats.css'

const emptyGroupForm = {
  name: '',
  member_ids: '',
}

const emptyPrivateKeyForm = {
  encrypted_key_json: '',
  password: '',
}

const cryptoFlowSteps = [
  'El usuario escribe un mensaje.',
  'El cliente genera una clave AES-256 efimera.',
  'El cliente genera un nonce unico.',
  'El mensaje se cifra con AES-256-GCM.',
  'La clave AES se cifra con RSA-OAEP usando la llave publica de cada miembro.',
  'Supabase guarda ciphertext, nonce, tag y timestamp.',
  'Supabase guarda una encrypted_key por cada miembro del canal.',
]

function Chats() {
  const [groups, setGroups] = useState([])
  const [selectedGroupId, setSelectedGroupId] = useState('')
  const [messages, setMessages] = useState([])
  const [messageText, setMessageText] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [groupForm, setGroupForm] = useState(emptyGroupForm)
  const [privateKeyForm, setPrivateKeyForm] = useState(emptyPrivateKeyForm)
  const [privateKeyPem, setPrivateKeyPem] = useState('')
  const [selectedMessage, setSelectedMessage] = useState(null)
  const [lastEncryptedPayload, setLastEncryptedPayload] = useState(null)
  const [status, setStatus] = useState({ type: 'idle', message: '' })
  const [loading, setLoading] = useState(false)

  const currentUser = useMemo(() => {
    const stored = localStorage.getItem('blu_user')
    return stored ? JSON.parse(stored) : null
  }, [])

  const selectedGroup = useMemo(() => {
    return groups.find((group) => group.id === selectedGroupId)
  }, [groups, selectedGroupId])

  const currentMessages = useMemo(() => {
    return messages
      .filter((message) => message.channel_id === selectedGroupId || message.group_id === selectedGroupId)
      .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
  }, [messages, selectedGroupId])

  const filteredGroups = groups.filter((group) =>
    group.name.toLowerCase().includes(searchTerm.toLowerCase()),
  )

  function showStatus(type, message) {
    setStatus({ type, message })
  }

  const refreshGroups = useCallback(async () => {
    setLoading(true)
    showStatus('loading', 'Cargando canales...')

    try {
      const loadedGroups = await loadUserGroups()
      setGroups(loadedGroups)
      setSelectedGroupId((currentGroupId) => currentGroupId || loadedGroups[0]?.id || '')
      showStatus('success', 'Canales cargados.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }, [])

  const refreshMessages = useCallback(async () => {
    if (!currentUser?.id) return

    setLoading(true)
    showStatus('loading', 'Cargando mensajes cifrados...')

    try {
      const encryptedMessages = await loadUserMessages(currentUser.id)
      const decryptedMessages = await decryptMessagesWithPrivateKey(
        encryptedMessages,
        privateKeyPem,
      )

      setMessages(decryptedMessages)
      showStatus('success', 'Mensajes actualizados.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }, [currentUser?.id, privateKeyPem])

  useEffect(() => {
    queueMicrotask(() => {
      refreshGroups()
    })
  }, [refreshGroups])

  useEffect(() => {
    queueMicrotask(() => {
      refreshMessages()
    })
  }, [refreshMessages])

  function handleSelectGroup(groupId) {
    setSelectedGroupId(groupId)
    setSelectedMessage(null)
  }

  function handleGroupFormChange(event) {
    const { name, value } = event.target
    setGroupForm((current) => ({ ...current, [name]: value }))
  }

  function handlePrivateKeyChange(event) {
    const { name, value } = event.target
    setPrivateKeyForm((current) => ({ ...current, [name]: value }))
  }

  async function handleCreateGroup(event) {
    event.preventDefault()
    setLoading(true)
    showStatus('loading', 'Creando canal...')

    try {
      const newGroup = await createGroup(groupForm)
      setGroups((currentGroups) => [newGroup, ...currentGroups])
      setSelectedGroupId(newGroup.id)
      setGroupForm(emptyGroupForm)
      showStatus('success', 'Canal creado. Ya puedes enviar mensajes cifrados.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleUnlockPrivateKey(event) {
    event.preventDefault()
    setLoading(true)
    showStatus('loading', 'Desbloqueando llave privada...')

    try {
      const encryptedPrivateKey = JSON.parse(privateKeyForm.encrypted_key_json)
      const decryptedPrivateKeyPem = await decryptPrivateKey(
        encryptedPrivateKey,
        privateKeyForm.password,
      )

      setPrivateKeyPem(decryptedPrivateKeyPem)
      setPrivateKeyForm((current) => ({ ...current, password: '' }))
      showStatus('success', 'Llave privada lista para descifrar mensajes.')
    } catch {
      showStatus('error', 'No se pudo desbloquear la llave privada cifrada.')
    } finally {
      setLoading(false)
    }
  }

  async function handleSendMessage(event) {
    event.preventDefault()

    const cleanMessage = messageText.trim()

    if (!cleanMessage || !selectedGroupId) return

    setLoading(true)
    showStatus('loading', 'Cifrando mensaje en el cliente...')

    try {
      const sentMessage = await sendEncryptedGroupMessage({
        group_id: selectedGroupId,
        content: cleanMessage,
      })
      const [displayMessage] = await decryptMessagesWithPrivateKey(
        [sentMessage],
        privateKeyPem,
      )

      setMessages((currentMessages) => [displayMessage, ...currentMessages])
      setSelectedMessage(displayMessage)
      setLastEncryptedPayload(sentMessage)
      setMessageText('')
      showStatus('success', 'Mensaje cifrado y guardado en Supabase.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="chats-page">
      <aside className="chats-sidebar">
        <div className="chats-brand">
          <div className="chats-logo">B</div>

          <div>
            <strong>Blu</strong>
            <span>Chats grupales</span>
          </div>
        </div>

        <div className="chats-search">
          <input
            type="text"
            placeholder="Buscar grupo..."
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
          />
        </div>

        <section className="groups-list">
          {filteredGroups.length === 0 ? (
            <p className="empty-text">No se encontraron grupos.</p>
          ) : (
            filteredGroups.map((group) => (
              <button
                key={group.id}
                className={`group-chat-card ${
                  selectedGroupId === group.id ? 'active' : ''
                }`}
                onClick={() => handleSelectGroup(group.id)}
              >
                <div className="group-icon">
                  {group.name.charAt(0).toUpperCase()}
                </div>

                <div className="group-info">
                  <div className="group-title-row">
                    <strong>{group.name}</strong>

                    {group.unread > 0 && (
                      <span className="unread-badge">{group.unread}</span>
                    )}
                  </div>

                  <span>{group.lastMessage}</span>
                  <span>{group.description}</span>
                </div>
              </button>
            ))
          )}
        </section>

        <form className="new-group-form" onSubmit={handleCreateGroup}>
          <input
            name="name"
            value={groupForm.name}
            onChange={handleGroupFormChange}
            placeholder="Nombre del canal"
            required
          />
          <textarea
            name="member_ids"
            value={groupForm.member_ids}
            onChange={handleGroupFormChange}
            placeholder="UUIDs de miembros separados por coma"
            required
          />
          <button className="new-group-button" disabled={loading}>
            Crear canal
          </button>
        </form>
      </aside>

      <section className="chat-main">
        <header className="chat-header">
          <div>
            <p className="section-label">Chat activo</p>
            <h1>{selectedGroup?.name || 'Grupo'}</h1>
            <span>{selectedGroup?.description}</span>
          </div>

          <div className="chat-status">
            <span className="status-dot"></span>
            {privateKeyPem ? 'Descifrado activo' : 'Grupo privado'}
          </div>
        </header>

        {status.message && (
          <p className={`chat-status-message ${status.type}`}>{status.message}</p>
        )}

        <section className="messages-area">
          {currentMessages.length === 0 ? (
            <p className="empty-chat-text">Selecciona un canal o envia el primer mensaje cifrado.</p>
          ) : (
            currentMessages.map((message) => (
              <article
                key={message.id}
                className={`message-bubble ${message.sender_id === currentUser?.id ? 'own' : ''}`}
                onClick={() => setSelectedMessage(message)}
              >
                <div className="message-meta">
                  <strong>{message.sender_id === currentUser?.id ? 'Tu' : 'Miembro'}</strong>
                  <span>{formatMessageTime(message.created_at)}</span>
                </div>

                <p>{message.plaintext || message.decrypt_error || 'Mensaje cifrado pendiente de descifrar'}</p>
                <small>{message.ciphertext_base64 ? 'AES-256-GCM guardado' : ''}</small>
              </article>
            ))
          )}
        </section>

        <form className="message-composer" onSubmit={handleSendMessage}>
          <input
            type="text"
            placeholder="Escribe un mensaje para el grupo..."
            value={messageText}
            onChange={(event) => setMessageText(event.target.value)}
          />

          <button type="submit" disabled={loading || !selectedGroupId}>
            {loading ? 'Procesando' : 'Enviar'}
          </button>
        </form>
      </section>

      <aside className="chat-details">
        <div className="details-card">
          <div className="details-avatar">
            {selectedGroup?.name?.charAt(0).toUpperCase() || 'G'}
          </div>

          <h2>{selectedGroup?.name}</h2>
          <p>{selectedGroup?.description}</p>
        </div>

        <form className="details-card key-card" onSubmit={handleUnlockPrivateKey}>
          <p className="section-label">Llave privada</p>
          <textarea
            name="encrypted_key_json"
            value={privateKeyForm.encrypted_key_json}
            onChange={handlePrivateKeyChange}
            placeholder='Pega aqui tu JSON de llave privada cifrada'
            required
          />
          <input
            name="password"
            type="password"
            value={privateKeyForm.password}
            onChange={handlePrivateKeyChange}
            placeholder="Contrasena"
            required
          />
          <button disabled={loading}>
            {privateKeyPem ? 'Llave desbloqueada' : 'Desbloquear'}
          </button>
        </form>

        <div className="details-card">
          <p className="section-label">Miembros</p>

          <div className="members-list">
            {selectedGroup?.members?.map((member) => (
              <div className="member-item" key={member.user_id || member}>
                <span>{(member.name || member).charAt(0).toUpperCase()}</span>
                <strong>{member.name || member}</strong>
              </div>
            ))}
          </div>
        </div>

        <div className="details-card">
          <p className="section-label">Seguridad</p>

          <div className="security-list">
            {cryptoFlowSteps.map((step, index) => (
              <span key={step}>{index + 1}. {step}</span>
            ))}
          </div>
        </div>

        <div className="details-card">
          <p className="section-label">Objeto almacenado</p>
          <PreviewValue label="Ciphertext" value={selectedMessage?.ciphertext_base64 || lastEncryptedPayload?.ciphertext_base64} />
          <PreviewValue label="Nonce" value={selectedMessage?.nonce_base64 || lastEncryptedPayload?.nonce_base64} />
          <PreviewValue label="Auth tag" value={selectedMessage?.auth_tag_base64 || lastEncryptedPayload?.auth_tag_base64} />
          <PreviewValue label="Encrypted keys" value={(selectedMessage?.encrypted_keys || lastEncryptedPayload?.encrypted_keys)?.length} />
        </div>
      </aside>
    </main>
  )
}

function formatMessageTime(timestamp) {
  if (!timestamp) return 'Ahora'

  return new Date(timestamp).toLocaleTimeString('es-GT', {
    hour: '2-digit',
    minute: '2-digit',
  })
}

function PreviewValue({ label, value }) {
  return (
    <div className="crypto-preview-row">
      <span>{label}</span>
      <code>{value || 'Pendiente'}</code>
    </div>
  )
}

export default Chats
