import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  createDirectConversation,
  decryptMessagesWithPrivateKey,
  loadUserMessages,
  sendEncryptedDirectMessage,
  loadContacts,
} from '../../services/messageService'
import { decryptPrivateKey } from '../../utils/privateKeyEncryption'
import '../Chats/Chats.css'

const emptyContactForm = {
  recipient_email: '',
}

const emptyPrivateKeyForm = {
  encrypted_key_json: '',
  password: '',
}

function preserveLocalPlaintext(nextMessages, currentMessages) {
  const plaintextByMessageId = new Map(
    currentMessages
      .filter((message) => message.plaintext)
      .map((message) => [message.id, message.plaintext]),
  )

  return nextMessages.map((message) => ({
    ...message,
    plaintext: message.plaintext || plaintextByMessageId.get(message.id) || '',
  }))
}

function DirectMessages() {
  const navigate = useNavigate()
  const [contacts, setContacts] = useState([])
  const [selectedContactId, setSelectedContactId] = useState('')
  const [messages, setMessages] = useState([])
  const [messageText, setMessageText] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [contactForm, setContactForm] = useState(emptyContactForm)
  const [privateKeyForm, setPrivateKeyForm] = useState(emptyPrivateKeyForm)
  const [privateKeyPem, setPrivateKeyPem] = useState('')
  const [selectedMessage, setSelectedMessage] = useState(null)
  const [lastEncryptedPayload, setLastEncryptedPayload] = useState(null)
  const [status, setStatus] = useState({ type: 'idle', message: '' })
  const [unlockStatus, setUnlockStatus] = useState({ type: 'idle', message: '' })
  const [loading, setLoading] = useState(false)
  const [showNewContactForm, setShowNewContactForm] = useState(false)
  const [showUnlockModal, setShowUnlockModal] = useState(true)

  const currentUser = useMemo(() => {
    const stored = localStorage.getItem('blu_user')
    return stored ? JSON.parse(stored) : null
  }, [])

  const selectedContact = useMemo(() => {
    return contacts.find((contact) => contact.id === selectedContactId)
  }, [contacts, selectedContactId])

  const currentMessages = useMemo(() => {
    if (!selectedContact?.channel_id) return []

    return messages
      .filter((message) => message.channel_id === selectedContact.channel_id)
      .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
  }, [messages, selectedContact])

  const filteredContacts = contacts.filter((contact) =>
    contact.email.toLowerCase().includes(searchTerm.toLowerCase()),
  )

  function showStatus(type, message) {
    setStatus({ type, message })
  }

  const refreshContacts = useCallback(async () => {
    setLoading(true)
    showStatus('loading', 'Cargando contactos...')

    try {
      const loadedContacts = await loadContacts()
      setContacts(loadedContacts)
      setSelectedContactId((currentContactId) => currentContactId || loadedContacts[0]?.id || '')
      showStatus('success', 'Contactos cargados.')
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

      setMessages((currentMessages) =>
        preserveLocalPlaintext(decryptedMessages, currentMessages),
      )
      showStatus('success', 'Mensajes actualizados.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }, [currentUser?.id, privateKeyPem])

  useEffect(() => {
    queueMicrotask(() => {
      refreshContacts()
    })
  }, [refreshContacts])

  useEffect(() => {
    queueMicrotask(() => {
      refreshMessages()
    })
  }, [refreshMessages])

  function handleSelectContact(contactId) {
    setSelectedContactId(contactId)
    setSelectedMessage(null)
    setShowNewContactForm(false)
  }

  function handleContactFormChange(event) {
    const { name, value } = event.target
    setContactForm((current) => ({ ...current, [name]: value }))
  }

  function handlePrivateKeyChange(event) {
    const { name, value } = event.target
    setPrivateKeyForm((current) => ({ ...current, [name]: value }))
  }

  async function handlePrivateKeyFileChange(event) {
    const file = event.target.files?.[0]
    if (!file) return

    try {
      const fileContent = await file.text()
      JSON.parse(fileContent)
      setPrivateKeyForm((current) => ({
        ...current,
        encrypted_key_json: fileContent,
      }))
      setUnlockStatus({ type: 'success', message: 'Archivo JSON cargado.' })
    } catch {
      setUnlockStatus({
        type: 'error',
        message: 'El archivo seleccionado no tiene un JSON valido.',
      })
    }
  }

  async function handleStartConversation(event) {
    event.preventDefault()
    setLoading(true)
    showStatus('loading', 'Iniciando conversación...')

    try {
      const newContact = await createDirectConversation(contactForm)

      setContacts((currentContacts) => {
        const exists = currentContacts.some((contact) => contact.id === newContact.id)
        if (exists) {
          return currentContacts.map((contact) =>
            contact.id === newContact.id ? { ...contact, ...newContact } : contact,
          )
        }

        return [newContact, ...currentContacts]
      })
      setSelectedContactId(newContact.id)
      setContactForm(emptyContactForm)
      setShowNewContactForm(false)
      showStatus('success', 'Conversación abierta.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleUnlockPrivateKey(event) {
    event.preventDefault()
    setLoading(true)
    setUnlockStatus({ type: 'loading', message: 'Desbloqueando llave privada...' })
    showStatus('loading', 'Desbloqueando llave privada...')

    try {
      const encryptedPrivateKey = JSON.parse(privateKeyForm.encrypted_key_json)
      const decryptedPrivateKeyPem = await decryptPrivateKey(
        encryptedPrivateKey,
        privateKeyForm.password,
      )

      setPrivateKeyPem(decryptedPrivateKeyPem)
      setPrivateKeyForm((current) => ({ ...current, password: '' }))
      setShowUnlockModal(false)
      setUnlockStatus({ type: 'success', message: 'Mensajes descifrados activos.' })
      showStatus('success', 'Llave privada lista para descifrar mensajes.')
    } catch {
      setUnlockStatus({
        type: 'error',
        message: 'No se pudo desbloquear. Revisa el archivo y la contrasena.',
      })
      showStatus('error', 'No se pudo desbloquear la llave privada cifrada.')
    } finally {
      setLoading(false)
    }
  }

  async function handleSendMessage(event) {
    event.preventDefault()

    const cleanMessage = messageText.trim()

    if (!cleanMessage || !selectedContact) return

    setLoading(true)
    showStatus('loading', 'Cifrando mensaje en el cliente...')

    try {
      const sentMessage = await sendEncryptedDirectMessage({
        recipient_id: selectedContact.id,
        recipient_email: selectedContact.email,
        content: cleanMessage,
      })
      const [displayMessage] = await decryptMessagesWithPrivateKey(
        [sentMessage],
        privateKeyPem,
      )
      const messageForChat = {
        ...displayMessage,
        plaintext: displayMessage.plaintext || cleanMessage,
        decrypt_error: '',
      }

      setMessages((currentMessages) => [messageForChat, ...currentMessages])
      setContacts((currentContacts) =>
        currentContacts.map((contact) =>
          contact.id === selectedContact.id && !contact.channel_id
            ? { ...contact, channel_id: sentMessage.channel_id }
            : contact,
        ),
      )
      setSelectedMessage(messageForChat)
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
    <>
    {showUnlockModal && (
      <div className="unlock-modal-backdrop" role="presentation">
        <section className="unlock-modal" role="dialog" aria-modal="true" aria-labelledby="unlock-title">
          <button
            type="button"
            className="unlock-close-button"
            aria-label="Cerrar"
            onClick={() => setShowUnlockModal(false)}
          >
            x
          </button>

          <div>
            <p className="section-label">Mensajes directos</p>
            <h2 id="unlock-title">Quieres ver los mensajes descifrados?</h2>
            <p>
              Sube tu archivo JSON de llave privada cifrada y escribe tu contrasena.
              Si cierras esta ventana, veras los mensajes en formato cifrado.
            </p>
          </div>

          <form className="unlock-form" onSubmit={handleUnlockPrivateKey}>
            <label>
              Archivo JSON
              <input
                type="file"
                accept=".json,application/json"
                onChange={handlePrivateKeyFileChange}
                required={!privateKeyForm.encrypted_key_json}
              />
            </label>

            <label>
              Contrasena
              <input
                name="password"
                type="password"
                value={privateKeyForm.password}
                onChange={handlePrivateKeyChange}
                placeholder="Contrasena de registro"
                required
              />
            </label>

            {unlockStatus.message && (
              <p className={`chat-status-message ${unlockStatus.type}`}>
                {unlockStatus.message}
              </p>
            )}

            <button disabled={loading || !privateKeyForm.encrypted_key_json}>
              {loading ? 'Desbloqueando' : 'Desbloquear mensajes'}
            </button>
          </form>
        </section>
      </div>
    )}

    <main className="chats-page">
      <aside className="chats-sidebar">
        <div className="chats-brand">
          <div className="chats-logo">B</div>

          <div>
            <strong>Blu</strong>
            <span>Mensajes directos</span>
          </div>
        </div>

        <button
          type="button"
          className="back-dashboard-button"
          onClick={() => navigate('/blu')}
        >
          Volver al panel principal
        </button>

        <div className="chats-search">
          <input
            type="text"
            placeholder="Buscar contacto..."
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
          />
        </div>

        <section className="groups-list">
          {filteredContacts.length === 0 ? (
            <p className="empty-text">No hay contactos. Inicia una conversación.</p>
          ) : (
            filteredContacts.map((contact) => (
              <button
                key={contact.id}
                className={`group-chat-card ${
                  selectedContactId === contact.id ? 'active' : ''
                }`}
                onClick={() => handleSelectContact(contact.id)}
              >
                <div className="group-icon">
                  {contact.name.charAt(0).toUpperCase()}
                </div>

                <div className="group-info">
                  <div className="group-title-row">
                    <strong>{contact.name}</strong>
                  </div>

                  <span>{contact.email}</span>
                </div>
              </button>
            ))
          )}
        </section>

        {showNewContactForm ? (
          <form className="new-group-form" onSubmit={handleStartConversation}>
            <input
              name="recipient_email"
              value={contactForm.recipient_email}
              onChange={handleContactFormChange}
              placeholder="Email del contacto"
              type="email"
              required
            />
            <button className="new-group-button" disabled={loading}>
              Iniciar chat
            </button>
            <button
              type="button"
              className="new-group-button"
              onClick={() => {
                setShowNewContactForm(false)
                setContactForm(emptyContactForm)
              }}
              style={{ opacity: 0.6 }}
            >
              Cancelar
            </button>
          </form>
        ) : (
          <button
            className="new-group-button"
            onClick={() => setShowNewContactForm(true)}
            style={{ marginTop: '1rem' }}
          >
            + Nuevo chat
          </button>
        )}
      </aside>

      <section className="chat-main">
        <header className="chat-header">
          <div>
            <p className="section-label">Chat personal</p>
            <h1>{selectedContact?.name || 'Contacto'}</h1>
            <span>{selectedContact?.email}</span>
          </div>

          <div className="chat-status">
            <span className="status-dot"></span>
            {privateKeyPem ? 'Descifrado activo' : 'Chat privado'}
          </div>
        </header>

        {status.message && (
          <p className={`chat-status-message ${status.type}`}>{status.message}</p>
        )}

        <section className="messages-area">
          {currentMessages.length === 0 ? (
            <p className="empty-chat-text">Selecciona un contacto o envia el primer mensaje cifrado.</p>
          ) : (
            currentMessages.map((message) => (
              <article
                key={message.id}
                className={`message-bubble ${message.sender_id === currentUser?.id ? 'own' : ''}`}
                onClick={() => setSelectedMessage(message)}
              >
                <div className="message-meta">
                  <strong>{message.sender_id === currentUser?.id ? 'Tu' : 'Contacto'}</strong>
                  <span>{formatMessageTime(message.created_at)}</span>
                </div>

                <p>{formatMessageContent(message, privateKeyPem)}</p>
                <small>{message.ciphertext_base64 ? 'AES-256-GCM guardado' : ''}</small>
              </article>
            ))
          )}
        </section>

        <form className="message-composer" onSubmit={handleSendMessage}>
          <input
            type="text"
            placeholder="Escribe un mensaje cifrado..."
            value={messageText}
            onChange={(event) => setMessageText(event.target.value)}
          />

          <button type="submit" disabled={loading || !selectedContact}>
            {loading ? 'Procesando' : 'Enviar'}
          </button>
        </form>
      </section>

      <aside className="chat-details">
        <div className="details-card">
          <div className="details-avatar">
            {selectedContact?.name?.charAt(0).toUpperCase() || 'C'}
          </div>

          <h2>{selectedContact?.name}</h2>
          <p>{selectedContact?.email}</p>
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
          <p className="section-label">Seguridad end-to-end</p>

          <div className="security-list">
            <span>1. El usuario escribe un mensaje.</span>
            <span>2. El cliente genera una clave AES-256 efimera.</span>
            <span>3. El cliente genera un nonce unico.</span>
            <span>4. El mensaje se cifra con AES-256-GCM.</span>
            <span>5. La clave AES se cifra con RSA-OAEP usando la llave publica del destinatario.</span>
            <span>6. Supabase guarda ciphertext, nonce, tag y timestamp.</span>
            <span>7. Solo el destinatario puede descifrar con su llave privada.</span>
          </div>
        </div>

        <div className="details-card">
          <p className="section-label">Objeto almacenado</p>
          <PreviewValue label="Ciphertext" value={selectedMessage?.ciphertext_base64 || lastEncryptedPayload?.ciphertext_base64} />
          <PreviewValue label="Nonce" value={selectedMessage?.nonce_base64 || lastEncryptedPayload?.nonce_base64} />
          <PreviewValue label="Auth tag" value={selectedMessage?.auth_tag_base64 || lastEncryptedPayload?.auth_tag_base64} />
          <PreviewValue label="Encrypted key" value={selectedMessage?.encrypted_keys?.[0]?.encrypted_key_base64 || lastEncryptedPayload?.encrypted_keys?.[0]?.encrypted_key_base64} />
        </div>
      </aside>
    </main>
    </>
  )
}

function formatMessageTime(timestamp) {
  if (!timestamp) return 'Ahora'

  return new Date(timestamp).toLocaleTimeString('es-GT', {
    hour: '2-digit',
    minute: '2-digit',
  })
}

function formatMessageContent(message, privateKeyPem) {
  if (message.plaintext) return message.plaintext
  if (privateKeyPem && message.decrypt_error) return message.decrypt_error
  if (message.ciphertext_base64) return `Cifrado: ${message.ciphertext_base64}`
  return 'Mensaje cifrado'
}

function PreviewValue({ label, value }) {
  return (
    <div className="crypto-preview-row">
      <span>{label}</span>
      <code>{value || 'Pendiente'}</code>
    </div>
  )
}

export default DirectMessages
