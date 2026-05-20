import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  createDirectConversation,
  decryptMessagesWithPrivateKey,
  loadBlockchain,
  loadContacts,
  loadUserMessages,
  sendEncryptedDirectMessage,
  tamperBlockchainBlock,
  verifyBlockchainIntegrity,
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

  const [blockchainBlocks, setBlockchainBlocks] = useState([])
  const [blockchainVerification, setBlockchainVerification] = useState(null)
  const [blockchainLoading, setBlockchainLoading] = useState(false)

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

  const refreshBlockchain = useCallback(async (silent = false) => {
    if (!silent) setBlockchainLoading(true)

    try {
      const [blocks, verification] = await Promise.all([
        loadBlockchain(),
        verifyBlockchainIntegrity(),
      ])

      setBlockchainBlocks(blocks)
      setBlockchainVerification(verification)
    } catch (error) {
      if (silent) {
        console.warn('[blockchain] No se pudo actualizar la cadena:', error.message)
      } else {
        showStatus('error', error.message)
      }
    } finally {
      if (!silent) setBlockchainLoading(false)
    }
  }, [])

  const refreshContacts = useCallback(async (silent = false) => {
    if (!silent) {
      setLoading(true)
      showStatus('loading', 'Cargando contactos...')
    }

    try {
      const loadedContacts = await loadContacts()

      setContacts(loadedContacts)
      setSelectedContactId(
        (currentContactId) => currentContactId || loadedContacts[0]?.id || '',
      )

      if (!silent) showStatus('success', 'Contactos cargados.')
    } catch (error) {
      if (silent) {
        console.warn('[direct] No se pudieron actualizar contactos:', error.message)
      } else {
        showStatus('error', error.message)
      }
    } finally {
      if (!silent) setLoading(false)
    }
  }, [])

  const refreshMessages = useCallback(async (silent = false) => {
    if (!currentUser?.id) return

    if (!silent) {
      setLoading(true)
      showStatus('loading', 'Cargando mensajes cifrados...')
    }

    try {
      const encryptedMessages = await loadUserMessages(currentUser.id)

      const decryptedMessages = await decryptMessagesWithPrivateKey(
        encryptedMessages,
        privateKeyPem,
      )

      setMessages((currentMessages) =>
        preserveLocalPlaintext(decryptedMessages, currentMessages),
      )

      if (!silent) showStatus('success', 'Mensajes actualizados.')
    } catch (error) {
      if (silent) {
        console.warn('[direct] No se pudieron actualizar mensajes:', error.message)
      } else {
        showStatus('error', error.message)
      }
    } finally {
      if (!silent) setLoading(false)
    }
  }, [currentUser?.id, privateKeyPem])

  useEffect(() => {
    queueMicrotask(() => {
      refreshContacts()
      refreshBlockchain()
    })
  }, [refreshContacts, refreshBlockchain])

  useEffect(() => {
    queueMicrotask(() => {
      refreshMessages()
    })
  }, [refreshMessages])

  useEffect(() => {
    if (!currentUser?.id) return

    const messagesInterval = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        refreshMessages(true)
      }
    }, 5000)

    const contactsInterval = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        refreshContacts(true)
      }
    }, 30000)

    const blockchainInterval = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        refreshBlockchain(true)
      }
    }, 15000)

    return () => {
      window.clearInterval(messagesInterval)
      window.clearInterval(contactsInterval)
      window.clearInterval(blockchainInterval)
    }
  }, [currentUser?.id, refreshContacts, refreshMessages, refreshBlockchain])

  function handleSelectContact(contactId) {
    setSelectedContactId(contactId)
    setSelectedMessage(null)
    setShowNewContactForm(false)
  }

  function handleContactFormChange(event) {
    const { name, value } = event.target

    setContactForm((current) => ({
      ...current,
      [name]: value,
    }))
  }

  function handlePrivateKeyChange(event) {
    const { name, value } = event.target

    setPrivateKeyForm((current) => ({
      ...current,
      [name]: value,
    }))
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

      setUnlockStatus({
        type: 'success',
        message: 'Archivo JSON cargado.',
      })
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
        const exists = currentContacts.some(
          (contact) => contact.id === newContact.id,
        )

        if (exists) {
          return currentContacts.map((contact) =>
            contact.id === newContact.id
              ? { ...contact, ...newContact }
              : contact,
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
    setUnlockStatus({
      type: 'loading',
      message: 'Desbloqueando llave privada...',
    })
    showStatus('loading', 'Desbloqueando llave privada...')

    try {
      const encryptedPrivateKey = JSON.parse(privateKeyForm.encrypted_key_json)

      const decryptedPrivateKeyPem = await decryptPrivateKey(
        encryptedPrivateKey,
        privateKeyForm.password,
      )

      setPrivateKeyPem(decryptedPrivateKeyPem)

      setPrivateKeyForm((current) => ({
        ...current,
        password: '',
      }))

      setShowUnlockModal(false)

      setUnlockStatus({
        type: 'success',
        message: 'Mensajes descifrados activos.',
      })

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

    if (!privateKeyPem) {
      showStatus(
        'error',
        'Desbloquea tu llave privada para firmar el mensaje antes de enviarlo.',
      )
      setShowUnlockModal(true)
      return
    }

    setLoading(true)
    showStatus('loading', 'Cifrando mensaje en el cliente...')

    try {
      const sentMessage = await sendEncryptedDirectMessage({
        recipient_id: selectedContact.id,
        recipient_email: selectedContact.email,
        content: cleanMessage,
        signer_private_key_pem: privateKeyPem,
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

      await refreshBlockchain()

      showStatus('success', 'Mensaje cifrado, enviado y registrado en blockchain.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleTamperBlock(blockIndex) {
    setBlockchainLoading(true)
    showStatus('loading', `Modificando bloque #${blockIndex} para demo...`)

    try {
      const result = await tamperBlockchainBlock(blockIndex)

      setBlockchainVerification(result.verification)

      await refreshBlockchain()

      showStatus(
        'success',
        `Bloque #${blockIndex} modificado. La cadena ahora debe aparecer como invalida.`,
      )
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setBlockchainLoading(false)
    }
  }

  return (
    <>
      {showUnlockModal && (
        <div className="unlock-modal-backdrop" role="presentation">
          <section
            className="unlock-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="unlock-title"
          >
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
                Sube tu archivo JSON de llave privada cifrada y escribe tu
                contrasena. Si cierras esta ventana, veras los mensajes en
                formato cifrado.
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
              <p className="empty-text">
                No hay contactos. Inicia una conversación.
              </p>
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

          <div className="sidebar-actions">
            {showNewContactForm ? (
              <form className="new-group-form" onSubmit={handleStartConversation}>
                <p className="section-label">Nuevo chat</p>

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
                  className="new-group-button secondary"
                  onClick={() => {
                    setShowNewContactForm(false)
                    setContactForm(emptyContactForm)
                  }}
                >
                  Cancelar
                </button>
              </form>
            ) : (
              <button
                className="new-group-button"
                onClick={() => setShowNewContactForm(true)}
              >
                + Nuevo chat
              </button>
            )}
          </div>
        </aside>

        <section className="chat-main">
          <header className="chat-header cool-chat-header">
            <div>
              <p className="section-label">Chat personal</p>
              <h1>{selectedContact?.name || 'Contacto'}</h1>
              <span>
                {selectedContact?.email ||
                  'Selecciona un contacto para empezar a conversar.'}
              </span>
            </div>

            <div className="chat-status">
              <span className="status-dot"></span>
              {privateKeyPem ? 'Descifrado activo' : 'Chat privado'}
            </div>
          </header>

          {status.message && (
            <p className={`chat-status-message ${status.type}`}>
              {status.message}
            </p>
          )}

          <section className="messages-area">
            {currentMessages.length === 0 ? (
              <div className="empty-chat-card">
                <span>💬</span>
                <h2>Sin mensajes</h2>
                <p>
                  Selecciona un contacto o envia el primer mensaje cifrado.
                </p>
              </div>
            ) : (
              currentMessages.map((message) => (
                <article
                  key={message.id}
                  className={`message-bubble ${
                    message.sender_id === currentUser?.id ? 'own' : ''
                  }`}
                  onClick={() => setSelectedMessage(message)}
                >
                  <div className="message-meta">
                    <strong>
                      {message.sender_id === currentUser?.id ? 'Tú' : 'Contacto'}
                    </strong>
                    <span>{formatMessageTime(message.created_at)}</span>
                  </div>

                  <p>{formatMessageContent(message, privateKeyPem)}</p>

                  <div className="message-tags">
                    <SignatureStatus status={message.signature_status} />
                    {message.ciphertext_base64 && <small>AES-256-GCM</small>}
                    {message.plaintext_hash && <small>SHA-256</small>}
                  </div>
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
          <div className="details-card group-summary-card">
            <div className="details-avatar">
              {selectedContact?.name?.charAt(0).toUpperCase() || 'C'}
            </div>

            <h2>{selectedContact?.name || 'Sin contacto'}</h2>
            <p>{selectedContact?.email || 'Selecciona un contacto.'}</p>
          </div>

          <form className="details-card key-card" onSubmit={handleUnlockPrivateKey}>
            <p className="section-label">Llave privada</p>

            <textarea
              name="encrypted_key_json"
              value={privateKeyForm.encrypted_key_json}
              onChange={handlePrivateKeyChange}
              placeholder="Pega aqui tu JSON de llave privada cifrada"
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

          <div className="details-card blockchain-card">
            <div className="blockchain-header">
              <div>
                <p className="section-label">Mini Blockchain</p>
                <h3>Bloques registrados</h3>
              </div>

              <button
                type="button"
                className="blockchain-refresh-button"
                onClick={() => refreshBlockchain()}
                disabled={blockchainLoading}
              >
                {blockchainLoading ? 'Cargando' : 'Actualizar'}
              </button>
            </div>

            {blockchainVerification && (
              <div
                className={`blockchain-status ${
                  blockchainVerification.valid ? 'valid' : 'invalid'
                }`}
              >
                {blockchainVerification.valid
                  ? `Cadena valida (${blockchainVerification.blocks || blockchainBlocks.length} bloques)`
                  : `Cadena invalida en bloque #${blockchainVerification.invalid_index}`}
              </div>
            )}

            <div className="blockchain-list">
              {blockchainBlocks.length === 0 ? (
                <p className="empty-text">Aun no hay bloques registrados.</p>
              ) : (
                blockchainBlocks.map((block) => (
                  <article
                    key={block.id || block.index}
                    className={`blockchain-block ${
                      blockchainVerification?.invalid_index === block.index
                        ? 'invalid'
                        : ''
                    }`}
                  >
                    <div className="blockchain-block-title">
                      <strong>Bloque #{block.index}</strong>
                      <span>{block.index === 0 ? 'Genesis' : 'Mensaje'}</span>
                    </div>

                    <div className="blockchain-row">
                      <span>Mensaje</span>
                      <code>{block.message_id || 'GENESIS'}</code>
                    </div>

                    <div className="blockchain-row">
                      <span>Hash mensaje</span>
                      <code>{shortHash(block.message_hash)}</code>
                    </div>

                    <div className="blockchain-row">
                      <span>Hash anterior</span>
                      <code>{shortHash(block.previous_hash)}</code>
                    </div>

                    <div className="blockchain-row">
                      <span>Hash bloque</span>
                      <code>{shortHash(block.hash)}</code>
                    </div>

                    <div className="blockchain-row">
                      <span>Nonce</span>
                      <code>{block.nonce}</code>
                    </div>

                    {block.index !== 0 && (
                      <button
                        type="button"
                        className="tamper-block-button"
                        onClick={() => handleTamperBlock(block.index)}
                        disabled={blockchainLoading}
                      >
                        Modificar bloque
                      </button>
                    )}
                  </article>
                ))
              )}
            </div>
          </div>

          <div className="details-card">
            <p className="section-label">Objeto almacenado</p>

            <PreviewValue
              label="Ciphertext"
              value={
                selectedMessage?.ciphertext_base64 ||
                lastEncryptedPayload?.ciphertext_base64
              }
            />

            <PreviewValue
              label="Nonce"
              value={
                selectedMessage?.nonce_base64 ||
                lastEncryptedPayload?.nonce_base64
              }
            />

            <PreviewValue
              label="Auth tag"
              value={
                selectedMessage?.auth_tag_base64 ||
                lastEncryptedPayload?.auth_tag_base64
              }
            />

            <PreviewValue
              label="Encrypted key"
              value={
                selectedMessage?.encrypted_keys?.[0]?.encrypted_key_base64 ||
                lastEncryptedPayload?.encrypted_keys?.[0]?.encrypted_key_base64
              }
            />

            <PreviewValue
              label="Plaintext hash"
              value={
                selectedMessage?.plaintext_hash ||
                lastEncryptedPayload?.plaintext_hash
              }
            />
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

function SignatureStatus({ status }) {
  if (!status) return null

  const labelByStatus = {
    valid: 'Firma verificada',
    invalid: 'Firma NO VERIFICADA',
    unsigned: 'Sin firma digital',
    'missing-public-key': 'Firma sin llave publica',
    unknown: 'Firma pendiente',
  }

  return (
    <span className={`signature-badge ${status}`}>
      {labelByStatus[status] || 'Firma pendiente'}
    </span>
  )
}

function PreviewValue({ label, value }) {
  return (
    <div className="crypto-preview-row">
      <span>{label}</span>
      <code>{value || 'Pendiente'}</code>
    </div>
  )
}

function shortHash(value) {
  if (!value) return 'N/A'

  const cleanValue = String(value)

  if (cleanValue.length <= 22) return cleanValue

  return `${cleanValue.slice(0, 10)}...${cleanValue.slice(-8)}`
}

export default DirectMessages