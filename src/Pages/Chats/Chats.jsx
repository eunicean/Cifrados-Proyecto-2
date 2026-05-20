import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  createGroup,
  decryptGroupMessages,
  deriveGroupAesKey,
  joinGroupWithCode,
  loadBlockchain,
  loadGroupMessages,
  loadUserGroups,
  searchGroupsByName,
  sendGroupMessage,
  tamperBlockchainBlock,
  verifyBlockchainIntegrity,
} from '../../services/messageService'
import { decryptPrivateKey } from '../../utils/privateKeyEncryption'
import './Chats.css'

function Chats() {
  const navigate = useNavigate()

  const [groups, setGroups] = useState([])
  const [selectedGroupId, setSelectedGroupId] = useState('')
  const [messages, setMessages] = useState([])
  const [messageText, setMessageText] = useState('')

  const [myGroupsFilter, setMyGroupsFilter] = useState('')
  const [newGroupName, setNewGroupName] = useState('')
  const [codeInput, setCodeInput] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [createdGroupCode, setCreatedGroupCode] = useState('')

  const [status, setStatus] = useState({ type: 'idle', message: '' })
  const [loading, setLoading] = useState(false)

  const [lastEncryptedPayload, setLastEncryptedPayload] = useState(null)
  const [selectedMessage, setSelectedMessage] = useState(null)

  const [blockchainBlocks, setBlockchainBlocks] = useState([])
  const [blockchainVerification, setBlockchainVerification] = useState(null)
  const [blockchainLoading, setBlockchainLoading] = useState(false)

  const [signatureKeyForm, setSignatureKeyForm] = useState({
    encrypted_key_json: '',
    password: '',
  })
  const [signaturePrivateKeyPem, setSignaturePrivateKeyPem] = useState('')

  const groupKeysRef = useRef({})
  const [unlockedGroupIds, setUnlockedGroupIds] = useState(new Set())

  const currentUser = useMemo(() => {
    const stored = localStorage.getItem('blu_user')
    return stored ? JSON.parse(stored) : null
  }, [])

  const selectedGroup = useMemo(
    () => groups.find((group) => group.id === selectedGroupId),
    [groups, selectedGroupId],
  )

  const filteredGroups = useMemo(
    () =>
      groups.filter((group) =>
        group.name.toLowerCase().includes(myGroupsFilter.toLowerCase()),
      ),
    [groups, myGroupsFilter],
  )

  const isUnlocked = unlockedGroupIds.has(selectedGroupId)

  const selectedGroupInviteCode =
    selectedGroup?.invite_code ||
    (selectedGroup?.created_by === currentUser?.id ? createdGroupCode : '')

  function showStatus(type, message) {
    setStatus({ type, message })
  }

  const refreshGroups = useCallback(async (silent = false) => {
    try {
      const loadedGroups = await loadUserGroups()

      setGroups(loadedGroups)
      setSelectedGroupId((currentGroupId) => currentGroupId || loadedGroups[0]?.id || '')
    } catch (error) {
      if (silent) {
        console.warn('[groups] No se pudieron actualizar grupos:', error.message)
      } else {
        showStatus('error', error.message)
      }
    }
  }, [])

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

  const refreshSelectedGroupMessages = useCallback(async (silent = false) => {
    if (!selectedGroupId || !unlockedGroupIds.has(selectedGroupId)) return

    if (!silent) {
      setLoading(true)
      showStatus('loading', 'Cargando mensajes...')
    }

    try {
      const rawMessages = await loadGroupMessages(selectedGroupId)
      const groupKey = groupKeysRef.current[selectedGroupId]
      const decryptedMessages = await decryptGroupMessages(rawMessages, groupKey)

      setMessages(decryptedMessages)
      if (!silent) showStatus('success', 'Mensajes cargados.')
    } catch (error) {
      if (silent) {
        console.warn('[groups] No se pudieron actualizar mensajes:', error.message)
      } else {
        showStatus('error', error.message)
      }
    } finally {
      if (!silent) setLoading(false)
    }
  }, [selectedGroupId, unlockedGroupIds])

  useEffect(() => {
    queueMicrotask(() => {
      refreshGroups()
    })
  }, [refreshGroups])

  useEffect(() => {
    queueMicrotask(() => {
      refreshBlockchain()
    })
  }, [refreshBlockchain])

  useEffect(() => {
    if (!currentUser?.id || groups.length === 0) return

    let cancelled = false

    async function unlockCreatorGroups() {
      const creatorGroups = groups.filter(
        (group) =>
          group.created_by === currentUser.id &&
          group.invite_code &&
          !groupKeysRef.current[group.id],
      )

      if (creatorGroups.length === 0) return

      const unlockedGroups = await Promise.all(
        creatorGroups.map(async (group) => ({
          id: group.id,
          key: await deriveGroupAesKey(group.invite_code, group.id),
        })),
      )

      if (cancelled) return

      unlockedGroups.forEach((group) => {
        groupKeysRef.current[group.id] = group.key
      })

      setUnlockedGroupIds((current) =>
        new Set([...current, ...unlockedGroups.map((group) => group.id)]),
      )
    }

    unlockCreatorGroups()

    return () => {
      cancelled = true
    }
  }, [groups, currentUser?.id])

  useEffect(() => {
    if (!selectedGroupId || !isUnlocked) return

    let cancelled = false

    async function loadMessages() {
      try {
        if (!cancelled) {
          await refreshSelectedGroupMessages()
        }
      } catch {
        // refreshSelectedGroupMessages already reports visible errors.
      }
    }

    loadMessages()

    return () => {
      cancelled = true
    }
  }, [selectedGroupId, isUnlocked, refreshSelectedGroupMessages])

  useEffect(() => {
    const groupsInterval = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        refreshGroups(true)
      }
    }, 30000)

    const blockchainInterval = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        refreshBlockchain(true)
      }
    }, 15000)

    return () => {
      window.clearInterval(groupsInterval)
      window.clearInterval(blockchainInterval)
    }
  }, [refreshBlockchain, refreshGroups])

  useEffect(() => {
    if (!selectedGroupId || !isUnlocked) return

    const messagesInterval = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        refreshSelectedGroupMessages(true)
      }
    }, 5000)

    return () => {
      window.clearInterval(messagesInterval)
    }
  }, [selectedGroupId, isUnlocked, refreshSelectedGroupMessages])

  function handleSelectGroup(groupId) {
    setSelectedGroupId(groupId)
    setMessages([])
    setSelectedMessage(null)
    setLastEncryptedPayload(null)
    setCodeInput('')
    setCreatedGroupCode('')
  }

  async function handleCreateGroup(event) {
    event.preventDefault()

    const cleanGroupName = newGroupName.trim()
    if (!cleanGroupName) return

    setLoading(true)
    showStatus('loading', 'Creando grupo...')

    try {
      const data = await createGroup(cleanGroupName)
      const group = data.group || data
      const code = data.code
      const groupWithCode = code ? { ...group, invite_code: code } : group

      setGroups((currentGroups) => [groupWithCode, ...currentGroups])
      setNewGroupName('')

      if (code) {
        setCreatedGroupCode(code)

        const aesKey = await deriveGroupAesKey(code, group.id)
        groupKeysRef.current[group.id] = aesKey

        setUnlockedGroupIds((current) => new Set([...current, group.id]))
        setSelectedGroupId(group.id)

        showStatus('success', 'Grupo creado. Comparte el código con los miembros.')
      }
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleSearch(event) {
    event.preventDefault()

    const cleanSearch = searchQuery.trim()
    if (!cleanSearch) return

    setLoading(true)

    try {
      const results = await searchGroupsByName(cleanSearch)

      setSearchResults(results)

      if (results.length === 0) {
        showStatus('idle', 'No se encontraron grupos con ese nombre.')
      }
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  function handleSelectSearchResult(group) {
    setSelectedGroupId(group.id)
    setMessages([])
    setSelectedMessage(null)
    setLastEncryptedPayload(null)
    setCodeInput('')
    setCreatedGroupCode('')
    setSearchResults([])
    setSearchQuery('')

    if (!groups.find((currentGroup) => currentGroup.id === group.id)) {
      setGroups((currentGroups) => [group, ...currentGroups])
    }
  }

  async function handleJoinOrUnlock(event) {
    event.preventDefault()

    const cleanCode = codeInput.trim()

    if (!cleanCode || !selectedGroupId) return

    setLoading(true)
    showStatus('loading', 'Verificando código...')

    try {
      await joinGroupWithCode(selectedGroupId, cleanCode)

      const aesKey = await deriveGroupAesKey(cleanCode, selectedGroupId)
      groupKeysRef.current[selectedGroupId] = aesKey

      setUnlockedGroupIds((current) => new Set([...current, selectedGroupId]))
      setCodeInput('')

      await refreshGroups()

      showStatus('success', 'Grupo desbloqueado.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleSendMessage(event) {
    event.preventDefault()

    const cleanMessage = messageText.trim()

    if (!cleanMessage || !selectedGroupId) return

    const aesKey = groupKeysRef.current[selectedGroupId]

    if (!aesKey) {
      showStatus('error', 'Ingresa el código del grupo primero.')
      return
    }

    if (!signaturePrivateKeyPem) {
      showStatus('error', 'Activa tu llave de firma antes de enviar mensajes.')
      return
    }

    setLoading(true)
    showStatus('loading', 'Cifrando mensaje...')

    try {
      const sentMessage = await sendGroupMessage(
        selectedGroupId,
        cleanMessage,
        aesKey,
        signaturePrivateKeyPem,
      )

      const [decryptedMessage] = await decryptGroupMessages([sentMessage], aesKey)

      setMessages((currentMessages) => [...currentMessages, decryptedMessage])
      setLastEncryptedPayload(sentMessage)
      setSelectedMessage(decryptedMessage)
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

  async function handleSignatureKeyFileChange(event) {
    const file = event.target.files?.[0]
    if (!file) return

    try {
      const content = await file.text()
      JSON.parse(content)

      setSignatureKeyForm((current) => ({
        ...current,
        encrypted_key_json: content,
      }))

      showStatus('success', 'Archivo de firma cargado.')
    } catch {
      showStatus('error', 'El archivo de llave privada no tiene JSON valido.')
    }
  }

  async function handleUnlockSignatureKey(event) {
    event.preventDefault()

    try {
      const encryptedPrivateKey = JSON.parse(signatureKeyForm.encrypted_key_json)
      const privateKeyPem = await decryptPrivateKey(
        encryptedPrivateKey,
        signatureKeyForm.password,
      )

      setSignaturePrivateKeyPem(privateKeyPem)
      setSignatureKeyForm((current) => ({
        ...current,
        password: '',
      }))

      showStatus('success', 'Llave de firma lista. Los mensajes saldran firmados.')
    } catch {
      showStatus('error', 'No se pudo desbloquear la llave para firmar.')
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

        <button
          type="button"
          className="back-dashboard-button"
          onClick={() => navigate('/login')}
        >
          Volver al panel principal
        </button>

        <div className="chats-search">
          <input
            type="text"
            placeholder="Filtrar mis grupos..."
            value={myGroupsFilter}
            onChange={(event) => setMyGroupsFilter(event.target.value)}
          />
        </div>

        <section className="groups-list">
          {filteredGroups.length === 0 ? (
            <p className="empty-text">No hay grupos.</p>
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

                    {!unlockedGroupIds.has(group.id) && (
                      <span className="locked-pill">Bloqueado</span>
                    )}
                  </div>

                  <span>{group.description}</span>
                </div>
              </button>
            ))
          )}
        </section>

        <div className="sidebar-actions">
          <form className="new-group-form" onSubmit={handleSearch}>
            <p className="section-label">Buscar grupo</p>

            <div className="sidebar-inline-form">
              <input
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.target.value)}
                placeholder="Nombre del grupo..."
              />

              <button type="submit" disabled={loading}>
                Buscar
              </button>
            </div>

            {searchResults.length > 0 && (
              <div className="sidebar-results">
                {searchResults.map((result) => (
                  <button
                    key={result.id}
                    type="button"
                    className="group-chat-card"
                    onClick={() => handleSelectSearchResult(result)}
                  >
                    <div className="group-icon">
                      {result.name.charAt(0).toUpperCase()}
                    </div>

                    <div className="group-info">
                      <strong>{result.name}</strong>
                      <span>
                        {result.is_member ? 'Ya eres miembro' : 'Unete con codigo'}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </form>

          <form className="new-group-form" onSubmit={handleCreateGroup}>
            <p className="section-label">Crear grupo</p>

            <input
              value={newGroupName}
              onChange={(event) => setNewGroupName(event.target.value)}
              placeholder="Nombre del grupo"
              required
            />

            <button className="new-group-button" disabled={loading}>
              Crear canal
            </button>
          </form>
        </div>
      </aside>

      <section className="chat-main">
        <header className="chat-header cool-chat-header">
          <div>
            <p className="section-label">Chat activo</p>
            <h1>{selectedGroup?.name || 'Grupo'}</h1>
            <span>
              {selectedGroup?.description ||
                'Selecciona un grupo para empezar a conversar.'}
            </span>
          </div>

          <div className="chat-status">
            <span className="status-dot"></span>
            {isUnlocked ? 'Descifrado activo' : 'Ingresa el código'}
          </div>
        </header>

        {status.message && (
          <p className={`chat-status-message ${status.type}`}>
            {status.message}
          </p>
        )}

        {!selectedGroupId ? (
          <div className="messages-area empty-chat-panel">
            <div className="empty-chat-card">
              <span>💬</span>
              <h2>Selecciona un grupo</h2>
              <p>Elige un chat de la izquierda o crea uno nuevo para iniciar.</p>
            </div>
          </div>
        ) : !isUnlocked ? (
          <div className="messages-area empty-chat-panel">
            <form className="unlock-group-card" onSubmit={handleJoinOrUnlock}>
              <span>🔐</span>
              <h2>Grupo protegido</h2>
              <p>
                Ingresa el código de 8 caracteres que compartió el creador del grupo.
              </p>

              <input
                type="text"
                value={codeInput}
                onChange={(event) => setCodeInput(event.target.value.toUpperCase())}
                placeholder="ABCD5678"
                maxLength={8}
                required
              />

              <button type="submit" disabled={loading}>
                {loading ? 'Verificando...' : 'Desbloquear grupo'}
              </button>
            </form>
          </div>
        ) : (
          <section className="messages-area">
            {messages.length === 0 ? (
              <div className="empty-chat-card">
                <span>✨</span>
                <h2>No hay mensajes</h2>
                <p>Envía el primero y se registrará en la mini blockchain.</p>
              </div>
            ) : (
              messages.map((message) => (
                <article
                  key={message.id}
                  className={`message-bubble ${
                    message.sender_id === currentUser?.id ? 'own' : ''
                  }`}
                  onClick={() => setSelectedMessage(message)}
                >
                  <div className="message-meta">
                    <strong>
                      {message.sender_id === currentUser?.id ? 'Tú' : 'Miembro'}
                    </strong>
                    <span>{formatMessageTime(message.created_at)}</span>
                  </div>

                  <p>{message.plaintext || message.decrypt_error || '...'}</p>

                  <div className="message-tags">
                    <SignatureStatus status={message.signature_status} />
                    {message.ciphertext_base64 && (
                      <small>AES-256-GCM</small>
                    )}
                    {message.plaintext_hash && (
                      <small>SHA-256</small>
                    )}
                  </div>
                </article>
              ))
            )}
          </section>
        )}

        {isUnlocked && (
          <form className="message-composer" onSubmit={handleSendMessage}>
            <input
              type="text"
              placeholder="Escribe un mensaje..."
              value={messageText}
              onChange={(event) => setMessageText(event.target.value)}
            />

            <button type="submit" disabled={loading || !selectedGroupId}>
              {loading ? 'Enviando' : 'Enviar'}
            </button>
          </form>
        )}
      </section>

      <aside className="chat-details">
        <div className="details-card group-summary-card">
          <div className="details-avatar">
            {selectedGroup?.name?.charAt(0).toUpperCase() || 'G'}
          </div>

          <h2>{selectedGroup?.name || 'Sin grupo'}</h2>
          <p>{selectedGroup?.description || 'Selecciona un grupo para ver detalles.'}</p>
        </div>

        {selectedGroupInviteCode && (
          <div className="details-card invite-code-card">
            <p className="section-label">Código del grupo</p>

            <p className="invite-code-text">
              {selectedGroupInviteCode}
            </p>

            <p>
              Comparte este código con quienes quieras invitar.
            </p>
          </div>
        )}

        <div className="details-card blockchain-card">
          <div className="blockchain-header">
            <div>
              <p className="section-label">Mini Blockchain</p>
              <h3>Bloques registrados</h3>
            </div>

            <button
              type="button"
              className="blockchain-refresh-button"
              onClick={refreshBlockchain}
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
          <p className="section-label">Miembros</p>

          <div className="members-list">
            {selectedGroup?.members?.length ? (
              selectedGroup.members.map((member) => (
                <div className="member-item" key={member.user_id || member}>
                  <span>{(member.name || member).charAt(0).toUpperCase()}</span>
                  <strong>{member.name || member}</strong>
                </div>
              ))
            ) : (
              <p className="empty-text">Sin miembros cargados.</p>
            )}
          </div>
        </div>

        <div className="details-card">
          <p className="section-label">Firma digital</p>

          {signaturePrivateKeyPem ? (
            <p className="verified-copy">
              Llave lista. Tus mensajes se firman con RSA-PSS.
            </p>
          ) : (
            <form className="key-card" onSubmit={handleUnlockSignatureKey}>
              <input
                type="file"
                accept=".json,application/json"
                onChange={handleSignatureKeyFileChange}
                required={!signatureKeyForm.encrypted_key_json}
              />

              <input
                type="password"
                value={signatureKeyForm.password}
                onChange={(event) =>
                  setSignatureKeyForm((current) => ({
                    ...current,
                    password: event.target.value,
                  }))
                }
                placeholder="Contrasena"
                required
              />

              <button disabled={loading || !signatureKeyForm.encrypted_key_json}>
                Activar firma
              </button>
            </form>
          )}
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
            label="Plaintext hash"
            value={
              selectedMessage?.plaintext_hash ||
              lastEncryptedPayload?.plaintext_hash
            }
          />
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

function shortHash(value) {
  if (!value) return 'N/A'

  const cleanValue = String(value)

  if (cleanValue.length <= 22) return cleanValue

  return `${cleanValue.slice(0, 10)}...${cleanValue.slice(-8)}`
}

export default Chats
