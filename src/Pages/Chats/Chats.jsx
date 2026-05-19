import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  createGroup,
  decryptGroupMessages,
  deriveGroupAesKey,
  joinGroupWithCode,
  loadGroupMessages,
  loadUserGroups,
  searchGroupsByName,
  sendGroupMessage,
} from '../../services/messageService'
import { decryptPrivateKey } from '../../utils/privateKeyEncryption'
import './Chats.css'

const cryptoFlowSteps = [
  'El creador genera un código de 8 caracteres.',
  'El servidor valida el código con SHA-256 y solo muestra el código al creador.',
  'El cliente deriva AES-256 del código + groupId con PBKDF2 (100k iter).',
  'Cada mensaje se cifra con AES-256-GCM y un nonce único de 12 bytes.',
  'Solo el ciphertext, nonce y auth_tag se almacenan en Supabase.',
  'Cualquier miembro con el código puede derivar la clave y descifrar.',
]

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
    () => groups.find((g) => g.id === selectedGroupId),
    [groups, selectedGroupId],
  )

  const filteredGroups = useMemo(
    () =>
      groups.filter((g) =>
        g.name.toLowerCase().includes(myGroupsFilter.toLowerCase()),
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

  const refreshGroups = useCallback(async () => {
    try {
      const loaded = await loadUserGroups()
      setGroups(loaded)
      setSelectedGroupId((prev) => prev || loaded[0]?.id || '')
    } catch (error) {
      showStatus('error', error.message)
    }
  }, [])

  useEffect(() => {
    queueMicrotask(() => {
      refreshGroups()
    })
  }, [refreshGroups])

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

  // Load and decrypt messages whenever the selected group becomes unlocked
  useEffect(() => {
    if (!selectedGroupId || !isUnlocked) return

    let cancelled = false
    async function load() {
      setLoading(true)
      showStatus('loading', 'Cargando mensajes...')
      try {
        const raw = await loadGroupMessages(selectedGroupId)
        const key = groupKeysRef.current[selectedGroupId]
        const decrypted = await decryptGroupMessages(raw, key)
        if (!cancelled) {
          setMessages(decrypted)
          showStatus('success', 'Mensajes cargados.')
        }
      } catch (error) {
        if (!cancelled) showStatus('error', error.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    return () => {
      cancelled = true
    }
  }, [selectedGroupId, isUnlocked])

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
    if (!newGroupName.trim()) return

    setLoading(true)
    showStatus('loading', 'Creando grupo...')
    try {
      const data = await createGroup(newGroupName.trim())
      const group = data.group || data
      const code = data.code
      const groupWithCode = code ? { ...group, invite_code: code } : group

      setGroups((prev) => [groupWithCode, ...prev])
      setNewGroupName('')

      if (code) {
        setCreatedGroupCode(code)
        const aesKey = await deriveGroupAesKey(code, group.id)
        groupKeysRef.current[group.id] = aesKey
        setUnlockedGroupIds((prev) => new Set([...prev, group.id]))
        setSelectedGroupId(group.id)
        showStatus('success', `Grupo creado. Comparte el código con los miembros.`)
      }
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleSearch(event) {
    event.preventDefault()
    if (!searchQuery.trim()) return

    setLoading(true)
    try {
      const results = await searchGroupsByName(searchQuery.trim())
      setSearchResults(results)
      if (results.length === 0) showStatus('idle', 'No se encontraron grupos con ese nombre.')
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
    if (!groups.find((g) => g.id === group.id)) {
      setGroups((prev) => [group, ...prev])
    }
  }

  async function handleJoinOrUnlock(event) {
    event.preventDefault()
    if (!codeInput.trim() || !selectedGroupId) return

    setLoading(true)
    showStatus('loading', 'Verificando código...')
    try {
      await joinGroupWithCode(selectedGroupId, codeInput.trim())
      const aesKey = await deriveGroupAesKey(codeInput.trim(), selectedGroupId)
      groupKeysRef.current[selectedGroupId] = aesKey
      setUnlockedGroupIds((prev) => new Set([...prev, selectedGroupId]))
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
      const [decrypted] = await decryptGroupMessages([sentMessage], aesKey)
      setMessages((prev) => [...prev, decrypted])
      setLastEncryptedPayload(sentMessage)
      setSelectedMessage(decrypted)
      setMessageText('')
      showStatus('success', 'Mensaje cifrado y enviado.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
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
      setSignatureKeyForm((current) => ({ ...current, password: '' }))
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
            onChange={(e) => setMyGroupsFilter(e.target.value)}
          />
        </div>

        <section className="groups-list">
          {filteredGroups.length === 0 ? (
            <p className="empty-text">No hay grupos.</p>
          ) : (
            filteredGroups.map((group) => (
              <button
                key={group.id}
                className={`group-chat-card ${selectedGroupId === group.id ? 'active' : ''}`}
                onClick={() => handleSelectGroup(group.id)}
              >
                <div className="group-icon">{group.name.charAt(0).toUpperCase()}</div>
                <div className="group-info">
                  <div className="group-title-row">
                    <strong>{group.name}</strong>
                    {!unlockedGroupIds.has(group.id) && (
                      <span style={{ fontSize: '0.75rem', opacity: 0.6 }}>🔒</span>
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
                onChange={(e) => setSearchQuery(e.target.value)}
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
                    <div className="group-icon">{result.name.charAt(0).toUpperCase()}</div>
                    <div className="group-info">
                      <strong>{result.name}</strong>
                      <span>{result.is_member ? 'Ya eres miembro' : 'Unete con codigo'}</span>
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
              onChange={(e) => setNewGroupName(e.target.value)}
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
        <header className="chat-header">
          <div>
            <p className="section-label">Chat activo</p>
            <h1>{selectedGroup?.name || 'Grupo'}</h1>
            <span>{selectedGroup?.description}</span>
          </div>
          <div className="chat-status">
            <span className="status-dot"></span>
            {isUnlocked ? 'Descifrado activo' : 'Ingresa el código'}
          </div>
        </header>

        {status.message && (
          <p className={`chat-status-message ${status.type}`}>{status.message}</p>
        )}

        {!selectedGroupId ? (
          <div className="messages-area" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <p className="empty-chat-text">Selecciona un grupo o únete a uno nuevo con su código.</p>
          </div>
        ) : !isUnlocked ? (
          <div className="messages-area" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <form
              onSubmit={handleJoinOrUnlock}
              style={{ textAlign: 'center', maxWidth: '320px', width: '100%' }}
            >
              <p style={{ marginBottom: '1rem', fontWeight: 600 }}>
                🔐 Ingresa el código del grupo
              </p>
              <p style={{ marginBottom: '1.5rem', opacity: 0.7, fontSize: '0.9rem' }}>
                El creador del grupo debe compartirte el código de 8 caracteres.
              </p>
              <input
                type="text"
                value={codeInput}
                onChange={(e) => setCodeInput(e.target.value.toUpperCase())}
                placeholder="Ej: ABCD5678"
                maxLength={8}
                style={{ width: '100%', marginBottom: '1rem', textAlign: 'center', letterSpacing: '0.2em', fontSize: '1.2rem' }}
                required
              />
              <button type="submit" disabled={loading} style={{ width: '100%' }}>
                {loading ? 'Verificando...' : 'Desbloquear / Unirse'}
              </button>
            </form>
          </div>
        ) : (
          <section className="messages-area">
            {messages.length === 0 ? (
              <p className="empty-chat-text">No hay mensajes. ¡Envía el primero!</p>
            ) : (
              messages.map((message) => (
                <article
                  key={message.id}
                  className={`message-bubble ${message.sender_id === currentUser?.id ? 'own' : ''}`}
                  onClick={() => setSelectedMessage(message)}
                >
                  <div className="message-meta">
                    <strong>{message.sender_id === currentUser?.id ? 'Tú' : 'Miembro'}</strong>
                    <span>{formatMessageTime(message.created_at)}</span>
                  </div>
                  <p>{message.plaintext || message.decrypt_error || '...'}</p>
                  <SignatureStatus status={message.signature_status} />
                  <small>{message.ciphertext_base64 ? 'AES-256-GCM' : ''}</small>
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
              onChange={(e) => setMessageText(e.target.value)}
            />
            <button type="submit" disabled={loading || !selectedGroupId}>
              {loading ? 'Enviando' : 'Enviar'}
            </button>
          </form>
        )}
      </section>

      <aside className="chat-details">
        <div className="details-card">
          <div className="details-avatar">
            {selectedGroup?.name?.charAt(0).toUpperCase() || 'G'}
          </div>
          <h2>{selectedGroup?.name || 'Sin grupo'}</h2>
          <p>{selectedGroup?.description}</p>
        </div>

        {selectedGroupInviteCode && (
          <div className="details-card" style={{ background: 'var(--color-accent, #3b82f6)', color: '#fff' }}>
            <p className="section-label" style={{ color: 'rgba(255,255,255,0.8)' }}>Código del grupo</p>
            <p style={{ fontSize: '1.8rem', fontWeight: 700, letterSpacing: '0.3em', margin: '0.5rem 0' }}>
              {selectedGroupInviteCode}
            </p>
            <p style={{ fontSize: '0.8rem', opacity: 0.85 }}>
              Comparte este código con quienes quieras invitar.
            </p>
          </div>
        )}

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
          <p className="section-label">Firma digital</p>
          {signaturePrivateKeyPem ? (
            <p className="verified-copy">Llave lista. Tus mensajes se firman con RSA-PSS.</p>
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

export default Chats
