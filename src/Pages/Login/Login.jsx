import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { registerWithKeyPair } from '../../services/authService'
import {
  decryptMessagesWithPrivateKey,
  loadUserGroups,
  sendEncryptedGroupMessage,
} from '../../services/messageService'
import { decryptPrivateKey } from '../../utils/privateKeyEncryption'
import './Login.css'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000'

const emptyRegisterForm = {
  display_name: '',
  email: '',
  password: '',
}

const emptyLoginForm = {
  email: '',
  password: '',
}

const emptyGroupForm = {
  name: '',
  member_ids: '',
}

const emptyGroupMessageForm = {
  group_id: '',
  content: '',
}

async function apiRequest(endpoint, options = {}) {
  const token = localStorage.getItem('blu_token')

  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  })

  let data = null

  try {
    data = await response.json()
  } catch {
    data = null
  }

  if (!response.ok) {
    throw new Error(data?.message || data?.error || 'Ocurrió un error con la API.')
  }

  return data
}

function Login() {
  const navigate = useNavigate()
  const [activeView, setActiveView] = useState('groups')
  const [authMode, setAuthMode] = useState('login')
  const [registerForm, setRegisterForm] = useState(emptyRegisterForm)
  const [loginForm, setLoginForm] = useState(emptyLoginForm)
  const [groupForm, setGroupForm] = useState(emptyGroupForm)
  const [groupMessageForm, setGroupMessageForm] = useState(emptyGroupMessageForm)

  const [currentUser, setCurrentUser] = useState(() => {
    const stored = localStorage.getItem('blu_user')
    return stored ? JSON.parse(stored) : null
  })

  const [messages, setMessages] = useState([])
  const [groups, setGroups] = useState([])
  const [selectedGroupId, setSelectedGroupId] = useState('')
  const [privateKeyPem, setPrivateKeyPem] = useState('')
  const [privateKeyForm, setPrivateKeyForm] = useState({ encrypted_key_json: '', password: '' })
  const [decryptedMessages, setDecryptedMessages] = useState([])
  const [selectedMessage, setSelectedMessage] = useState(null)
  const [status, setStatus] = useState({ type: 'idle', message: '' })
  const [loading, setLoading] = useState(false)

  const isLoggedIn = Boolean(currentUser)

  const dashboardTitle = useMemo(() => {
    if (activeView === 'groups') return 'Chats grupales'
    if (activeView === 'inbox') return 'Mensajes'
    return 'Blu'
  }, [activeView])

  function showStatus(type, message) {
    setStatus({ type, message })
  }

  function handleRegisterChange(event) {
    const { name, value } = event.target
    setRegisterForm((current) => ({ ...current, [name]: value }))
  }

  function handleLoginChange(event) {
    const { name, value } = event.target
    setLoginForm((current) => ({ ...current, [name]: value }))
  }

  function handleGroupChange(event) {
    const { name, value } = event.target
    setGroupForm((current) => ({ ...current, [name]: value }))
  }

  function handleGroupMessageChange(event) {
    const { name, value } = event.target
    setGroupMessageForm((current) => ({ ...current, [name]: value }))
  }

  async function handleRegister(event) {
    event.preventDefault()
    setLoading(true)
    showStatus('loading', 'Generando llaves RSA y creando usuario...')

    try {
      await registerWithKeyPair(registerForm)

      setRegisterForm(emptyRegisterForm)
      setAuthMode('login')
      showStatus('success', 'Usuario registrado. Guarda el archivo de llave privada que se descargó.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleLogin(event) {
    event.preventDefault()
    setLoading(true)
    showStatus('loading', 'Verificando credenciales...')

    try {
      const data = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify(loginForm),
      })

      const token = data.access_token || data.token
      const user = data.user || {
        id: data.user_id,
        email: loginForm.email,
        display_name: data.display_name || loginForm.email,
      }

      if (!token) {
        throw new Error('El backend no devolvió un JWT válido.')
      }

      localStorage.setItem('blu_token', token)
      localStorage.setItem('blu_user', JSON.stringify(user))

      setCurrentUser(user)
      setLoginForm(emptyLoginForm)
      showStatus('success', 'Sesión iniciada correctamente.')
      navigate('/chats')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  function handleLogout() {
    localStorage.removeItem('blu_token')
    localStorage.removeItem('blu_user')
    setCurrentUser(null)
    setMessages([])
    setGroups([])
    setSelectedMessage(null)
    setActiveView('groups')
    showStatus('idle', '')
  }

  async function handleCreateGroup(event) {
    event.preventDefault()
    setLoading(true)
    showStatus('loading', 'Creando chat grupal...')

    try {
      const data = await apiRequest('/groups', {
        method: 'POST',
        body: JSON.stringify({ name: groupForm.name }),
      })

      const newGroup = data.group || data
      const code = data.code

      setGroupForm(emptyGroupForm)
      setGroups((current) => [newGroup, ...current])
      showStatus(
        'success',
        code
          ? `Grupo creado. Código del grupo: ${code} — compártelo con los miembros.`
          : 'Chat grupal creado correctamente.',
      )
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleSendGroupMessage(event) {
    event.preventDefault()
    setLoading(true)
    showStatus('loading', 'Cifrando y enviando mensaje al grupo...')

    try {
      const sentMessage = await sendEncryptedGroupMessage({
        group_id: groupMessageForm.group_id,
        content: groupMessageForm.content,
      })

      setGroupMessageForm(emptyGroupMessageForm)
      setSelectedMessage(sentMessage)
      showStatus('success', 'Mensaje cifrado y enviado al chat grupal.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  const loadMessages = useCallback(async () => {
    if (!currentUser?.id) return

    setLoading(true)
    showStatus('loading', 'Cargando mensajes...')

    try {
      const data = await apiRequest(`/messages/${currentUser.id}`)
      setMessages(data.messages || data || [])
      showStatus('success', 'Mensajes cargados correctamente.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }, [currentUser?.id])

  useEffect(() => {
    if (activeView === 'inbox' && currentUser?.id) {
      queueMicrotask(() => {
        loadMessages()
        if (groups.length === 0) {
          loadUserGroups().then(setGroups).catch(() => {})
        }
      })
    }
  }, [activeView, currentUser?.id, loadMessages])

  useEffect(() => {
    const filtered = selectedGroupId
      ? messages.filter(m => m.channel_id === selectedGroupId || m.group_id === selectedGroupId)
      : messages

    if (!privateKeyPem) {
      setDecryptedMessages(filtered)
      return
    }

    decryptMessagesWithPrivateKey(filtered, privateKeyPem)
      .then(setDecryptedMessages)
      .catch(() => setDecryptedMessages(filtered))
  }, [messages, selectedGroupId, privateKeyPem])

  async function handleUnlockPrivateKey(event) {
    event.preventDefault()
    setLoading(true)
    showStatus('loading', 'Desbloqueando llave privada...')

    let encryptedKey
    try {
      encryptedKey = JSON.parse(privateKeyForm.encrypted_key_json)
    } catch {
      showStatus('error', 'El JSON de la llave privada no es válido. Verifica que pegaste el archivo completo.')
      setLoading(false)
      return
    }

    try {
      const pem = await decryptPrivateKey(encryptedKey, privateKeyForm.password)
      console.log('[unlock] Llave privada desbloqueada. Encabezado:', pem.split('\n')[0])
      setPrivateKeyPem(pem)
      setPrivateKeyForm(f => ({ ...f, password: '' }))
      showStatus('success', 'Llave privada lista. Los mensajes se descifrarán automáticamente.')
    } catch (err) {
      console.error('[unlock] Error al descifrar la llave privada:', err.message)
      showStatus('error', 'Contraseña incorrecta o archivo de llave inválido.')
    } finally {
      setLoading(false)
    }
  }

  if (!isLoggedIn) {
    return (
      <main className="auth-layout">
        <section className="hero-panel">
          <div className="floating-shapes" aria-hidden="true">
            <span className="shape shape-circle"></span>
            <span className="shape shape-square"></span>
            <span className="shape shape-triangle"></span>
            <span className="shape shape-diamond"></span>
            <span className="shape shape-ring"></span>
            <span className="shape shape-small-circle"></span>
          </div>

          <div className="hero-content">
            <p className="eyebrow hero-eyebrow">Blu</p>
            <h1>Chats grupales seguros</h1>
            <p className="hero-subtitle">
              Una plataforma simple para comunicar equipos mediante grupos privados.
            </p>
          </div>
        </section>

        <section className="auth-card">
          <div className="auth-tabs">
            <button
              type="button"
              className={authMode === 'login' ? 'active' : ''}
              onClick={() => setAuthMode('login')}
            >
              Login
            </button>

            <button
              type="button"
              className={authMode === 'register' ? 'active' : ''}
              onClick={() => setAuthMode('register')}
            >
              Registro
            </button>
          </div>

          {authMode === 'login' ? (
            <form onSubmit={handleLogin} className="form-stack">
              <div>
                <p className="eyebrow">Acceso</p>
                <h2>Iniciar sesión</h2>
              </div>

              <label>
                Correo electrónico
                <input
                  name="email"
                  type="email"
                  value={loginForm.email}
                  onChange={handleLoginChange}
                  required
                />
              </label>

              <label>
                Contraseña
                <input
                  name="password"
                  type="password"
                  value={loginForm.password}
                  onChange={handleLoginChange}
                  required
                />
              </label>

              <button className="primary-button" disabled={loading}>
                {loading ? 'Validando...' : 'Entrar'}
              </button>
            </form>
          ) : (
            <form onSubmit={handleRegister} className="form-stack">
              <div>
                <p className="eyebrow">Cuenta</p>
                <h2>Crear usuario</h2>
              </div>

              <label>
                Nombre visible
                <input
                  name="display_name"
                  value={registerForm.display_name}
                  onChange={handleRegisterChange}
                  required
                />
              </label>

              <label>
                Correo electrónico
                <input
                  name="email"
                  type="email"
                  value={registerForm.email}
                  onChange={handleRegisterChange}
                  required
                />
              </label>

              <label>
                Contraseña
                <input
                  name="password"
                  type="password"
                  minLength={8}
                  value={registerForm.password}
                  onChange={handleRegisterChange}
                  required
                />
              </label>

              <button className="primary-button" disabled={loading}>
                {loading ? 'Creando...' : 'Registrarse'}
              </button>
            </form>
          )}

          {status.message && (
            <p className={`status-message ${status.type}`}>{status.message}</p>
          )}
        </section>
      </main>
    )
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div>
          <div className="brand-row">
            <div className="brand-badge small">B</div>

            <div>
              <strong>Blu</strong>
              <span>Group Chat</span>
            </div>
          </div>

          <nav className="nav-menu">
            <button
              className={activeView === 'groups' ? 'active' : ''}
              onClick={() => setActiveView('groups')}
            >
              Grupos
            </button>

            <button
              className={activeView === 'inbox' ? 'active' : ''}
              onClick={() => setActiveView('inbox')}
            >
              Mensajes
            </button>
          </nav>
        </div>

        <div className="user-card">
          <span>Sesión activa</span>
          <strong>{currentUser.display_name || currentUser.email}</strong>
          <small>{currentUser.id}</small>

          <button onClick={handleLogout}>
            Cerrar sesión
          </button>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Panel principal</p>
            <h1>{dashboardTitle}</h1>
          </div>

          <div className="security-pills">
            <span>Grupos privados</span>
            <span>API REST</span>
            <span>Sesión JWT</span>
          </div>
        </header>

        {status.message && (
          <p className={`status-message ${status.type}`}>{status.message}</p>
        )}

        {activeView === 'groups' && (
          <section className="content-grid">
            <form className="panel form-stack" onSubmit={handleCreateGroup}>
              <div>
                <p className="eyebrow">Nuevo chat</p>
                <h2>Crear grupo</h2>
                <p className="muted">
                  Crea un espacio privado para conversar con varios miembros.
                </p>
              </div>

              <label>
                Nombre del grupo
                <input
                  name="name"
                  value={groupForm.name}
                  onChange={handleGroupChange}
                  placeholder="Ej. Equipo de proyecto"
                  required
                />
              </label>

              <button className="primary-button" disabled={loading}>
                {loading ? 'Creando...' : 'Crear grupo'}
              </button>
            </form>

            <form className="panel form-stack" onSubmit={handleSendGroupMessage}>
              <div>
                <p className="eyebrow">Mensaje grupal</p>
                <h2>Enviar mensaje</h2>
                <p className="muted">
                  Escribe el ID del grupo y envía un mensaje para todos sus miembros.
                </p>
              </div>

              <label>
                ID del grupo
                <input
                  name="group_id"
                  value={groupMessageForm.group_id}
                  onChange={handleGroupMessageChange}
                  placeholder="UUID del grupo"
                  required
                />
              </label>

              <label>
                Mensaje
                <textarea
                  name="content"
                  value={groupMessageForm.content}
                  onChange={handleGroupMessageChange}
                  placeholder="Escribe un mensaje para el grupo..."
                  required
                />
              </label>

              <button className="primary-button" disabled={loading}>
                {loading ? 'Enviando...' : 'Enviar mensaje'}
              </button>
            </form>

            <section className="panel groups-panel">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">Chats recientes</p>
                  <h2>Grupos creados</h2>
                </div>
              </div>

              <div className="group-list">
                {groups.length === 0 ? (
                  <p className="muted">
                    Aún no has creado grupos en esta sesión.
                  </p>
                ) : (
                  groups.map((group, index) => (
                    <article className="group-item" key={group.id || index}>
                      <div className="group-avatar">
                        {(group.name || 'G').charAt(0).toUpperCase()}
                      </div>

                      <div>
                        <strong>{group.name || 'Grupo sin nombre'}</strong>
                        <span>{group.id || 'ID pendiente'}</span>
                      </div>
                    </article>
                  ))
                )}
              </div>
            </section>
          </section>
        )}

        {activeView === 'inbox' && (
          <section className="content-grid">
            <div className="panel">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">Mensajes</p>
                  <h2>Mensajes recibidos</h2>
                </div>

                <button className="ghost-button" onClick={loadMessages}>
                  Actualizar
                </button>
              </div>

              <select
                value={selectedGroupId}
                onChange={e => { setSelectedGroupId(e.target.value); setSelectedMessage(null) }}
                style={{ marginBottom: '0.75rem', width: '100%', padding: '0.4rem' }}
              >
                <option value="">Todos los grupos</option>
                {groups.map(g => (
                  <option key={g.id} value={g.id}>{g.name || g.id}</option>
                ))}
              </select>

              <div className="message-list">
                {decryptedMessages.length === 0 ? (
                  <p className="muted">No hay mensajes en este grupo.</p>
                ) : (
                  decryptedMessages.map((message) => (
                    <button
                      key={message.id}
                      className="message-item"
                      onClick={() => setSelectedMessage(message)}
                    >
                      <strong>
                        {groups.find(g => g.id === (message.channel_id || message.group_id))?.name
                          || message.group_id
                          || 'Grupo desconocido'}
                      </strong>
                      <span>
                        {message.plaintext
                          ? message.plaintext.slice(0, 60)
                          : message.decrypt_error || 'Cifrado — desbloquea tu llave privada'}
                      </span>
                      <small>{message.created_at ? new Date(message.created_at).toLocaleString('es-GT') : ''}</small>
                    </button>
                  ))
                )}
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <form className="panel form-stack" onSubmit={handleUnlockPrivateKey}>
                <div>
                  <p className="eyebrow">Descifrado</p>
                  <h2>{privateKeyPem ? 'Llave activa' : 'Desbloquear llave privada'}</h2>
                </div>

                {privateKeyPem ? (
                  <p className="muted" style={{ color: 'green' }}>
                    Llave privada cargada. Los mensajes se descifran automáticamente.
                  </p>
                ) : (
                  <>
                    <label>
                      JSON de llave privada cifrada
                      <textarea
                        value={privateKeyForm.encrypted_key_json}
                        onChange={e => setPrivateKeyForm(f => ({ ...f, encrypted_key_json: e.target.value }))}
                        placeholder='Pega aquí el contenido de tu archivo _private_key.json'
                        rows={4}
                        required
                      />
                    </label>
                    <label>
                      Contraseña
                      <input
                        type="password"
                        value={privateKeyForm.password}
                        onChange={e => setPrivateKeyForm(f => ({ ...f, password: e.target.value }))}
                        required
                      />
                    </label>
                    <button className="primary-button" disabled={loading}>
                      Desbloquear
                    </button>
                  </>
                )}
              </form>

              <EncryptedPreview message={selectedMessage} />
            </div>
          </section>
        )}
      </section>
    </main>
  )
}

function EncryptedPreview({ message }) {
  if (!message) {
    return (
      <aside className="panel encrypted-preview empty">
        <p className="eyebrow">Detalle del mensaje</p>
        <h2>Sin mensaje seleccionado</h2>
        <p className="muted">
          Aquí se mostrará la información técnica del mensaje grupal seleccionado.
        </p>
      </aside>
    )
  }

  return (
    <aside className="panel encrypted-preview">
      <p className="eyebrow">Objeto almacenado</p>
      <h2>Mensaje grupal</h2>

      <PreviewRow label="ID" value={message.id} />
      <PreviewRow label="Grupo" value={message.group_id} />
      <PreviewRow label="Ciphertext" value={message.ciphertext} />
      <PreviewRow label="Encrypted key" value={message.encrypted_key} />
      <PreviewRow label="Nonce / IV" value={message.nonce || message.iv} />
      <PreviewRow label="Auth tag" value={message.auth_tag || message.tag} />
      <PreviewRow label="Timestamp" value={message.created_at || message.timestamp} />

      {message.encrypted_keys && (
        <div className="code-block">
          <strong>encrypted_keys grupales</strong>
          <pre>{JSON.stringify(message.encrypted_keys, null, 2)}</pre>
        </div>
      )}
    </aside>
  )
}

function PreviewRow({ label, value }) {
  return (
    <div className="preview-row">
      <span>{label}</span>
      <code>{value || 'Pendiente'}</code>
    </div>
  )
}

export default Login
