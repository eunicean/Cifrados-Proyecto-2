import { useEffect, useMemo, useState } from 'react'
import { getUserPublicKey } from './utils/api'
import { encryptMessageForRecipient } from './utils/messageCrypto'
import './App.css'

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

const emptyMessageForm = {
  recipient_id: '',
  content: '',
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
  const token = localStorage.getItem('vaultchain_token')

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

function App() {
  const [activeView, setActiveView] = useState('individual')
  const [authMode, setAuthMode] = useState('login')
  const [registerForm, setRegisterForm] = useState(emptyRegisterForm)
  const [loginForm, setLoginForm] = useState(emptyLoginForm)
  const [messageForm, setMessageForm] = useState(emptyMessageForm)
  const [groupForm, setGroupForm] = useState(emptyGroupForm)
  const [groupMessageForm, setGroupMessageForm] = useState(emptyGroupMessageForm)

  const [currentUser, setCurrentUser] = useState(() => {
    const stored = localStorage.getItem('vaultchain_user')
    return stored ? JSON.parse(stored) : null
  })

  const [messages, setMessages] = useState([])
  const [groups, setGroups] = useState([])
  const [selectedMessage, setSelectedMessage] = useState(null)
  const [status, setStatus] = useState({ type: 'idle', message: '' })
  const [loading, setLoading] = useState(false)

  const isLoggedIn = Boolean(currentUser)

  const dashboardTitle = useMemo(() => {
    if (activeView === 'individual') return 'Mensaje individual cifrado'
    if (activeView === 'groups') return 'Mensajería grupal'
    if (activeView === 'inbox') return 'Bandeja cifrada'
    return 'VaultChain'
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

  function handleMessageChange(event) {
    const { name, value } = event.target
    setMessageForm((current) => ({ ...current, [name]: value }))
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
    showStatus('loading', 'Creando usuario y preparando identidad criptográfica...')

    try {
      const data = await apiRequest('/auth/register', {
        method: 'POST',
        body: JSON.stringify(registerForm),
      })

      setRegisterForm(emptyRegisterForm)
      setAuthMode('login')
      showStatus('success', 'Usuario registrado correctamente. Ahora puedes iniciar sesión.')
      console.log('Registro:', data)
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

      localStorage.setItem('vaultchain_token', token)
      localStorage.setItem('vaultchain_user', JSON.stringify(user))

      setCurrentUser(user)
      setLoginForm(emptyLoginForm)
      showStatus('success', 'Sesión iniciada correctamente.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  function handleLogout() {
    localStorage.removeItem('vaultchain_token')
    localStorage.removeItem('vaultchain_user')
    setCurrentUser(null)
    setMessages([])
    setGroups([])
    setSelectedMessage(null)
    showStatus('idle', '')
  }

  async function handleSendMessage(event) {
    event.preventDefault()
    setLoading(true)
    showStatus('loading', 'Obteniendo llave pública del destinatario...')

    try {
      if (!currentUser?.id) {
        throw new Error('No hay usuario autenticado.')
      }

      const { public_key_pem: recipientPublicKeyPem } = await getUserPublicKey(
        messageForm.recipient_id,
      )

      showStatus('loading', 'Cifrando mensaje con AES-256-GCM y RSA-OAEP...')

      const encryptedMessage = await encryptMessageForRecipient(
        messageForm.content,
        recipientPublicKeyPem,
      )

      const payload = {
        sender_id: currentUser.id,
        recipient_id: messageForm.recipient_id,
        group_id: null,
        ciphertext: encryptedMessage.ciphertext,
        encrypted_key: encryptedMessage.encrypted_key,
        iv: encryptedMessage.iv,
        nonce: encryptedMessage.iv,
        auth_tag: null,
        timestamp: encryptedMessage.timestamp,
        created_at: encryptedMessage.timestamp,
      }

      const data = await apiRequest('/messages', {
        method: 'POST',
        body: JSON.stringify(payload),
      })

      setMessageForm(emptyMessageForm)
      setSelectedMessage(data.message || data || payload)

      showStatus(
        'success',
        'Mensaje cifrado y enviado correctamente. El texto plano no fue enviado al servidor.',
      )
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleCreateGroup(event) {
    event.preventDefault()
    setLoading(true)
    showStatus('loading', 'Creando grupo seguro...')

    try {
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

      setGroupForm(emptyGroupForm)
      setGroups((current) => [data.group || data, ...current])
      showStatus('success', 'Grupo creado correctamente.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleSendGroupMessage(event) {
    event.preventDefault()
    setLoading(true)
    showStatus('loading', 'Enviando mensaje grupal cifrado...')

    try {
      const data = await apiRequest('/messages', {
        method: 'POST',
        body: JSON.stringify({
          group_id: groupMessageForm.group_id,
          plaintext: groupMessageForm.content,
        }),
      })

      setGroupMessageForm(emptyGroupMessageForm)
      showStatus('success', 'Mensaje grupal enviado. La clave AES debe ir cifrada para cada miembro.')
      setSelectedMessage(data.message || data)
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  async function loadMessages() {
    if (!currentUser?.id) return

    setLoading(true)
    showStatus('loading', 'Cargando mensajes cifrados...')

    try {
      const data = await apiRequest(`/messages/${currentUser.id}`)
      setMessages(data.messages || data || [])
      showStatus('success', 'Mensajes cargados correctamente.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (activeView === 'inbox' && currentUser?.id) {
      loadMessages()
    }
  }, [activeView, currentUser?.id])

  if (!isLoggedIn) {
    return (
      <main className="auth-layout">
        <section className="hero-panel">
          <div className="brand-badge">VC</div>
          <div>
            <p className="eyebrow">VaultChain</p>
            <h1>Mensajería segura con cifrado híbrido</h1>
            <p className="hero-text">
              Prototipo para demostrar identidad, hashing, JWT, AES-256-GCM,
              RSA-OAEP, mensajes grupales y API REST.
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
                <p className="eyebrow">Identidad</p>
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
            <div className="brand-badge small">VC</div>
            <div>
              <strong>VaultChain</strong>
              <span>Secure Chat</span>
            </div>
          </div>

          <nav className="nav-menu">
            <button
              className={activeView === 'individual' ? 'active' : ''}
              onClick={() => setActiveView('individual')}
            >
              Mensaje individual
            </button>
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
              Bandeja
            </button>
          </nav>
        </div>

        <div className="user-card">
          <span>Sesión activa</span>
          <strong>{currentUser.display_name || currentUser.email}</strong>
          <small>{currentUser.id}</small>
          <button onClick={handleLogout}>Cerrar sesión</button>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Módulo 2</p>
            <h1>{dashboardTitle}</h1>
          </div>

          <div className="security-pills">
            <span>AES-256-GCM</span>
            <span>RSA-OAEP</span>
            <span>JWT</span>
          </div>
        </header>

        {status.message && (
          <p className={`status-message ${status.type}`}>{status.message}</p>
        )}

        {activeView === 'individual' && (
          <section className="content-grid">
            <form className="panel form-stack" onSubmit={handleSendMessage}>
              <div>
                <p className="eyebrow">POST /messages</p>
                <h2>Enviar mensaje individual</h2>
                <p className="muted">
                  El backend debe obtener la llave pública del destinatario,
                  cifrar el mensaje con AES-GCM y cifrar la clave AES con RSA-OAEP.
                </p>
              </div>

              <label>
                ID del destinatario
                <input
                  name="recipient_id"
                  value={messageForm.recipient_id}
                  onChange={handleMessageChange}
                  placeholder="UUID del destinatario"
                  required
                />
              </label>

              <label>
                Mensaje
                <textarea
                  name="content"
                  value={messageForm.content}
                  onChange={handleMessageChange}
                  placeholder="Escribe el mensaje sensible..."
                  required
                />
              </label>

              <button className="primary-button" disabled={loading}>
                {loading ? 'Cifrando...' : 'Enviar cifrado'}
              </button>
            </form>

            <EncryptedPreview message={selectedMessage} />
          </section>
        )}

        {activeView === 'groups' && (
          <section className="content-grid">
            <form className="panel form-stack" onSubmit={handleCreateGroup}>
              <div>
                <p className="eyebrow">POST /groups</p>
                <h2>Crear grupo</h2>
                <p className="muted">
                  Se usará para compartir la clave AES cifrada con la llave pública
                  de cada miembro.
                </p>
              </div>

              <label>
                Nombre del grupo
                <input
                  name="name"
                  value={groupForm.name}
                  onChange={handleGroupChange}
                  placeholder="Ej. Finanzas internas"
                  required
                />
              </label>

              <label>
                IDs de miembros separados por coma
                <textarea
                  name="member_ids"
                  value={groupForm.member_ids}
                  onChange={handleGroupChange}
                  placeholder="uuid-1, uuid-2, uuid-3"
                  required
                />
              </label>

              <button className="primary-button" disabled={loading}>
                Crear grupo
              </button>
            </form>

            <form className="panel form-stack" onSubmit={handleSendGroupMessage}>
              <div>
                <p className="eyebrow">Mensaje grupal</p>
                <h2>Enviar a grupo</h2>
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
                  placeholder="Mensaje para todos los miembros..."
                  required
                />
              </label>

              <button className="primary-button" disabled={loading}>
                Enviar a grupo
              </button>
            </form>
          </section>
        )}

        {activeView === 'inbox' && (
          <section className="content-grid">
            <div className="panel">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">GET /messages/{currentUser.id}</p>
                  <h2>Mensajes recibidos</h2>
                </div>
                <button className="ghost-button" onClick={loadMessages}>
                  Actualizar
                </button>
              </div>

              <div className="message-list">
                {messages.length === 0 ? (
                  <p className="muted">No hay mensajes cargados todavía.</p>
                ) : (
                  messages.map((message) => (
                    <button
                      key={message.id}
                      className="message-item"
                      onClick={() => setSelectedMessage(message)}
                    >
                      <strong>{message.sender_id || 'Remitente desconocido'}</strong>
                      <span>{message.created_at || 'Sin fecha'}</span>
                      <small>
                        {message.group_id ? 'Mensaje grupal' : 'Mensaje individual'}
                      </small>
                    </button>
                  ))
                )}
              </div>
            </div>

            <EncryptedPreview message={selectedMessage} />
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
        <p className="eyebrow">Estructura cifrada</p>
        <h2>Sin mensaje seleccionado</h2>
        <p className="muted">
          Aquí se mostrará el ciphertext, encrypted_key, nonce, auth_tag y timestamp.
        </p>
      </aside>
    )
  }

  return (
    <aside className="panel encrypted-preview">
      <p className="eyebrow">Objeto almacenado</p>
      <h2>Mensaje cifrado</h2>

      <PreviewRow label="ID" value={message.id} />
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

export default App