import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { registerWithKeyPair } from '../../services/authService'
import { decryptPrivateKey } from '../../utils/privateKeyEncryption'
import './Login.css'

const API_URL =
  import.meta.env.VITE_API_URL || 'https://cifrados-proyecto-2.onrender.com'

const emptyRegisterForm = {
  display_name: '',
  email: '',
  password: '',
}

const emptyLoginForm = {
  email: '',
  password: '',
}

const emptySessionKeyForm = {
  encrypted_key_json: '',
  password: '',
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
  const [authMode, setAuthMode] = useState('login')
  const [registerForm, setRegisterForm] = useState(emptyRegisterForm)
  const [loginForm, setLoginForm] = useState(emptyLoginForm)
  const [sessionKeyForm, setSessionKeyForm] = useState(emptySessionKeyForm)
  const [showSessionKeyModal, setShowSessionKeyModal] = useState(false)

  const [currentUser, setCurrentUser] = useState(() => {
    const stored = localStorage.getItem('blu_user')
    return stored ? JSON.parse(stored) : null
  })

  const [status, setStatus] = useState({ type: 'idle', message: '' })
  const [loading, setLoading] = useState(false)

  const isLoggedIn = Boolean(currentUser)

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
      setSessionKeyForm({
        encrypted_key_json: '',
        password: loginForm.password,
      })
      setShowSessionKeyModal(!sessionStorage.getItem('blu_private_key_pem'))
      setLoginForm(emptyLoginForm)
      showStatus('success', 'Sesión iniciada correctamente.')
    } catch (error) {
      showStatus('error', error.message)
    } finally {
      setLoading(false)
    }
  }

  function handleLogout() {
    localStorage.removeItem('blu_token')
    localStorage.removeItem('blu_user')
    sessionStorage.removeItem('blu_private_key_pem')
    sessionStorage.removeItem('blu_private_key_loaded_at')
    setCurrentUser(null)
    setSessionKeyForm(emptySessionKeyForm)
    setShowSessionKeyModal(false)
    showStatus('idle', '')
  }

  async function handleSessionKeyFileChange(event) {
    const file = event.target.files?.[0]
    if (!file) return

    try {
      const content = await file.text()
      JSON.parse(content)
      setSessionKeyForm((current) => ({
        ...current,
        encrypted_key_json: content,
      }))
      showStatus('success', 'Archivo de llave cargado.')
    } catch {
      showStatus('error', 'El archivo seleccionado no tiene un JSON valido.')
    }
  }

  async function handleSaveSessionKey(event) {
    event.preventDefault()
    setLoading(true)
    showStatus('loading', 'Desbloqueando llave para esta sesion...')

    try {
      const encryptedPrivateKey = JSON.parse(sessionKeyForm.encrypted_key_json)
      const privateKeyPem = await decryptPrivateKey(
        encryptedPrivateKey,
        sessionKeyForm.password,
      )

      sessionStorage.setItem('blu_private_key_pem', privateKeyPem)
      sessionStorage.setItem('blu_private_key_loaded_at', new Date().toISOString())
      setSessionKeyForm(emptySessionKeyForm)
      setShowSessionKeyModal(false)
      showStatus('success', 'Llave privada lista para esta sesion.')
    } catch {
      showStatus('error', 'No se pudo desbloquear la llave. Revisa el JSON y la contrasena.')
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
    <>
    {showSessionKeyModal && (
      <div className="session-key-backdrop">
        <section className="session-key-modal" role="dialog" aria-modal="true">
          <button
            type="button"
            className="session-key-close"
            onClick={() => setShowSessionKeyModal(false)}
            aria-label="Cerrar"
          >
            x
          </button>

          <p className="eyebrow">Llave de sesion</p>
          <h2>Sube tu llave privada</h2>
          <p className="muted">
            Se desbloquea solo para esta sesion y se borra al cerrar sesion o por inactividad.
          </p>

          <form className="form-stack" onSubmit={handleSaveSessionKey}>
            <label>
              Archivo JSON de llave privada
              <input
                type="file"
                accept=".json,application/json"
                onChange={handleSessionKeyFileChange}
                required={!sessionKeyForm.encrypted_key_json}
              />
            </label>

            <label>
              Contraseña
              <input
                type="password"
                value={sessionKeyForm.password}
                onChange={(event) =>
                  setSessionKeyForm((current) => ({
                    ...current,
                    password: event.target.value,
                  }))
                }
                required
              />
            </label>

            <button
              className="primary-button"
              disabled={loading || !sessionKeyForm.encrypted_key_json}
            >
              {loading ? 'Guardando...' : 'Usar en esta sesion'}
            </button>
          </form>
        </section>
      </div>
    )}

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
            <button onClick={() => navigate('/chats')}>
              Chats grupales
            </button>

            <button onClick={() => navigate('/direct-messages')}>
              Chats individuales
            </button>

            <button onClick={() => setShowSessionKeyModal(true)}>
              Cargar llave de sesion
            </button>
          </nav>
        </div>

        <div className="user-card">
          <div className="user-card-header">
            <div className="user-avatar">
              {(currentUser.display_name || currentUser.email || 'U').charAt(0).toUpperCase()}
            </div>

            <div>
              <span className="session-pill">
                <span></span>
                Sesion activa
              </span>
              <strong>{currentUser.display_name || currentUser.email}</strong>
            </div>
          </div>

          <div className="user-meta">
            <span>{currentUser.email}</span>
            <small>{currentUser.id}</small>
          </div>

          <button className="logout-button" onClick={handleLogout}>
            Cerrar sesion
          </button>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Panel principal</p>
            <h1>Inicio</h1>
          </div>

          <div className="security-pills">
            <span>Chats cifrados</span>
            <span>RSA + AES</span>
            <span>Sesión JWT</span>
          </div>
        </header>

        {status.message && (
          <p className={`status-message ${status.type}`}>{status.message}</p>
        )}

        <section className="home-grid">
          <button
            type="button"
            className="home-card"
            onClick={() => navigate('/chats')}
          >
            <span className="home-card-icon">G</span>
            <span className="eyebrow">Canales</span>
            <strong>Chats grupales</strong>
            <small>Crear grupos, unirte con código y conversar con cifrado AES-GCM.</small>
          </button>

          <button
            type="button"
            className="home-card"
            onClick={() => navigate('/direct-messages')}
          >
            <span className="home-card-icon">D</span>
            <span className="eyebrow">Privado</span>
            <strong>Chats individuales</strong>
            <small>Enviar mensajes directos cifrados con llaves RSA por usuario.</small>
          </button>

          <section className="panel session-panel">
            <p className="eyebrow">Cuenta activa</p>
            <h2>{currentUser.display_name || currentUser.email}</h2>
            <p className="muted">{currentUser.email}</p>
            <code>{currentUser.id}</code>
          </section>
        </section>
      </section>
    </main>
    </>
  )
}

export default Login
