import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { registerWithKeyPair } from '../../services/authService'
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
    setCurrentUser(null)
    showStatus('idle', '')
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
            <button onClick={() => navigate('/chats')}>
              Chats grupales
            </button>

            <button onClick={() => navigate('/direct-messages')}>
              Chats individuales
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
  )
}

export default Login
