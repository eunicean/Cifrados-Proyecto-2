import { useState } from 'react'
import { registerUser } from './auth/registerUser'
import heroImg from './assets/hero.png'
import './App.css'

const initialForm = {
  name: '',
  email: '',
  password: '',
}

function App() {
  const [form, setForm] = useState(initialForm)
  const [status, setStatus] = useState({ type: 'idle', message: '' })
  const [registeredUser, setRegisteredUser] = useState(null)

  function handleChange(event) {
    const { name, value } = event.target
    setForm((currentForm) => ({
      ...currentForm,
      [name]: value,
    }))
  }

  async function handleSubmit(event) {
    event.preventDefault()
    setStatus({ type: 'loading', message: 'Creando cuenta...' })
    setRegisteredUser(null)

    try {
      const user = await registerUser(form)
      setRegisteredUser(user)
      setForm(initialForm)
      setStatus({ type: 'success', message: 'Cuenta creada correctamente.' })
    } catch (error) {
      setStatus({ type: 'error', message: error.message })
    }
  }

  const isLoading = status.type === 'loading'

  return (
    <main className="auth-page">
      <section className="brand-panel" aria-label="Nova">
        <img src={heroImg} alt="" className="brand-mark" />
        <div>
          <p className="eyebrow">Nova</p>
          <h1>Chat cifrado</h1>
        </div>
      </section>

      <section className="auth-panel" aria-labelledby="register-title">
        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="form-heading">
            <p className="eyebrow">Registro</p>
            <h2 id="register-title">Crear cuenta</h2>
          </div>

          <label>
            Nombre
            <input
              name="name"
              type="text"
              autoComplete="name"
              value={form.name}
              onChange={handleChange}
              required
            />
          </label>

          <label>
            Correo
            <input
              name="email"
              type="email"
              autoComplete="email"
              value={form.email}
              onChange={handleChange}
              required
            />
          </label>

          <label>
            Contraseña
            <input
              name="password"
              type="password"
              autoComplete="new-password"
              minLength={8}
              value={form.password}
              onChange={handleChange}
              required
            />
          </label>

          <button type="submit" disabled={isLoading}>
            {isLoading ? 'Guardando...' : 'Registrarse'}
          </button>

          {status.message && (
            <p className={`form-message ${status.type}`} role="status">
              {status.message}
            </p>
          )}

          {registeredUser && (
            <div className="user-result">
              <span>ID {registeredUser.id}</span>
              <strong>{registeredUser.email}</strong>
            </div>
          )}
        </form>
      </section>
    </main>
  )
}

export default App
