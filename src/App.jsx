import { useEffect } from 'react'
import {
  BrowserRouter as Router,
  Navigate,
  Route,
  Routes,
  useNavigate,
} from 'react-router-dom'
import Chats from './Pages/Chats/Chats.jsx'
import Login from './Pages/Login/Login.jsx'
import DirectMessages from './Pages/DirectMessages/DirectMessages'
import './App.css'

const SESSION_TIMEOUT_MS = 20 * 60 * 1000

function SessionTimeout() {
  const navigate = useNavigate()

  useEffect(() => {
    let timeoutId = null

    function clearSession() {
      localStorage.removeItem('blu_token')
      localStorage.removeItem('blu_user')
      sessionStorage.removeItem('blu_private_key_pem')
      sessionStorage.removeItem('blu_private_key_loaded_at')
      navigate('/login', { replace: true })
    }

    function resetTimer() {
      window.clearTimeout(timeoutId)

      if (!localStorage.getItem('blu_token')) return

      timeoutId = window.setTimeout(() => {
        clearSession()
      }, SESSION_TIMEOUT_MS)
    }

    const events = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart']
    events.forEach((eventName) => window.addEventListener(eventName, resetTimer))
    resetTimer()

    return () => {
      window.clearTimeout(timeoutId)
      events.forEach((eventName) => window.removeEventListener(eventName, resetTimer))
    }
  }, [navigate])

  return null
}

function App() {
  return (
    <Router>
      <SessionTimeout />
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<Login />} />
        <Route path="/blu" element={<Login />} />
        <Route path="/chats" element={<Chats />} />
        <Route path="/direct-messages" element={<DirectMessages />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </Router>
  )
}

export default App
