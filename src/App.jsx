import { BrowserRouter as Router, Navigate, Route, Routes } from 'react-router-dom'
import Chats from './Pages/Chats/Chats.jsx'
import Login from './Pages/Login/Login.jsx'
import './App.css'

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<Login />} />
        <Route path="/blu" element={<Login />} />
        <Route path="/chats" element={<Chats />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </Router>
  )
}

export default App
