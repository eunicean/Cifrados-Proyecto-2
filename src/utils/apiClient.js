const API_URL =
  import.meta.env.VITE_API_URL || 'https://cifrados-proyecto-2.onrender.com'

export async function apiRequest(endpoint, options = {}) {
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
