// Registro estructurado para el SIEM (Hito 3).
// Cada evento se escribe como una linea JSON por stdout; Filebeat la decodifica en api.*
// No se registran contrasenas, JWT, cuerpos de mensajes ni llaves.

const MAX_TEXT = 200

function truncate(value, max = MAX_TEXT) {
  if (value === undefined || value === null) return null
  const text = String(value)
  return text.length > max ? `${text.slice(0, max)}…` : text
}

// "rt.alice@example.com" -> "rt***@example.com"
export function maskEmail(email) {
  const text = String(email || '').trim().toLowerCase()
  const at = text.lastIndexOf('@')
  if (at < 1) return text ? '***' : null
  return `${text.slice(0, Math.min(2, at))}***${truncate(text.slice(at), 100)}`
}

// PoC-02: busqueda con comodines de LIKE o que apunta a canales "direct"
export function isSuspiciousGroupSearch(term) {
  const text = String(term || '')
  return /[%_*\\]/.test(text) || /^\s*direct/i.test(text)
}

export function securityEvent(event, req, details = {}) {
  const entry = {
    log_type: 'cifrados-api',
    event,
    ts: new Date().toISOString(),
    client_ip: req?.ip ?? null,
    user_id: req?.auth?.sub ? String(req.auth.sub) : null,
    method: req?.method ?? null,
    route: req?.route?.path ?? null,
    url: truncate(req?.originalUrl, 300),
    ...details,
  }
  console.log(JSON.stringify(entry))
}

// Una linea por peticion: sirve para detectar rafagas por IP
export function requestLogger(req, res, next) {
  const start = process.hrtime.bigint()
  res.on('finish', () => {
    securityEvent('http_request', req, {
      status: res.statusCode,
      duration_ms: Number((process.hrtime.bigint() - start) / 1_000_000n),
      user_agent: truncate(req.headers['user-agent'], 150),
    })
  })
  next()
}