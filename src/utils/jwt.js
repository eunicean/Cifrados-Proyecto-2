import crypto from 'node:crypto'

function toBase64Url(value) {
  return Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function parseExpiration(expiresIn) {
  if (typeof expiresIn === 'number' && Number.isFinite(expiresIn)) {
    return expiresIn
  }

  if (typeof expiresIn !== 'string') {
    throw new Error('El tiempo de expiracion del JWT no es valido.')
  }

  const match = expiresIn.trim().match(/^(\d+)([smhd])$/i)

  if (!match) {
    throw new Error('Usa un formato de expiracion como 15m, 1h o 7d.')
  }

  const value = Number(match[1])
  const unit = match[2].toLowerCase()
  const multipliers = {
    s: 1,
    m: 60,
    h: 60 * 60,
    d: 60 * 60 * 24,
  }

  return value * multipliers[unit]
}

export function issueJwt(payload, secret, options = {}) {
  if (!secret) {
    throw new Error('Falta la llave secreta para firmar el JWT.')
  }

  const expiresIn = options.expiresIn ?? '1h'
  const issuedAt = Math.floor(Date.now() / 1000)
  const expiresAt = issuedAt + parseExpiration(expiresIn)

  const header = { alg: 'HS256', typ: 'JWT' }
  const claims = {
    ...payload,
    iat: issuedAt,
    exp: expiresAt,
  }

  const encodedHeader = toBase64Url(JSON.stringify(header))
  const encodedPayload = toBase64Url(JSON.stringify(claims))
  const unsignedToken = `${encodedHeader}.${encodedPayload}`

  const signature = crypto
    .createHmac('sha256', secret)
    .update(unsignedToken)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')

  return `${unsignedToken}.${signature}`
}

export function decodeJwtPayload(token) {
  const [, payload] = token.split('.')

  if (!payload) {
    throw new Error('JWT invalido.')
  }

  const normalizedPayload = payload.replace(/-/g, '+').replace(/_/g, '/')
  const paddedPayload = normalizedPayload.padEnd(
    normalizedPayload.length + ((4 - (normalizedPayload.length % 4)) % 4),
    '=',
  )

  return JSON.parse(Buffer.from(paddedPayload, 'base64').toString('utf8'))
}
