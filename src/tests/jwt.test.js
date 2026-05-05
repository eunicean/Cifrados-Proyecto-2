import { describe, expect, test } from 'vitest'
import { decodeJwtPayload, issueJwt, verifyJwt } from '../utils/jwt.js'

describe('JWT utilities', () => {
  test('genera un JWT valido y permite decodificar su payload', () => {
    const payload = {
      id: 'user-1',
      email: 'test@example.com',
    }

    const secret = 'super-secret-key'

    const token = issueJwt(payload, secret, { expiresIn: '1h' })
    const decodedPayload = decodeJwtPayload(token)

    expect(token.split('.')).toHaveLength(3)
    expect(decodedPayload.id).toBe(payload.id)
    expect(decodedPayload.email).toBe(payload.email)
    expect(typeof decodedPayload.iat).toBe('number')
    expect(typeof decodedPayload.exp).toBe('number')
    expect(decodedPayload.exp).toBeGreaterThan(decodedPayload.iat)
  })

  test('verifica la firma y expiracion de un JWT valido', () => {
    const secret = 'super-secret-key'

    const token = issueJwt(
      {
        id: 'user-1',
        email: 'test@example.com',
      },
      secret,
      { expiresIn: '1h' },
    )

    const verifiedPayload = verifyJwt(token, secret)

    expect(verifiedPayload.id).toBe('user-1')
    expect(verifiedPayload.email).toBe('test@example.com')
  })

  test('rechaza un JWT con firma manipulada', () => {
    const token = issueJwt({ id: 'user-1' }, 'secret-correcto', {
      expiresIn: '1h',
    })

    expect(() => verifyJwt(token, 'secret-incorrecto')).toThrow(/JWT invalido/)
  })

  test('lanza error cuando falta el secret del JWT', () => {
    const payload = {
      id: 'user-1',
      email: 'test@example.com',
    }

    expect(() => issueJwt(payload, '', { expiresIn: '1h' })).toThrow(
      /Falta la llave secreta/,
    )
  })

  test('lanza error cuando el formato de expiracion no es valido', () => {
    const payload = {
      id: 'user-1',
      email: 'test@example.com',
    }

    const secret = 'super-secret-key'

    expect(() => issueJwt(payload, secret, { expiresIn: 'una-hora' })).toThrow(
      /Usa un formato de expiracion/,
    )
  })
})