import test from 'node:test'
import assert from 'node:assert/strict'
import { issueJwt, decodeJwtPayload } from '../utils/jwt.js'

test('genera un JWT valido y permite decodificar su payload', () => {
    const payload = {
        id: 'user-1',
        email: 'test@example.com',
    }

    const secret = 'super-secret-key'

    const token = issueJwt(payload, secret, { expiresIn: '1h' })
    const decodedPayload = decodeJwtPayload(token)

    assert.equal(token.split('.').length, 3)

    assert.equal(decodedPayload.id, payload.id)
    assert.equal(decodedPayload.email, payload.email)

    assert.equal(typeof decodedPayload.iat, 'number')
    assert.equal(typeof decodedPayload.exp, 'number')
    assert.ok(decodedPayload.exp > decodedPayload.iat)
})