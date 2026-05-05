import test from 'node:test'
import assert from 'node:assert/strict'
import { issueJwt, decodeJwtPayload, verifyJwt } from '../utils/jwt.js'

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

    assert.equal(verifiedPayload.id, 'user-1')
    assert.equal(verifiedPayload.email, 'test@example.com')
})

test('rechaza un JWT con firma manipulada', () => {
    const token = issueJwt({ id: 'user-1' }, 'secret-correcto', { expiresIn: '1h' })

    assert.throws(
        () => verifyJwt(token, 'secret-incorrecto'),
        /JWT invalido/
    )
})

    test('lanza error cuando falta el secret del JWT', () => {
    const payload = {
        id: 'user-1',
        email: 'test@example.com',
    }

    assert.throws(
        () => issueJwt(payload, '', { expiresIn: '1h' }),
        /Falta la llave secreta/
    )
    })

    test('lanza error cuando el formato de expiracion no es valido', () => {
    const payload = {
        id: 'user-1',
        email: 'test@example.com',
    }

    const secret = 'super-secret-key'

    assert.throws(
        () => issueJwt(payload, secret, { expiresIn: 'una-hora' }),
        /Usa un formato de expiracion/
    )
})
