import test from 'node:test'
import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { generateRsaKeyPairPem } from '../utils/rsaKeyPair.js'

// Simula el objeto window para poder probar funciones pensadas para navegador
globalThis.window = {
    crypto: webcrypto,
}

// Simula btoa porque Node no lo trae como navegador en todos los entornos
globalThis.btoa = (value) => Buffer.from(value, 'binary').toString('base64')

test('genera un par de llaves RSA-2048 en formato PEM', async () => {
    const keyPair = await generateRsaKeyPairPem()

    assert.equal(typeof keyPair.publicKeyPem, 'string')
    assert.equal(typeof keyPair.privateKeyPem, 'string')

    assert.ok(keyPair.publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----'))
    assert.ok(keyPair.publicKeyPem.endsWith('-----END PUBLIC KEY-----\n'))

    assert.ok(keyPair.privateKeyPem.startsWith('-----BEGIN PRIVATE KEY-----'))
    assert.ok(keyPair.privateKeyPem.endsWith('-----END PRIVATE KEY-----\n'))
})