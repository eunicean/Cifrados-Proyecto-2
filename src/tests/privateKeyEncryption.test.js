import test from 'node:test'
import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { generateRsaKeyPairPem } from '../utils/rsaKeyPair.js'
import {
    encryptPrivateKey,
    decryptPrivateKey,
} from '../utils/privateKeyEncryption.js'

// Simula APIs del navegador para que Web Crypto funcione en Node
globalThis.window = {
    crypto: webcrypto,
}

globalThis.btoa = (value) => Buffer.from(value, 'binary').toString('base64')
globalThis.atob = (value) => Buffer.from(value, 'base64').toString('binary')

test('cifra y descifra una llave privada RSA usando PBKDF2 y AES-GCM', async () => {
    const password = 'Password-Segura-123'
    const { privateKeyPem } = await generateRsaKeyPairPem()

    const encryptedData = await encryptPrivateKey(privateKeyPem, password)
    const decryptedPrivateKey = await decryptPrivateKey(encryptedData, password)

    assert.equal(decryptedPrivateKey, privateKeyPem)

    assert.equal(encryptedData.algorithm, 'AES-GCM')
    assert.equal(encryptedData.kdf, 'PBKDF2')
    assert.equal(encryptedData.hash, 'SHA-256')
    assert.equal(encryptedData.iterations, 600000)

    assert.equal(typeof encryptedData.salt, 'string')
    assert.equal(typeof encryptedData.iv, 'string')
    assert.equal(typeof encryptedData.encryptedPrivateKey, 'string')

    assert.notEqual(encryptedData.encryptedPrivateKey, privateKeyPem)
})

test('falla al descifrar la llave privada con una contraseña incorrecta', async () => {
    const correctPassword = 'Password-Correcta-123'
    const wrongPassword = 'Password-Incorrecta-456'

    const { privateKeyPem } = await generateRsaKeyPairPem()
    const encryptedData = await encryptPrivateKey(privateKeyPem, correctPassword)

    await assert.rejects(
        async () => {
        await decryptPrivateKey(encryptedData, wrongPassword)
        },
        {
        name: 'OperationError',
        },
    )
})