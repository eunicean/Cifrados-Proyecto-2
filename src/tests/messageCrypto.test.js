import test from 'node:test'
import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { generateRsaKeyPairPem } from '../utils/rsaKeyPair.js'
import {
    decryptStoredMessage,
    encryptMessage,
    encryptMessageForRecipients,
} from '../utils/messageCrypto.js'

globalThis.window = {
    crypto: webcrypto,
}

globalThis.btoa = (value) => Buffer.from(value, 'binary').toString('base64')
globalThis.atob = (value) => Buffer.from(value, 'base64').toString('binary')

test('cifra AES-256-GCM separando nonce, ciphertext y auth tag para la BD', async () => {
    const encryptedMessage = await encryptMessage('mensaje secreto')

    assert.equal(typeof encryptedMessage.ciphertext_base64, 'string')
    assert.equal(typeof encryptedMessage.nonce_base64, 'string')
    assert.equal(typeof encryptedMessage.auth_tag_base64, 'string')

    assert.notEqual(encryptedMessage.ciphertext_base64, '')
    assert.notEqual(encryptedMessage.nonce_base64, '')
    assert.notEqual(encryptedMessage.auth_tag_base64, '')
    assert.equal(Buffer.from(encryptedMessage.nonce_base64, 'base64').length, 12)
    assert.equal(Buffer.from(encryptedMessage.auth_tag_base64, 'base64').length, 16)
})

test('descifra end-to-end un mensaje grupal usando una llave privada RSA', async () => {
    const alice = await generateRsaKeyPairPem()
    const bob = await generateRsaKeyPairPem()
    const plaintext = 'hola equipo'

    const encryptedMessage = await encryptMessageForRecipients(plaintext, [
        {
        user_id: 'alice',
        public_key_pem: alice.publicKeyPem,
        },
        {
        user_id: 'bob',
        public_key_pem: bob.publicKeyPem,
        },
    ])

    const decryptedForBob = await decryptStoredMessage(
        encryptedMessage,
        bob.privateKeyPem,
    )

    assert.equal(encryptedMessage.encrypted_keys.length, 2)
    assert.equal(decryptedForBob, plaintext)
})
