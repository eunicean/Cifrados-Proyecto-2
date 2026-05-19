# Módulo 2 — Mensajería Cifrada End-to-End

Implementación de cifrado híbrido (AES-256-GCM + RSA-OAEP) para mensajería grupal cifrada en el cliente.

---

## 1. Cifrado AES-256-GCM con nonce único por mensaje

Archivo: [src/utils/crypto/aesGcm.js](src\utils\crypto\aesGcm.js)

Cada mensaje genera una clave AES-256 efímera y un nonce aleatorio de 12 bytes. El tag de autenticación GCM (16 bytes) es separado del ciphertext para almacenarse de forma explícita.

```js
export async function encryptMessage(plaintext) {
  // Clave AES-256 efímera, extractable para cifrarla con RSA después
  const aesKey = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  )

  // Nonce único de 12 bytes — nunca reutilizado con la misma clave
  const iv = window.crypto.getRandomValues(new Uint8Array(12))

  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    aesKey,
    encoder.encode(plaintext),
  )

  // Web Crypto devuelve ciphertext || tag — se separan manualmente
  const { ciphertextBuffer: rawCiphertext, authTagBuffer } =
    splitCiphertextAndTag(ciphertextBuffer)

  const rawAesKey = await window.crypto.subtle.exportKey('raw', aesKey)

  return {
    ciphertext_base64: arrayBufferToBase64(rawCiphertext),
    nonce_base64:      arrayBufferToBase64(iv),
    auth_tag_base64:   arrayBufferToBase64(authTagBuffer),
    rawAesKey,
    timestamp: new Date().toISOString(),
  }
}
```

Objeto almacenado resultante:

```json
{
  "ciphertext_base64": "sJJq0w==",
  "nonce_base64":      "+UDP65WM/BenSg03",
  "auth_tag_base64":   "VthXNt2xwZuJhWGyceX20w==",
  "timestamp":         "2026-05-05T03:24:12.738Z"
}
```

---

## 2. Cifrado híbrido — clave AES cifrada con RSA-OAEP

Archivo: [src/utils/crypto/rsaOaep.js](src/utils/crypto/rsaOaep.js)

La clave AES efímera se cifra con la llave pública RSA-2048 del destinatario usando RSA-OAEP + SHA-256. Solo quien tenga la llave privada correspondiente puede recuperarla.

```js
export async function encryptAesKeyWithPublicKey(rawAesKey, publicKeyPem) {
  const publicKey = await window.crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(publicKeyPem),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  )

  const encryptedKey = await window.crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    rawAesKey,
  )

  return arrayBufferToBase64(encryptedKey)
}

export async function decryptAesKeyWithPrivateKey(encryptedKey, privateKeyPem) {
  const privateKey = await window.crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(privateKeyPem),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt'],
  )

  return await window.crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    base64ToArrayBuffer(encryptedKey),
  )
}
```

---

## 3. Descifrado funcional end-to-end

Archivo: [src/utils/crypto/hybridMessageCrypto.js](src/utils/crypto/hybridMessageCrypto.js)

El destinatario recupera la clave AES descifrando su `encrypted_key_base64` con su llave privada RSA y luego descifra el mensaje. `decryptStoredMessage` intenta cada clave cifrada disponible hasta encontrar la propia.

```js
export async function decryptMessageForRecipient(encryptedMessage, recipientPrivateKeyPem) {
  // 1. Descifrar la clave AES con la llave privada RSA
  const rawAesKey = await decryptAesKeyWithPrivateKey(
    encryptedMessage.encrypted_key_base64,
    recipientPrivateKeyPem,
  )

  // 2. Descifrar el mensaje con la clave AES recuperada
  return await decryptMessage(
    encryptedMessage.ciphertext_base64,
    encryptedMessage.nonce_base64,
    rawAesKey,
    encryptedMessage.auth_tag_base64,
  )
}

export async function decryptStoredMessage(encryptedMessage, recipientPrivateKeyPem) {
  const encryptedKeys = encryptedMessage.encrypted_keys ?? []
  let lastError = null

  // Probar cada encrypted_key hasta encontrar la del destinatario
  for (const messageKey of encryptedKeys) {
    try {
      return await decryptMessageForRecipient(
        { ...encryptedMessage, encrypted_key_base64: messageKey.encrypted_key_base64 },
        recipientPrivateKeyPem,
      )
    } catch (error) {
      lastError = error
    }
  }

  throw lastError ?? new Error('No hay una clave cifrada para descifrar el mensaje.')
}
```

Flujo completo desde el cliente:

```js
// Enviar
const payload = await encryptMessageForRecipients(texto, miembros)
await apiRequest('/messages', { method: 'POST', body: JSON.stringify(payload) })

// Recibir y descifrar
const { messages } = await apiRequest(`/messages/${userId}`)
const plaintext = await decryptStoredMessage(messages[0], privateKeyPem)
```

---

## 4. Mensajería grupal con clave compartida

Archivo: [src/utils/crypto/hybridMessageCrypto.js](src/utils/crypto/hybridMessageCrypto.js)

Para chats grupales, el ciphertext es único (un solo cifrado AES-256-GCM), pero la clave AES se cifra individualmente con la llave pública RSA de cada miembro. Cada miembro recibe su propio `encrypted_key_base64`.

```js
export async function encryptMessageForRecipients(plaintext, recipients) {
  // Un solo cifrado AES — mismo ciphertext para todos los miembros
  const encryptedMessage = await encryptMessage(plaintext)

  // Una encrypted_key por miembro, cifrada con su llave pública RSA
  const encryptedKeys = await Promise.all(
    recipients.map(async (recipient) => ({
      user_id: recipient.user_id,
      encrypted_key_base64: await encryptAesKeyWithPublicKey(
        encryptedMessage.rawAesKey,
        recipient.public_key_pem,
      ),
    })),
  )

  return {
    ciphertext_base64: encryptedMessage.ciphertext_base64,
    nonce_base64:      encryptedMessage.nonce_base64,
    auth_tag_base64:   encryptedMessage.auth_tag_base64,
    encrypted_keys:    encryptedKeys,
    timestamp:         encryptedMessage.timestamp,
  }
}
```

Las llaves públicas de los miembros se obtienen antes de cifrar:

```js
// src/services/messageService.js
const keysData = await apiRequest(`/groups/${group_id}/members/keys`)
const payload  = await encryptMessageForRecipients(content, keysData.members)
```

Resultado en `message_keys` (una fila por miembro):

```json
[
  { "message_id": "uuid", "encrypted_key_base64": "Ee/8Bz..." },
  { "message_id": "uuid", "encrypted_key_base64": "Hz4yR5..." },
  { "message_id": "uuid", "encrypted_key_base64": "F6x7TJ..." }
]
```

---

## 5. POST y GET de mensajes via API REST

Archivo: [app.js (Express)](app.js)

### POST /messages

Requiere JWT. Verifica que el remitente sea miembro del canal, guarda el mensaje cifrado y una `encrypted_key` por destinatario.

```js
app.post('/messages', requireAuth, async (req, res) => {
  const channelId     = req.body.channel_id || req.body.group_id
  const encryptedKeys = req.body.encrypted_keys

  await ensureChannelMember(channelId, req.auth.sub)

  const { data: message } = await supabase
    .from('messages')
    .insert({
      channel_id:        channelId,
      sender_id:         req.auth.sub,
      ciphertext_base64: req.body.ciphertext_base64,
      nonce_base64:      req.body.nonce_base64,
      auth_tag_base64:   req.body.auth_tag_base64,
    })
    .select()
    .single()

  await supabase.from('message_keys').insert(
    encryptedKeys.map((key) => ({
      message_id:           message.id,
      encrypted_key_base64: key.encrypted_key_base64,
    })),
  )

  res.status(201).json({ message })
})
```

### GET /messages/:userId

Retorna todos los mensajes cifrados de los canales del usuario, incluyendo las `encrypted_keys` de cada mensaje.

```js
app.get('/messages/:userId', requireAuth, async (req, res) => {
  if (req.params.userId !== req.auth.sub) throw new Error('Acceso denegado.')

  const { data: memberships } = await supabase
    .from('channel_members')
    .select('channel_id')
    .eq('user_id', req.auth.sub)

  const channelIds = memberships.map((m) => m.channel_id)

  const { data: messages } = await supabase
    .from('messages')
    .select('id, created_at, channel_id, sender_id, ciphertext_base64, nonce_base64, auth_tag_base64')
    .in('channel_id', channelIds)
    .order('created_at', { ascending: false })

  const { data: keys } = await supabase
    .from('message_keys')
    .select('id, message_id, encrypted_key_base64')
    .in('message_id', messages.map((m) => m.id))

  res.json({
    messages: messages.map((msg) => ({
      ...msg,
      encrypted_keys: keys.filter((k) => k.message_id === msg.id),
    })),
  })
})
```

Ejemplo de respuesta:

```json
{
  "messages": [
    {
      "id": "c12eb2f9-...",
      "channel_id": "417456cf-...",
      "sender_id": "uuid-remitente",
      "ciphertext_base64": "sJJq0w==",
      "nonce_base64": "+UDP65WM/BenSg03",
      "auth_tag_base64": "VthXNt2xwZuJhWGyceX20w==",
      "created_at": "2026-05-05T03:24:12.738Z",
      "encrypted_keys": [
        { "id": 1, "message_id": "c12eb2f9-...", "encrypted_key_base64": "Ee/8Bz..." },
        { "id": 2, "message_id": "c12eb2f9-...", "encrypted_key_base64": "Hz4yR5..." },
        { "id": 3, "message_id": "c12eb2f9-...", "encrypted_key_base64": "F6x7TJ..." }
      ]
    }
  ]
}
```
---
## 6. Pruebas unitarias
- [AES GCM](src\tests\aesGcm.test.js)
- [Base64](src\tests\base64.test.js)
- [Encrypt Message](src\tests\messageCrypto.test.js)

![phase 2 tests](.\src\assets\phase2tests.jpeg)