function bufferToPem(buffer, label) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  bytes.forEach(b => { binary += String.fromCharCode(b) })
  const base64 = btoa(binary)
  const lines = base64.match(/.{1,64}/g).join('\n')
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`
}

export async function generateRsaKeyPairPem() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  )

  const [publicKeyBuffer, privateKeyBuffer] = await Promise.all([
    window.crypto.subtle.exportKey('spki', keyPair.publicKey),
    window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey),
  ])

  return {
    publicKeyPem: bufferToPem(publicKeyBuffer, 'PUBLIC KEY'),
    privateKeyPem: bufferToPem(privateKeyBuffer, 'PRIVATE KEY'),
  }
}
