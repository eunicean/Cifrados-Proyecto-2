export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return btoa(binary)
}

export function base64ToArrayBuffer(base64) {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }

  return bytes.buffer
}

export function concatArrayBuffers(...buffers) {
  const totalLength = buffers.reduce((total, buffer) => total + buffer.byteLength, 0)
  const combined = new Uint8Array(totalLength)
  let offset = 0

  buffers.forEach((buffer) => {
    combined.set(new Uint8Array(buffer), offset)
    offset += buffer.byteLength
  })

  return combined.buffer
}
