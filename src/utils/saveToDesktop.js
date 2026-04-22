function sanitizeEmail(email) {
  return email.replace(/[^a-zA-Z0-9._-]/g, '_')
}

export async function saveEncryptedKeyToDesktop(email, encryptedKey) {
  const filename = `${sanitizeEmail(email)}_private_key.json`
  const content = JSON.stringify(encryptedKey, null, 2)

  if ('showSaveFilePicker' in window) {
    try {
      const handle = await window.showSaveFilePicker({
        suggestedName: filename,
        types: [
          {
            description: 'Llave privada cifrada',
            accept: { 'application/json': ['.json'] },
          },
        ],
      })
      const writable = await handle.createWritable()
      await writable.write(content)
      await writable.close()
      return
    } catch (err) {
      if (err.name === 'AbortError') return
      // NotAllowedError u otro: caer al fallback
    }
  }

  // Fallback: descarga estándar del navegador
  const blob = new Blob([content], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
