import { apiRequest } from '../utils/apiClient'
import { encryptPrivateKey } from '../utils/privateKeyEncryption'
import { generateRsaKeyPairPem } from '../utils/rsaKeyPair'
import { saveEncryptedKeyToDesktop } from '../utils/saveToDesktop'

export async function registerWithKeyPair(registerForm) {
  const { publicKeyPem, privateKeyPem } = await generateRsaKeyPairPem()
  const encryptedPrivateKey = await encryptPrivateKey(
    privateKeyPem,
    registerForm.password,
  )

  const data = await apiRequest('/auth/register', {
    method: 'POST',
    body: JSON.stringify({
      name: registerForm.display_name,
      email: registerForm.email,
      password: registerForm.password,
      public_key: publicKeyPem,
    }),
  })

  await saveEncryptedKeyToDesktop(registerForm.email, encryptedPrivateKey)

  return data
}

export async function loginWithPassword(loginForm) {
  return await apiRequest('/auth/login', {
    method: 'POST',
    body: JSON.stringify(loginForm),
  })
}
