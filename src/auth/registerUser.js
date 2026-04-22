import { supabase } from '../lib/supabaseClient'
import { hashPassword } from './passwordHash'
import { generateRsaKeyPairPem } from '../utils/rsaKeyPair'
import { encryptPrivateKey } from '../utils/privateKeyEncryption'
import { saveEncryptedKeyToDesktop } from '../utils/saveToDesktop'

const USER_TABLE = 'user'

export async function registerUser({ name, email, password }) {
  const cleanName = name.trim()
  const cleanEmail = email.trim().toLowerCase()

  if (!cleanName) throw new Error('Ingresa tu nombre.')
  if (!cleanEmail) throw new Error('Ingresa tu correo.')

  const [passwordHash, { publicKeyPem, privateKeyPem }] = await Promise.all([
    hashPassword(password),
    generateRsaKeyPairPem(),
  ])

  const encryptedKey = await encryptPrivateKey(privateKeyPem, password)

  const { data, error } = await supabase
    .from(USER_TABLE)
    .insert({
      name: cleanName,
      email: cleanEmail,
      password: passwordHash,
      key: publicKeyPem,
    })
    .select('id, name, email')
    .single()

  if (error) {
    if (error.code === '23505') throw new Error('Ese correo ya esta registrado.')
    throw new Error(error.message)
  }

  await saveEncryptedKeyToDesktop(cleanEmail, encryptedKey)

  return data
}
