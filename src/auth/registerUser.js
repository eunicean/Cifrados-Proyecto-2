import { supabase } from '../lib/supabaseClient'
import { hashPassword } from './passwordHash'

const USER_TABLE = 'user'

export async function registerUser({ name, email, password }) {
  const cleanName = name.trim()
  const cleanEmail = email.trim().toLowerCase()

  if (!cleanName) {
    throw new Error('Ingresa tu nombre.')
  }

  if (!cleanEmail) {
    throw new Error('Ingresa tu correo.')
  }

  const passwordHash = await hashPassword(password)

  const { data, error } = await supabase
    .from(USER_TABLE)
    .insert({
      name: cleanName,
      email: cleanEmail,
      password_hash: passwordHash,
    })
    .select('id, name, email')
    .single()

  if (error) {
    if (error.code === '23505') {
      throw new Error('Ese correo ya esta registrado.')
    }

    throw new Error(error.message)
  }

  return data
}
