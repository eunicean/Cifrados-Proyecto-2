import { supabase } from '../lib/supabaseClient'

/**
 * Retorna la llave pública del usuario en formato PEM.
 */
export async function getUserPublicKey(userId) {
 // GET /users/{id}/key
  if (!userId) throw new Error('Se requiere el ID del usuario.')

  const { data, error } = await supabase
    .from('user')
    .select('key')
    .eq('id', userId)
    .single()

  if (error) {
    if (error.code === 'PGRST116') throw new Error('Usuario no encontrado.')
    throw new Error(error.message)
  }

  if (!data.key) throw new Error('Este usuario no tiene llave pública registrada.')

  return { public_key_pem: data.key }
}
