import bcrypt from 'bcryptjs'

const BCRYPT_SALT_ROUNDS = 12

export async function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 8) {
    throw new Error('La contraseña debe tener al menos 8 caracteres.')
  }

  return bcrypt.hash(password, BCRYPT_SALT_ROUNDS)
}

export async function verifyPassword(password, passwordHash) {
  return bcrypt.compare(password, passwordHash)
}
