import { verifyPassword } from './passwordHash.js'
import { issueJwt } from '../utils/jwt.js'

export async function loginUser(
  { email, password },
  dependencies,
) {
  const cleanEmail = email.trim().toLowerCase()

  if (!cleanEmail) throw new Error('Ingresa tu correo.')
  if (typeof password !== 'string' || !password) {
    throw new Error('Ingresa tu contraseña.')
  }

  const { findUserByEmail, jwtSecret, jwtExpiresIn = '1h' } = dependencies

  const user = await findUserByEmail(cleanEmail)

  if (!user?.password) {
    throw new Error('Credenciales invalidas.')
  }

  const isValidPassword = await verifyPassword(password, user.password)

  if (!isValidPassword) {
    throw new Error('Credenciales invalidas.')
  }

  const token = issueJwt(
    {
      sub: String(user.id),
      email: user.email,
      name: user.name,
    },
    jwtSecret,
    { expiresIn: jwtExpiresIn },
  )

  return {
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
    },
  }
}
