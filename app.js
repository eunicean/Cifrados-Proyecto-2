import fs from 'node:fs'
import express from 'express'
import { createClient } from '@supabase/supabase-js'
import { hashPassword } from './src/auth/passwordHash.js'
import { loginUser } from './src/auth/loginUser.js'
import { verifyJwt } from './src/utils/jwt.js'

function loadLocalEnv() {
  if (!fs.existsSync('.env')) return

  const lines = fs.readFileSync('.env', 'utf8').split('\n')
  lines.forEach((line) => {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) return

    const [key, ...valueParts] = trimmed.split('=')
    if (process.env[key]) return
    process.env[key] = valueParts.join('=').replace(/^["']|["']$/g, '')
  })
}

loadLocalEnv()

const app = express()
const port = process.env.PORT || 3000
const jwtSecret = process.env.JWT_SECRET || 'dev-secret-change-me'
const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL
const supabaseKey =
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_ANON_KEY ||
  process.env.VITE_SUPABASE_PUBLISHABLE_KEY

if (!supabaseUrl || !supabaseKey) {
  throw new Error('Faltan variables de Supabase para iniciar la API.')
}

const supabase = createClient(supabaseUrl, supabaseKey)

app.use(express.json({ limit: '1mb' }))
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', process.env.CLIENT_ORIGIN || '*')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')

  if (req.method === 'OPTIONS') {
    res.sendStatus(204)
    return
  }

  next()
})

function sendError(res, error, status = 400) {
  res.status(status).json({ message: error.message || 'Ocurrio un error.' })
}

function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || ''
    const token = header.startsWith('Bearer ') ? header.slice(7) : ''
    req.auth = verifyJwt(token, jwtSecret)
    next()
  } catch (error) {
    sendError(res, error, 401)
  }
}

async function ensureChannelMember(channelId, userId) {
  const { data, error } = await supabase
    .from('channel_members')
    .select('id')
    .eq('channel_id', channelId)
    .eq('user_id', userId)
    .maybeSingle()

  if (error) throw new Error(error.message)
  if (!data) throw new Error('No perteneces a este chat.')
}

app.post('/auth/register', async (req, res) => {
  try {
    const name = (req.body.name || req.body.display_name || '').trim()
    const email = (req.body.email || '').trim().toLowerCase()
    const password = req.body.password
    const publicKey = req.body.public_key || req.body.key

    if (!name) throw new Error('Ingresa tu nombre.')
    if (!email) throw new Error('Ingresa tu correo.')
    if (!publicKey) throw new Error('Falta la llave publica RSA del usuario.')

    const passwordHash = await hashPassword(password)
    const { data, error } = await supabase
      .from('user')
      .insert({
        name,
        email,
        password: passwordHash,
        key: publicKey,
      })
      .select('id, name, email')
      .single()

    if (error) {
      if (error.code === '23505') throw new Error('Ese correo ya esta registrado.')
      throw new Error(error.message)
    }

    res.status(201).json({ user: data })
  } catch (error) {
    sendError(res, error)
  }
})

app.post('/auth/login', async (req, res) => {
  try {
    const result = await loginUser(req.body, {
      jwtSecret,
      jwtExpiresIn: process.env.JWT_EXPIRES_IN || '8h',
      findUserByEmail: async (email) => {
        const { data, error } = await supabase
          .from('user')
          .select('id, name, email, password')
          .eq('email', email)
          .maybeSingle()

        if (error) throw new Error(error.message)
        return data
      },
    })

    res.json(result)
  } catch (error) {
    sendError(res, error, 401)
  }
})

app.post('/groups', requireAuth, async (req, res) => {
  try {
    const name = (req.body.name || '').trim()
    const memberIds = Array.isArray(req.body.member_ids) ? req.body.member_ids : []
    const uniqueMemberIds = [...new Set([req.auth.sub, ...memberIds].filter(Boolean))]

    if (!name) throw new Error('Ingresa el nombre del grupo.')
    if (uniqueMemberIds.length < 2) {
      throw new Error('Agrega al menos un miembro adicional al grupo.')
    }

    const { data: channel, error: channelError } = await supabase
      .from('channels')
      .insert({ name, created_by: req.auth.sub })
      .select('id, name, created_at, created_by')
      .single()

    if (channelError) throw new Error(channelError.message)

    const { error: membersError } = await supabase
      .from('channel_members')
      .insert(
        uniqueMemberIds.map((userId) => ({
          channel_id: channel.id,
          user_id: userId,
        })),
      )

    if (membersError) throw new Error(membersError.message)

    res.status(201).json({
      group: {
        ...channel,
        member_ids: uniqueMemberIds,
      },
    })
  } catch (error) {
    sendError(res, error)
  }
})

app.get('/groups', requireAuth, async (req, res) => {
  try {
    const { data: memberships, error: membershipError } = await supabase
      .from('channel_members')
      .select('channel_id')
      .eq('user_id', req.auth.sub)

    if (membershipError) throw new Error(membershipError.message)

    const channelIds = memberships
      .map((membership) => membership.channel_id)
      .filter(Boolean)

    if (channelIds.length === 0) {
      res.json({ groups: [] })
      return
    }

    const { data: channels, error: channelsError } = await supabase
      .from('channels')
      .select('id, name, created_at, created_by')
      .in('id', channelIds)
      .order('created_at', { ascending: false })

    if (channelsError) throw new Error(channelsError.message)

    const { data: allMembers, error: allMembersError } = await supabase
      .from('channel_members')
      .select('channel_id, user_id')
      .in('channel_id', channelIds)

    if (allMembersError) throw new Error(allMembersError.message)

    const userIds = [...new Set(allMembers.map((member) => member.user_id).filter(Boolean))]
    const { data: users, error: usersError } = await supabase
      .from('user')
      .select('id, name, email')
      .in('id', userIds)

    if (usersError) throw new Error(usersError.message)

    res.json({
      groups: channels.map((channel) => {
        const members = allMembers
          .filter((member) => member.channel_id === channel.id)
          .map((member) => {
            const user = users.find((currentUser) => currentUser.id === member.user_id)
            return {
              user_id: member.user_id,
              name: user?.name || user?.email || member.user_id,
              email: user?.email || '',
            }
          })

        return {
          ...channel,
          description: `${members.length} miembro${members.length === 1 ? '' : 's'}`,
          members,
          member_ids: members.map((member) => member.user_id),
        }
      }),
    })
  } catch (error) {
    sendError(res, error, 403)
  }
})

app.get('/groups/:groupId/members/keys', requireAuth, async (req, res) => {
  try {
    await ensureChannelMember(req.params.groupId, req.auth.sub)

    const { data: members, error: membersError } = await supabase
      .from('channel_members')
      .select('user_id')
      .eq('channel_id', req.params.groupId)

    if (membersError) throw new Error(membersError.message)

    const userIds = members.map((member) => member.user_id).filter(Boolean)
    const { data: users, error: usersError } = await supabase
      .from('user')
      .select('id, name, email, key')
      .in('id', userIds)

    if (usersError) throw new Error(usersError.message)

    res.json({
      members: users.map((user) => ({
        user_id: user.id,
        name: user.name,
        email: user.email,
        public_key_pem: user.key,
      })),
    })
  } catch (error) {
    sendError(res, error, 403)
  }
})

app.post('/messages', requireAuth, async (req, res) => {
  try {
    const channelId = req.body.channel_id || req.body.group_id
    const encryptedKeys = Array.isArray(req.body.encrypted_keys)
      ? req.body.encrypted_keys
      : []

    if (!channelId) throw new Error('Falta el ID del grupo.')
    if (!req.body.ciphertext_base64) throw new Error('Falta el ciphertext.')
    if (!req.body.nonce_base64) throw new Error('Falta el nonce.')
    if (!req.body.auth_tag_base64) throw new Error('Falta el tag de autenticacion.')
    if (encryptedKeys.length === 0) throw new Error('Faltan las claves AES cifradas.')

    await ensureChannelMember(channelId, req.auth.sub)

    const { data: message, error: messageError } = await supabase
      .from('messages')
      .insert({
        channel_id: channelId,
        sender_id: req.auth.sub,
        ciphertext_base64: req.body.ciphertext_base64,
        nonce_base64: req.body.nonce_base64,
        auth_tag_base64: req.body.auth_tag_base64,
      })
      .select('id, created_at, channel_id, sender_id, ciphertext_base64, nonce_base64, auth_tag_base64')
      .single()

    if (messageError) throw new Error(messageError.message)

    const { data: keys, error: keysError } = await supabase
      .from('message_keys')
      .insert(
        encryptedKeys.map((key) => ({
          message_id: message.id,
          encrypted_key_base64: key.encrypted_key_base64 || key.encrypted_key,
        })),
      )
      .select('id, message_id, encrypted_key_base64')

    if (keysError) throw new Error(keysError.message)

    res.status(201).json({
      message: {
        ...message,
        group_id: message.channel_id,
        ciphertext: message.ciphertext_base64,
        nonce: message.nonce_base64,
        auth_tag: message.auth_tag_base64,
        encrypted_keys: keys,
      },
    })
  } catch (error) {
    sendError(res, error)
  }
})

app.get('/messages/:userId', requireAuth, async (req, res) => {
  try {
    if (req.params.userId !== req.auth.sub) {
      throw new Error('No puedes consultar mensajes de otro usuario.')
    }

    const { data: memberships, error: membershipError } = await supabase
      .from('channel_members')
      .select('channel_id')
      .eq('user_id', req.auth.sub)

    if (membershipError) throw new Error(membershipError.message)

    const channelIds = memberships.map((membership) => membership.channel_id).filter(Boolean)
    if (channelIds.length === 0) {
      res.json({ messages: [] })
      return
    }

    const { data: messages, error: messagesError } = await supabase
      .from('messages')
      .select('id, created_at, channel_id, sender_id, ciphertext_base64, nonce_base64, auth_tag_base64')
      .in('channel_id', channelIds)
      .order('created_at', { ascending: false })

    if (messagesError) throw new Error(messagesError.message)

    const messageIds = messages.map((message) => message.id)
    if (messageIds.length === 0) {
      res.json({ messages: [] })
      return
    }

    const { data: keys, error: keysError } = await supabase
      .from('message_keys')
      .select('id, message_id, encrypted_key_base64')
      .in('message_id', messageIds)

    if (keysError) throw new Error(keysError.message)

    res.json({
      messages: messages.map((message) => ({
        ...message,
        group_id: message.channel_id,
        ciphertext: message.ciphertext_base64,
        nonce: message.nonce_base64,
        auth_tag: message.auth_tag_base64,
        encrypted_keys: keys.filter((key) => key.message_id === message.id),
      })),
    })
  } catch (error) {
    sendError(res, error, 403)
  }
})

app.listen(port, () => {
  console.log(`API REST escuchando en http://localhost:${port}`)
})
