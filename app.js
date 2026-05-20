import fs from 'node:fs'
import crypto from 'node:crypto'
import express from 'express'
import { createClient } from '@supabase/supabase-js'
import { hashPassword } from './src/auth/passwordHash.js'
import { loginUser } from './src/auth/loginUser.js'
import {
  getFullBlockchain,
  registerMessageTransaction,
  tamperBlockForDemo,
  verifyFullBlockchain,
} from './src/blockchain/blockchainService.js'
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

function logInfo(scope, message, details = {}) {
  console.log(`[${scope}] ${message}`, details)
}

function logWarn(scope, message, details = {}) {
  console.warn(`[${scope}] ${message}`, details)
}

function shortValue(value) {
  if (!value) return null
  return String(value).slice(0, 12)
}

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

function generateGroupCode(length = 8) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const bytes = crypto.randomBytes(length)

  return Array.from(bytes, (byte) => chars[byte % chars.length]).join('')
}

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex')
}

function sendError(res, error, status = 400) {
  logWarn('api', 'Solicitud rechazada', {
    status,
    message: error.message || 'Ocurrio un error.',
  })

  res.status(status).json({
    message: error.message || 'Ocurrio un error.',
  })
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
  logInfo('authz', 'Verificando membresia de canal', {
    channelId,
    userId,
  })

  const { data, error } = await supabase
    .from('channel_members')
    .select('id')
    .eq('channel_id', channelId)
    .eq('user_id', userId)
    .maybeSingle()

  if (error) throw new Error(error.message)
  if (!data) throw new Error('No perteneces a este chat.')

  logInfo('authz', 'Membresia confirmada', {
    channelId,
    userId,
  })
}

function buildDirectChannelName(userId, recipientId) {
  return `direct:${[userId, recipientId].sort().join(':')}`
}

async function attachSenderPublicKeys(messages) {
  const senderIds = [
    ...new Set(messages.map((message) => message.sender_id).filter(Boolean)),
  ]

  if (senderIds.length === 0) return messages

  const { data: users, error } = await supabase
    .from('user')
    .select('id, key')
    .in('id', senderIds)

  if (error) throw new Error(error.message)

  const publicKeysByUserId = new Map(
    users.map((user) => [user.id, user.key]),
  )

  return messages.map((message) => ({
    ...message,
    sender_public_key: publicKeysByUserId.get(message.sender_id) || '',
  }))
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

    logInfo('auth', 'Registrando usuario con llave publica', {
      email,
      hasPublicKey: Boolean(publicKey),
    })

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
      if (error.code === '23505') {
        throw new Error('Ese correo ya esta registrado.')
      }

      throw new Error(error.message)
    }

    logInfo('auth', 'Usuario registrado', {
      userId: data.id,
      email: data.email,
    })

    res.status(201).json({
      user: data,
    })
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

    logInfo('auth', 'Sesion iniciada', {
      userId: result.user?.id,
      email: result.user?.email,
    })

    res.json(result)
  } catch (error) {
    sendError(res, error, 401)
  }
})

app.post('/groups', requireAuth, async (req, res) => {
  try {
    const name = (req.body.name || '').trim()

    if (!name) throw new Error('Ingresa el nombre del grupo.')

    const code = generateGroupCode()
    const keyHash = hashCode(code)

    logInfo('groups', 'Creando grupo', {
      name,
      createdBy: req.auth.sub,
      keyHash: shortValue(keyHash),
    })

    const { data: channel, error: channelError } = await supabase
      .from('channels')
      .insert({
        name,
        created_by: req.auth.sub,
        key_hash: keyHash,
        group_code: code,
      })
      .select('id, name, created_at, created_by')
      .single()

    if (channelError) throw new Error(channelError.message)

    const { error: membersError } = await supabase
      .from('channel_members')
      .insert({
        channel_id: channel.id,
        user_id: req.auth.sub,
      })

    if (membersError) throw new Error(membersError.message)

    logInfo('groups', 'Grupo creado', {
      groupId: channel.id,
      createdBy: req.auth.sub,
    })

    res.status(201).json({
      group: {
        ...channel,
        invite_code: code,
        member_ids: [req.auth.sub],
      },
      code,
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
      .select('id, name, created_at, created_by, group_code')
      .in('id', channelIds)
      .not('name', 'like', 'direct:%')
      .order('created_at', { ascending: false })

    if (channelsError) throw new Error(channelsError.message)

    const { data: allMembers, error: allMembersError } = await supabase
      .from('channel_members')
      .select('channel_id, user_id')
      .in('channel_id', channelIds)

    if (allMembersError) throw new Error(allMembersError.message)

    const userIds = [
      ...new Set(allMembers.map((member) => member.user_id).filter(Boolean)),
    ]

    const { data: users, error: usersError } = await supabase
      .from('user')
      .select('id, name, email')
      .in('id', userIds)

    if (usersError) throw new Error(usersError.message)

    logInfo('groups', 'Grupos cargados', {
      userId: req.auth.sub,
      count: channels.length,
    })

    res.json({
      groups: channels.map((channel) => {
        const members = allMembers
          .filter((member) => member.channel_id === channel.id)
          .map((member) => {
            const user = users.find(
              (currentUser) => currentUser.id === member.user_id,
            )

            return {
              user_id: member.user_id,
              name: user?.name || user?.email || member.user_id,
              email: user?.email || '',
            }
          })

        return {
          id: channel.id,
          name: channel.name,
          created_at: channel.created_at,
          created_by: channel.created_by,
          invite_code:
            channel.created_by === req.auth.sub ? channel.group_code : null,
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

app.get('/direct-conversations', requireAuth, async (req, res) => {
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
      logInfo('direct', 'Sin conversaciones directas', {
        userId: req.auth.sub,
      })

      res.json({ conversations: [] })
      return
    }

    const { data: channels, error: channelsError } = await supabase
      .from('channels')
      .select('id, name, created_at')
      .in('id', channelIds)
      .like('name', 'direct:%')
      .order('created_at', { ascending: false })

    if (channelsError) throw new Error(channelsError.message)

    if (channels.length === 0) {
      res.json({ conversations: [] })
      return
    }

    const directChannelIds = channels.map((channel) => channel.id)

    const { data: members, error: membersError } = await supabase
      .from('channel_members')
      .select('channel_id, user_id')
      .in('channel_id', directChannelIds)

    if (membersError) throw new Error(membersError.message)

    const contactIds = [
      ...new Set(
        members
          .map((member) => member.user_id)
          .filter((userId) => userId && userId !== req.auth.sub),
      ),
    ]

    if (contactIds.length === 0) {
      res.json({ conversations: [] })
      return
    }

    const { data: users, error: usersError } = await supabase
      .from('user')
      .select('id, name, email, key')
      .in('id', contactIds)

    if (usersError) throw new Error(usersError.message)

    logInfo('direct', 'Conversaciones directas cargadas', {
      userId: req.auth.sub,
      count: channels.length,
    })

    res.json({
      conversations: channels.map((channel) => {
        const contactMembership = members.find(
          (member) =>
            member.channel_id === channel.id &&
            member.user_id !== req.auth.sub,
        )

        const contact = users.find(
          (user) => user.id === contactMembership?.user_id,
        )

        return {
          id: contact?.id || contactMembership?.user_id || channel.id,
          channel_id: channel.id,
          name: contact?.name || contact?.email || 'Contacto',
          email: contact?.email || '',
          key: contact?.key || '',
        }
      }),
    })
  } catch (error) {
    sendError(res, error, 403)
  }
})

app.post('/direct-conversations', requireAuth, async (req, res) => {
  try {
    const recipientEmail = (req.body.recipient_email || '').trim().toLowerCase()
    const recipientId = req.body.recipient_id

    let recipientQuery = supabase
      .from('user')
      .select('id, name, email, key')

    recipientQuery = recipientId
      ? recipientQuery.eq('id', recipientId)
      : recipientQuery.eq('email', recipientEmail)

    const { data: recipient, error: recipientError } =
      await recipientQuery.maybeSingle()

    if (recipientError) throw new Error(recipientError.message)
    if (!recipient) throw new Error('Contacto no encontrado.')
    if (recipient.id === req.auth.sub) {
      throw new Error('No puedes iniciar un chat contigo mismo.')
    }

    const channelName = buildDirectChannelName(req.auth.sub, recipient.id)

    logInfo('direct', 'Preparando conversacion directa', {
      senderId: req.auth.sub,
      recipientId: recipient.id,
      channelName,
    })

    const { data: existingChannel, error: existingChannelError } =
      await supabase
        .from('channels')
        .select('id, name, created_at')
        .eq('name', channelName)
        .maybeSingle()

    if (existingChannelError) throw new Error(existingChannelError.message)

    let channel = existingChannel

    if (!channel) {
      const { data: newChannel, error: channelError } = await supabase
        .from('channels')
        .insert({
          name: channelName,
          created_by: req.auth.sub,
        })
        .select('id, name, created_at')
        .single()

      if (channelError) throw new Error(channelError.message)

      const { error: membersError } = await supabase
        .from('channel_members')
        .insert([
          {
            channel_id: newChannel.id,
            user_id: req.auth.sub,
          },
          {
            channel_id: newChannel.id,
            user_id: recipient.id,
          },
        ])

      if (membersError) throw new Error(membersError.message)

      channel = newChannel
    }

    logInfo(
      'direct',
      existingChannel ? 'Conversacion reutilizada' : 'Conversacion creada',
      {
        channelId: channel.id,
        senderId: req.auth.sub,
        recipientId: recipient.id,
      },
    )

    res.status(existingChannel ? 200 : 201).json({
      conversation: {
        id: recipient.id,
        channel_id: channel.id,
        name: recipient.name || recipient.email,
        email: recipient.email,
        key: recipient.key,
      },
    })
  } catch (error) {
    sendError(res, error)
  }
})

app.get('/groups/search', requireAuth, async (req, res) => {
  try {
    const name = (req.query.name || '').trim()

    if (!name) {
      res.json({ groups: [] })
      return
    }

    const { data: channels, error } = await supabase
      .from('channels')
      .select('id, name, created_at, created_by')
      .ilike('name', `%${name}%`)
      .limit(20)

    if (error) throw new Error(error.message)

    const channelIds = channels.map((channel) => channel.id)
    let memberChannelIds = new Set()

    if (channelIds.length > 0) {
      const { data: memberships } = await supabase
        .from('channel_members')
        .select('channel_id')
        .eq('user_id', req.auth.sub)
        .in('channel_id', channelIds)

      memberChannelIds = new Set(
        (memberships || []).map((membership) => membership.channel_id),
      )
    }

    logInfo('groups', 'Busqueda de grupos completada', {
      userId: req.auth.sub,
      query: name,
      count: channels.length,
    })

    res.json({
      groups: channels.map((channel) => ({
        ...channel,
        is_member: memberChannelIds.has(channel.id),
      })),
    })
  } catch (error) {
    sendError(res, error)
  }
})

app.post('/groups/:id/join', requireAuth, async (req, res) => {
  try {
    const code = (req.body.code || '').trim()

    if (!code) throw new Error('Ingresa el código del grupo.')

    const { data: channel, error: channelError } = await supabase
      .from('channels')
      .select('id, name, key_hash')
      .eq('id', req.params.id)
      .maybeSingle()

    if (channelError) throw new Error(channelError.message)
    if (!channel) throw new Error('Grupo no encontrado.')

    if (hashCode(code) !== channel.key_hash) {
      logWarn('groups', 'Codigo de grupo incorrecto', {
        groupId: req.params.id,
        userId: req.auth.sub,
      })

      throw new Error('Código de grupo incorrecto.')
    }

    const { data: existing } = await supabase
      .from('channel_members')
      .select('id')
      .eq('channel_id', req.params.id)
      .eq('user_id', req.auth.sub)
      .maybeSingle()

    if (!existing) {
      const { error: memberError } = await supabase
        .from('channel_members')
        .insert({
          channel_id: req.params.id,
          user_id: req.auth.sub,
        })

      if (memberError) throw new Error(memberError.message)
    }

    logInfo(
      'groups',
      existing ? 'Grupo desbloqueado por miembro existente' : 'Usuario unido al grupo',
      {
        groupId: req.params.id,
        userId: req.auth.sub,
      },
    )

    res.json({
      joined: !existing,
      group: {
        id: channel.id,
        name: channel.name,
      },
    })
  } catch (error) {
    sendError(res, error)
  }
})

app.get('/groups/:groupId/messages', requireAuth, async (req, res) => {
  try {
    await ensureChannelMember(req.params.groupId, req.auth.sub)

    const { data: messages, error: messagesError } = await supabase
      .from('messages')
      .select(
        'id, created_at, channel_id, sender_id, ciphertext_base64, nonce_base64, auth_tag_base64, plaintext_hash, signature_base64, signature_algorithm',
      )
      .eq('channel_id', req.params.groupId)
      .order('created_at', { ascending: true })

    if (messagesError) throw new Error(messagesError.message)

    const messagesWithSenderKeys = await attachSenderPublicKeys(messages || [])

    logInfo('messages', 'Mensajes de grupo cargados', {
      groupId: req.params.groupId,
      userId: req.auth.sub,
      count: messagesWithSenderKeys.length,
    })

    res.json({
      messages: messagesWithSenderKeys,
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

    logInfo('messages', 'Llaves publicas de miembros cargadas', {
      groupId: req.params.groupId,
      members: users.length,
    })

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

    if (!channelId) throw new Error('Falta el ID del canal.')
    if (!req.body.ciphertext_base64) throw new Error('Falta el ciphertext.')
    if (!req.body.nonce_base64) throw new Error('Falta el nonce.')
    if (!req.body.auth_tag_base64) {
      throw new Error('Falta el tag de autenticacion.')
    }

    await ensureChannelMember(channelId, req.auth.sub)

    logInfo('messages', 'Guardando mensaje cifrado', {
      channelId,
      senderId: req.auth.sub,
      hasPlaintextHash: Boolean(req.body.plaintext_hash || req.body.message_hash),
      hasSignature: Boolean(req.body.signature_base64),
      encryptedKeys: encryptedKeys.length,
    })

    const { data: message, error: messageError } = await supabase
      .from('messages')
      .insert({
        channel_id: channelId,
        sender_id: req.auth.sub,
        ciphertext_base64: req.body.ciphertext_base64,
        nonce_base64: req.body.nonce_base64,
        auth_tag_base64: req.body.auth_tag_base64,
        plaintext_hash: req.body.plaintext_hash || req.body.message_hash || null,
        signature_base64: req.body.signature_base64 || null,
        signature_algorithm: req.body.signature_algorithm || null,
      })
      .select(
        'id, created_at, channel_id, sender_id, ciphertext_base64, nonce_base64, auth_tag_base64, plaintext_hash, signature_base64, signature_algorithm',
      )
      .single()

    if (messageError) throw new Error(messageError.message)

    logInfo('messages', 'Mensaje guardado', {
      messageId: message.id,
      channelId: message.channel_id,
      hash: shortValue(message.plaintext_hash),
      signatureAlgorithm: message.signature_algorithm || 'none',
    })

    let blockchainBlock = null

    try {
      blockchainBlock = await registerMessageTransaction({
        ...message,
        group_id: message.channel_id,
        message_hash: message.plaintext_hash,
      })

      logInfo('blockchain', 'Mensaje registrado en blockchain', {
        messageId: message.id,
        blockIndex: blockchainBlock.index,
        blockHash: shortValue(blockchainBlock.hash),
        previousHash: shortValue(blockchainBlock.previous_hash),
      })
    } catch (blockchainError) {
      console.error(
        '[blockchain] No se pudo registrar el mensaje:',
        blockchainError.message,
      )
    }

    let keys = []

    if (encryptedKeys.length > 0) {
      const { data: insertedKeys, error: keysError } = await supabase
        .from('message_keys')
        .insert(
          encryptedKeys.map((key) => ({
            message_id: message.id,
            encrypted_key_base64:
              key.encrypted_key_base64 || key.encrypted_key,
          })),
        )
        .select('id, message_id, encrypted_key_base64')

      if (keysError) throw new Error(keysError.message)

      keys = insertedKeys || []

      logInfo('messages', 'Claves cifradas guardadas', {
        messageId: message.id,
        count: keys.length,
      })
    }

    const [messageWithSenderKey] = await attachSenderPublicKeys([message])

    res.status(201).json({
      message: {
        ...messageWithSenderKey,
        group_id: message.channel_id,
        ciphertext: message.ciphertext_base64,
        nonce: message.nonce_base64,
        auth_tag: message.auth_tag_base64,
        encrypted_keys: keys,
        blockchain_block: blockchainBlock,
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

    const channelIds = memberships
      .map((membership) => membership.channel_id)
      .filter(Boolean)

    if (channelIds.length === 0) {
      res.json({ messages: [] })
      return
    }

    const { data: allMessages, error: messagesError } = await supabase
      .from('messages')
      .select(
        'id, created_at, channel_id, sender_id, ciphertext_base64, nonce_base64, auth_tag_base64, plaintext_hash, signature_base64, signature_algorithm',
      )
      .in('channel_id', channelIds)
      .order('created_at', { ascending: false })

    if (messagesError) throw new Error(messagesError.message)

    logInfo('messages', 'Mensajes del usuario cargados', {
      userId: req.auth.sub,
      count: allMessages.length,
    })

    const messageIds = allMessages.map((message) => message.id)

    if (messageIds.length === 0) {
      res.json({ messages: [] })
      return
    }

    const { data: keys, error: keysError } = await supabase
      .from('message_keys')
      .select('id, message_id, encrypted_key_base64')
      .in('message_id', messageIds)

    if (keysError) throw new Error(keysError.message)

    const messagesWithSenderKeys = await attachSenderPublicKeys(allMessages)

    res.json({
      messages: messagesWithSenderKeys.map((message) => ({
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

app.get('/users', async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('user')
      .select('id, name, email, key')

    if (error) throw new Error(error.message)

    res.json({
      users,
    })
  } catch (error) {
    sendError(res, error)
  }
})

app.get('/blockchain', requireAuth, async (req, res) => {
  try {
    const blocks = await getFullBlockchain()

    logInfo('blockchain', 'Cadena consultada', {
      userId: req.auth.sub,
      blocks: blocks.length,
    })

    res.json({
      blocks,
      total_blocks: blocks.length,
    })
  } catch (error) {
    sendError(res, error, 500)
  }
})

app.get('/blockchain/verify', requireAuth, async (req, res) => {
  try {
    const verification = await verifyFullBlockchain()

    logInfo('blockchain', 'Verificacion de cadena ejecutada', {
      userId: req.auth.sub,
      valid: verification.valid,
      blocks: verification.blocks,
      invalidIndex: verification.invalid_index,
    })

    res.json(verification)
  } catch (error) {
    sendError(res, error, 500)
  }
})

app.post('/blockchain/tamper/:index', requireAuth, async (req, res) => {
  try {
    const block = await tamperBlockForDemo(req.params.index)
    const verification = await verifyFullBlockchain()

    logInfo('blockchain', 'Bloque modificado para demo', {
      userId: req.auth.sub,
      blockIndex: block.index,
      validAfterTamper: verification.valid,
      invalidIndex: verification.invalid_index,
    })

    res.json({
      message: 'Bloque modificado para demo.',
      block,
      verification,
    })
  } catch (error) {
    sendError(res, error, 400)
  }
})

app.listen(port, () => {
  logInfo('server', `API REST escuchando en http://localhost:${port}`, {
    supabaseUrl,
    hasServiceRole: Boolean(process.env.SUPABASE_SERVICE_ROLE_KEY),
  })
})