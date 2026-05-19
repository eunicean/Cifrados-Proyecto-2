import fs from 'node:fs'
import { createClient } from '@supabase/supabase-js'

const BLOCKCHAIN_TABLE = 'blockchain_blocks'

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

const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL
const supabaseKey =
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_ANON_KEY ||
  process.env.VITE_SUPABASE_PUBLISHABLE_KEY

if (!supabaseUrl || !supabaseKey) {
  throw new Error('Faltan variables de Supabase para iniciar blockchain.')
}

const supabase = createClient(supabaseUrl, supabaseKey)

function mapDbBlockToDomain(block) {
  return {
    id: block.id,
    index: block.block_index,
    timestamp: block.timestamp,
    message_id: block.message_id,
    sender_id: block.sender_id,
    recipient_id: block.recipient_id,
    group_id: block.group_id,
    message_hash: block.message_hash,
    previous_hash: block.previous_hash,
    nonce: block.nonce,
    hash: block.hash,
    created_at: block.created_at,
  }
}

function mapDomainBlockToDb(block) {
  return {
    block_index: block.index,
    timestamp: block.timestamp,
    message_id: block.message_id,
    sender_id: block.sender_id,
    recipient_id: block.recipient_id,
    group_id: block.group_id,
    message_hash: block.message_hash,
    previous_hash: block.previous_hash,
    nonce: block.nonce,
    hash: block.hash,
  }
}

export async function getBlockchain() {
  const { data, error } = await supabase
    .from(BLOCKCHAIN_TABLE)
    .select('*')
    .order('block_index', { ascending: true })

  if (error) {
    throw new Error(error.message)
  }

  return data.map(mapDbBlockToDomain)
}

export async function getLastBlock() {
  const { data, error } = await supabase
    .from(BLOCKCHAIN_TABLE)
    .select('*')
    .order('block_index', { ascending: false })
    .limit(1)
    .maybeSingle()

  if (error) {
    throw new Error(error.message)
  }

  return data ? mapDbBlockToDomain(data) : null
}

export async function saveBlock(block) {
  const { data, error } = await supabase
    .from(BLOCKCHAIN_TABLE)
    .insert(mapDomainBlockToDb(block))
    .select('*')
    .single()

  if (error) {
    throw new Error(error.message)
  }

  return mapDbBlockToDomain(data)
}
