import { createClient } from '@supabase/supabase-js'

const viteEnv = import.meta.env || {}
const nodeEnv = typeof process !== 'undefined' ? process.env : {}
const supabaseUrl = viteEnv.VITE_SUPABASE_URL || nodeEnv.SUPABASE_URL
const supabasePublishableKey =
  viteEnv.VITE_SUPABASE_PUBLISHABLE_KEY ||
  nodeEnv.SUPABASE_SERVICE_ROLE_KEY ||
  nodeEnv.SUPABASE_ANON_KEY

if (!supabaseUrl || !supabasePublishableKey) {
  throw new Error('Faltan variables de Supabase para iniciar el cliente.')
}

export const supabase = createClient(supabaseUrl, supabasePublishableKey)
