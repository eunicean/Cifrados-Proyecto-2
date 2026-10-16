// Cliente falso de Supabase para probar la API sin base de datos.
// Cada consulta (cadena from().select()...) consume el siguiente resultado de la cola;
// si la cola esta vacia responde con `defaultRow`.

export const SECRET_DB_DETAIL = 'relation "user" column "password" SECRETO_INTERNO'

export const defaultRow = {
  id: 'c1',
  channel_id: 'c1',
  user_id: 'u2',
  sender_id: 'u2',
  message_id: 'm1',
  created_by: 'u1',
  name: 'Grupo',
  email: 'contacto@example.com',
  key: 'PUBLIC-KEY-PEM',
  // sha256('CODIGO01'): permite probar POST /groups/:id/join
  key_hash: '21469b5de7817abb398fda8a1c122414f24e5976724e23b5e0e6552324df7500',
  group_code: 'CODIGO01',
  ciphertext_base64: 'Y2lwaGVy',
  nonce_base64: 'bm9uY2U=',
  auth_tag_base64: 'dGFn',
  plaintext_hash: 'a'.repeat(64),
  encrypted_key_base64: 'a2V5',
}

// Compartido via globalThis: vi.resetModules() crea otra instancia de este modulo para app.js
globalThis.__supabaseMockDb ??= {
  queue: [],
  calls: [],
  reset() {
    this.queue = []
    this.calls = []
  },
}

export const db = globalThis.__supabaseMockDb

export const dbFailure = () => ({ error: { message: SECRET_DB_DETAIL, code: 'XX000' } })

function createQuery(table) {
  let single = false

  const query = new Proxy(
    {},
    {
      get(_, method) {
        if (method === 'then') {
          const next = db.queue.length > 0 ? db.queue.shift() : {}
          const result = next.error
            ? { data: null, error: next.error }
            : { data: next.data ?? (single ? defaultRow : [defaultRow]), error: null }

          return (resolve, reject) => Promise.resolve(result).then(resolve, reject)
        }

        return (...args) => {
          db.calls.push({ table, method, args })
          if (method === 'single' || method === 'maybeSingle') single = true
          return query
        }
      },
    },
  )

  return query
}

export const supabaseModule = {
  createClient: () => ({
    from: (table) => createQuery(table),
  }),
}
