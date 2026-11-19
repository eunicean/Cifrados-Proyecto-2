#!/usr/bin/env node
// Hito 3 · Resume que reglas del CRS dispararon en el audit log del WAF.
//
//   docker logs cifrados-waf > waf.log 2>&1
//   node scripts/blue-team/falsos-positivos.mjs waf.log [--desde "2026-11-17T16:00:00Z"] [--ua texto] [--detalle]
//
// Sirve para el analisis de falsos positivos: se navega la app de forma normal con el WAF
// en DetectionOnly (registro, login, crear grupo, unirse, enviar mensajes) y luego se
// listan las reglas que dispararon por ruta y campo. Toda regla que aparezca con trafico
// legitimo es un candidato a falso positivo y se documenta en docs/hito-3/README.md.
//
// --ua filtra por un fragmento del User-Agent (por ejemplo el del navegador usado).

import fs from 'node:fs'

const [file, ...rest] = process.argv.slice(2)
if (!file) {
  console.error('Uso: node scripts/blue-team/falsos-positivos.mjs waf.log [--desde "AAAA-MM-DD HH:MM"] [--ua texto]')
  process.exit(1)
}

function option(name) {
  const index = rest.indexOf(name)
  return index >= 0 ? rest[index + 1] : null
}

const since = option('--desde') ? new Date(option('--desde')) : null
const uaFilter = option('--ua')?.toLowerCase() || null
// --detalle: lista cada transaccion (hora, metodo, URI, codigo y todas sus reglas)
const detail = rest.includes('--detalle')
const detailRows = []

// Reglas de puntuacion/resumen del CRS: no identifican un ataque por si solas
const SUMMARY_RULES = new Set(['949110', '959100', '980130', '980140', '980170'])

// PowerShell 5 con `>` guarda el archivo en UTF-16; se detecta por el BOM
const buffer = fs.readFileSync(file)
const isUtf16 = buffer[0] === 0xff && buffer[1] === 0xfe
const content = buffer.toString(isUtf16 ? 'utf16le' : 'utf8').replace(/^\uFEFF/, '')

const hits = new Map()
let transactions = 0
let skippedBySince = 0

for (const rawLine of content.split(/\r?\n/)) {
  const line = rawLine.trim()
  if (!line.startsWith('{"transaction"')) continue

  let tx
  try {
    tx = JSON.parse(line).transaction
  } catch {
    continue
  }

  // time_stamp de ModSecurity viene en la hora del contenedor (UTC) y sin zona
  const when = new Date(`${tx.time_stamp} UTC`)
  if (since && when < since) {
    skippedBySince += 1
    continue
  }

  const ua = String(tx.request?.headers?.['user-agent'] || '')
  if (uaFilter && !ua.toLowerCase().includes(uaFilter)) continue

  transactions += 1
  const uri = String(tx.request?.uri || '').split('?')[0]
  detailRows.push(
    `| ${tx.time_stamp} | ${tx.request?.method} | \`${uri}\` | ${tx.response?.http_code} | ${
      (tx.messages || []).map((m) => m.details?.ruleId).join(', ') || '—'
    } |`,
  )

  for (const message of tx.messages || []) {
    const id = message.details?.ruleId
    if (!id || SUMMARY_RULES.has(id)) continue

    // libmodsecurity v3: "... against variable `ARGS:json.password' (Value: ...)"
    const field = String(message.details?.match || '').match(/variable `([^']+)'/)?.[1]
      || (message.details?.data || '').match(/within ([A-Z_]+:[^:\s]+)/)?.[1]
      || '?'
    const key = `${id}|${tx.request?.method} ${uri}|${field}`
    const entry = hits.get(key) || { id, route: `${tx.request?.method} ${uri}`, field, msg: message.message, count: 0, last: tx.time_stamp }
    entry.count += 1
    entry.last = tx.time_stamp
    hits.set(key, entry)
  }
}

console.log(`Archivo leido como ${isUtf16 ? 'UTF-16' : 'UTF-8'}.`)
console.log(`Transacciones analizadas: ${transactions} (anteriores a --desde: ${skippedBySince})`)
console.log('El WAF solo guarda las transacciones "relevantes" (alguna regla o respuesta 4xx/5xx).\n')
if (detail) {
  console.log('| Hora (UTC) | Metodo | URI | HTTP | Reglas |')
  console.log('|---|---|---|---|---|')
  detailRows.forEach((row) => console.log(row))
  console.log('')
}

if (hits.size === 0) {
  console.log('Ninguna regla de deteccion disparo con el filtro indicado: sin falsos positivos observados.')
  process.exit(0)
}

console.log('| Regla | Ruta | Campo | Mensaje | Veces | Ultima vez |')
console.log('|---|---|---|---|---|---|')
for (const entry of [...hits.values()].sort((a, b) => b.count - a.count)) {
  console.log(`| ${entry.id} | \`${entry.route}\` | \`${entry.field}\` | ${entry.msg} | ${entry.count} | ${entry.last} |`)
}
