#!/usr/bin/env node
// Hito 3 · Carga en Kibana el dashboard y las reglas de deteccion del Blue Team.
//
// Uso (desde la raiz del repo, con el perfil `siem` levantado):
//   ELASTIC_PASSWORD=... node scripts/blue-team/kibana-setup.mjs
//   ELASTIC_PASSWORD=... node scripts/blue-team/kibana-setup.mjs --solo-reglas
//   ELASTIC_PASSWORD=... node scripts/blue-team/kibana-setup.mjs --solo-dashboard
//
// Variables: KIBANA_URL (por defecto http://localhost:5601), ELASTIC_USER (elastic),
// ELASTIC_PASSWORD (obligatoria; la misma del .env). Requiere Node 18 o superior.
//
// Es idempotente: el dashboard se importa con overwrite y las reglas que ya existen
// se actualizan (PUT por rule_id).

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const kibanaDir = path.resolve(here, '../../docs/hito-3/kibana')
const kibanaUrl = (process.env.KIBANA_URL || 'http://localhost:5601').replace(/\/$/, '')
const user = process.env.ELASTIC_USER || 'elastic'
const password = process.env.ELASTIC_PASSWORD

if (!password) {
  console.error('Falta ELASTIC_PASSWORD (la del .env del entorno Blue Team).')
  process.exit(1)
}

const args = new Set(process.argv.slice(2))
const auth = `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`
const baseHeaders = {
  Authorization: auth,
  'kbn-xsrf': 'cifrados',
  'elastic-api-version': '2023-10-31',
}

async function kibana(method, route, { json, body, headers = {} } = {}) {
  const response = await fetch(`${kibanaUrl}${route}`, {
    method,
    headers: {
      ...baseHeaders,
      ...(json ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: json ? JSON.stringify(json) : body,
  })
  const text = await response.text()
  let data = null
  try {
    data = JSON.parse(text)
  } catch {
    data = text
  }
  return { status: response.status, data }
}

async function waitForKibana() {
  for (let attempt = 1; attempt <= 60; attempt += 1) {
    try {
      const { status, data } = await kibana('GET', '/api/status')
      if (status === 200 && data?.status?.overall?.level === 'available') return
    } catch {
      // Kibana todavia no acepta conexiones
    }
    process.stdout.write(attempt === 1 ? 'Esperando a Kibana' : '.')
    await new Promise((resolve) => setTimeout(resolve, 5000))
  }
  throw new Error(`Kibana no respondio en ${kibanaUrl}`)
}

async function importDashboard() {
  const file = path.join(kibanaDir, 'dashboard.ndjson')
  const form = new FormData()
  form.append('file', new Blob([fs.readFileSync(file)], { type: 'application/ndjson' }), 'dashboard.ndjson')

  const { status, data } = await kibana('POST', '/api/saved_objects/_import?overwrite=true', { body: form })

  if (status !== 200 || !data.success) {
    console.error('\n✗ Importacion del dashboard con errores:', JSON.stringify(data, null, 2))
    process.exitCode = 1
    return
  }
  console.log(`\n✓ Dashboard importado (${data.successCount} objetos): ${kibanaUrl}/app/dashboards#/view/cifrados-siem`)
}

async function loadRules() {
  const rules = JSON.parse(fs.readFileSync(path.join(kibanaDir, 'reglas-deteccion.json'), 'utf8'))

  for (const rule of rules) {
    let result = await kibana('POST', '/api/detection_engine/rules', { json: rule })
    let action = 'creada'

    if (result.status === 409) {
      result = await kibana('PUT', '/api/detection_engine/rules', { json: rule })
      action = 'actualizada'
    }

    if (result.status === 200) {
      console.log(`✓ ${rule.name} (${action})`)
    } else {
      process.exitCode = 1
      console.error(`✗ ${rule.name}: HTTP ${result.status}`, JSON.stringify(result.data))
    }
  }
  console.log(`Reglas: ${kibanaUrl}/app/security/rules (filtrar por la etiqueta "Cifrados")`)
}

await waitForKibana()
if (!args.has('--solo-reglas')) await importDashboard()
if (!args.has('--solo-dashboard')) await loadRules()
