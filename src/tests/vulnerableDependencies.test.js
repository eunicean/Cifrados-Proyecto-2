import fs from 'node:fs'
import { describe, expect, test } from 'vitest'

// Hallazgos #3, #4, #8, #9 y #10: dependencias vulnerables reportadas por npm audit en la Fase 1.
// Revisa todas las copias de cada paquete en package-lock.json (lo que realmente se instala).
const lock = JSON.parse(fs.readFileSync(process.env.LOCKFILE_PATH || 'package-lock.json', 'utf8'))

function installedVersions(name) {
  return Object.entries(lock.packages)
    .filter(([path]) => path === `node_modules/${name}` || path.endsWith(`/node_modules/${name}`))
    .map(([, info]) => info.version)
}

function isAtLeast(version, minimum) {
  const current = version.split('-')[0].split('.').map(Number)
  const target = minimum.split('.').map(Number)

  for (let i = 0; i < 3; i += 1) {
    if (current[i] !== target[i]) return current[i] > target[i]
  }

  return true
}

const patched = [
  ['#3', 'proxy-addr', '2.0.8', 'GHSA-jqcg-44mw-7w3h'],
  ['#4', 'react-router', '7.18.2', 'GHSA-wrjc-x8rr-h8h6'],
  ['#8', 'ws', '8.20.2', 'GHSA-96hv-2xvq-fx4p'],
  ['#9', 'qs', '6.15.4', 'GHSA-4mjr-xmp4-gh2g'],
  ['#10', 'body-parser', '2.2.3', 'GHSA-v422-hmwv-36x6'],
]

describe('Dependencias sin versiones vulnerables', () => {
  test.each(patched)('%s: %s >= %s (%s)', (_, name, minimum) => {
    const vulnerable = installedVersions(name).filter((version) => !isAtLeast(version, minimum))

    expect(vulnerable).toEqual([])
  })
})
