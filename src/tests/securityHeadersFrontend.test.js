import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { createServer } from 'vite'
import viteConfig from '../../vite.config.js'

// Hallazgos #6 (clickjacking, CWE-1021), #7 (CSP, CWE-693) y #11 (nosniff) que ZAP encontro en localhost:5173
describe('Encabezados de seguridad del frontend (servidor de Vite)', () => {
  let server
  let baseUrl

  beforeAll(async () => {
    server = await createServer({
      configFile: 'vite.config.js',
      logLevel: 'silent',
      server: { port: 0, host: '127.0.0.1', hmr: false },
    })
    await server.listen()
    const { port } = server.httpServer.address()
    baseUrl = `http://127.0.0.1:${port}`
  }, 30000)

  afterAll(async () => {
    await server?.close()
  })

  test('#6: la pagina no se puede cargar dentro de un iframe', async () => {
    const response = await fetch(`${baseUrl}/`)

    expect(response.headers.get('x-frame-options')).toBe('DENY')
    expect(response.headers.get('content-security-policy')).toContain("frame-ancestors 'none'")
  })

  test('#11: desactiva el MIME sniffing', async () => {
    const response = await fetch(`${baseUrl}/`)

    expect(response.headers.get('x-content-type-options')).toBe('nosniff')
  })
})

describe('#7: el build de produccion envia la CSP como encabezado HTTP', () => {
  const config = viteConfig({ mode: 'production', command: 'serve' })
  const csp = config.preview.headers['Content-Security-Policy']

  test('solo permite scripts del mismo origen', () => {
    const scriptSrc = csp.split('; ').find((directive) => directive.startsWith('script-src'))

    expect(scriptSrc).toBe("script-src 'self'")
    expect(csp).toContain("object-src 'none'")
  })

  test('incluye frame-ancestors, que no funciona dentro de <meta>', () => {
    expect(csp).toContain("frame-ancestors 'none'")
    expect(config.preview.headers['X-Frame-Options']).toBe('DENY')
  })

  test('permite conectarse a la API que usa el frontend', () => {
    expect(csp).toContain('https://cifrados-proyecto-2-1.onrender.com')
  })
})
