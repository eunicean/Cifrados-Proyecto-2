// Vitest en Windows escribe rutas con "\" en lcov.info; SonarQube (y su scanner en Docker) espera "/"
import fs from 'node:fs'

const lcovPath = 'coverage/lcov.info'
const lcov = fs.readFileSync(lcovPath, 'utf8')

fs.writeFileSync(
  lcovPath,
  lcov.replace(/^SF:([^\r\n]*)/gm, (_, file) => `SF:${file.replaceAll('\\', '/')}`),
)
