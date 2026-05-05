import { webcrypto } from 'node:crypto'
import { TextDecoder, TextEncoder } from 'node:util'

Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
  configurable: true,
})

Object.defineProperty(globalThis, 'window', {
  value: {
    crypto: webcrypto,
  },
  configurable: true,
})

Object.defineProperty(globalThis, 'TextEncoder', {
  value: TextEncoder,
  configurable: true,
})

Object.defineProperty(globalThis, 'TextDecoder', {
  value: TextDecoder,
  configurable: true,
})

Object.defineProperty(globalThis, 'btoa', {
  value: (value) => Buffer.from(value, 'binary').toString('base64'),
  configurable: true,
})

Object.defineProperty(globalThis, 'atob', {
  value: (value) => Buffer.from(value, 'base64').toString('binary'),
  configurable: true,
})