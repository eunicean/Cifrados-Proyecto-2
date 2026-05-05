import { describe, expect, test } from 'vitest'
import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  concatArrayBuffers,
} from '../utils/crypto/base64.js'

describe('Base64 utilities', () => {
  test('convierte ArrayBuffer a Base64 y de vuelta sin perder datos', () => {
    const originalBytes = new Uint8Array([10, 20, 30, 40, 250])
    const base64 = arrayBufferToBase64(originalBytes.buffer)
    const restoredBuffer = base64ToArrayBuffer(base64)
    const restoredBytes = new Uint8Array(restoredBuffer)

    expect(Array.from(restoredBytes)).toEqual(Array.from(originalBytes))
  })

  test('concatena varios ArrayBuffer en orden correcto', () => {
    const first = new Uint8Array([1, 2]).buffer
    const second = new Uint8Array([3, 4]).buffer
    const third = new Uint8Array([5]).buffer

    const result = concatArrayBuffers(first, second, third)

    expect(Array.from(new Uint8Array(result))).toEqual([1, 2, 3, 4, 5])
  })
})