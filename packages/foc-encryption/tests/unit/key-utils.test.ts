import { describe, expect, it } from 'vitest'
import { aesGcmEncrypt, deriveAesGcmObjectKey } from '../../src/crypto.js'
import { InvalidKeyError } from '../../src/errors.js'
import { validateCek } from '../../src/key-utils.js'

describe('validateCek', () => {
  it('accepts a valid 32-byte key', () => {
    const key = crypto.getRandomValues(new Uint8Array(32))
    expect(() => validateCek(key)).not.toThrow()
  })

  it('rejects a key shorter than 32 bytes', () => {
    const key = new Uint8Array(16)
    expect(() => validateCek(key)).toThrow(InvalidKeyError)
  })

  it('rejects a key longer than 32 bytes', () => {
    const key = new Uint8Array(64)
    expect(() => validateCek(key)).toThrow(InvalidKeyError)
  })

  it('rejects an all-zero key', () => {
    const key = new Uint8Array(32)
    expect(() => validateCek(key)).toThrow(InvalidKeyError)
  })
})

describe('deriveAesGcmObjectKey', () => {
  it('separates objects that reuse one caller CEK', async () => {
    const cek = new Uint8Array(32).fill(1)
    const nonce = new Uint8Array(12)
    const plaintext = new Uint8Array([1, 2, 3])
    const aad = new Uint8Array([0])
    const first = await deriveAesGcmObjectKey(cek, new Uint8Array(12).fill(2))
    const sameObject = await deriveAesGcmObjectKey(cek, new Uint8Array(12).fill(2))
    const otherObject = await deriveAesGcmObjectKey(cek, new Uint8Array(12).fill(3))

    const firstCiphertext = await aesGcmEncrypt(first, nonce, plaintext, aad)
    expect(await aesGcmEncrypt(sameObject, nonce, plaintext, aad)).toEqual(firstCiphertext)
    expect(await aesGcmEncrypt(otherObject, nonce, plaintext, aad)).not.toEqual(firstCiphertext)
  })
})
