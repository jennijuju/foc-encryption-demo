import * as cborg from 'cborg'
import { describe, expect, it } from 'vitest'
import { COSE_HEADER_ALG } from '../../../src/cose/headers.js'
import { importAesGcmKey } from '../../../src/crypto.js'
import { AuthenticationError } from '../../../src/errors.js'
import { ChunkedAes256GcmStream, MAX_CHUNK_INDEX, deriveChunkNonce } from '../../../src/schemes/chunked-aes-256-gcm.js'

describe('ChunkedAes256GcmStream scheme', () => {
  it('has correct algorithm properties', () => {
    const scheme = new ChunkedAes256GcmStream()
    expect(scheme.name).toBe('Chunked-AES-256-GCM-STREAM')
    expect(scheme.algorithmId).toBe(-65793)
    expect(scheme.isSeekable).toBe(true)
  })

  it('encrypts multi-chunk data and reports correct chunk count', async () => {
    const scheme = new ChunkedAes256GcmStream({ chunkSize: 16 })
    const rawKey = crypto.getRandomValues(new Uint8Array(32))
    const key = await importAesGcmKey(rawKey)
    const plaintext = new Uint8Array(50) // 16 + 16 + 18 = 3 chunks at chunkSize=16... wait 50/16 = 4 chunks
    plaintext.fill(0x42)
    const protectedHeaders = cborg.encode(new Map([[COSE_HEADER_ALG, -65793]]))

    const result = await scheme.encrypt(key, plaintext, protectedHeaders, 'Encrypt0')

    expect(result.chunkCount).toBe(4) // ceil(50/16) = 4
    expect(result.chunkSize).toBe(16)
    expect(result.iv.length).toBe(12)
    // Each chunk is chunkSize + 16 tag, except last which is (50 - 48) + 16 = 18
    expect(result.ciphertext.length).toBe(3 * (16 + 16) + (2 + 16))
  })

  it('generates a 12-byte random base nonce', async () => {
    const scheme = new ChunkedAes256GcmStream({ chunkSize: 32 })
    const rawKey = crypto.getRandomValues(new Uint8Array(32))
    const key = await importAesGcmKey(rawKey)
    const plaintext = new Uint8Array(64)
    const protectedHeaders = cborg.encode(new Map([[COSE_HEADER_ALG, -65793]]))

    const result = await scheme.encrypt(key, plaintext, protectedHeaders, 'Encrypt0')

    expect(result.iv.length).toBe(12)
  })

  it('full decrypt round-trip', async () => {
    const scheme = new ChunkedAes256GcmStream({ chunkSize: 16 })
    const rawKey = crypto.getRandomValues(new Uint8Array(32))
    const key = await importAesGcmKey(rawKey)
    const plaintext = new Uint8Array(50)
    plaintext.fill(0x42)
    const protectedHeaders = cborg.encode(new Map([[COSE_HEADER_ALG, -65793]]))

    const result = await scheme.encrypt(key, plaintext, protectedHeaders, 'Encrypt0')
    const decrypted = await scheme.decrypt(key, result.ciphertext, result.iv, protectedHeaders, 'Encrypt0', {
      chunkSize: result.chunkSize,
      chunkCount: result.chunkCount,
    })

    expect(decrypted).toEqual(plaintext)
  })

  it('wrong key throws AuthenticationError on decrypt', async () => {
    const scheme = new ChunkedAes256GcmStream({ chunkSize: 16 })
    const rawKey1 = crypto.getRandomValues(new Uint8Array(32))
    const rawKey2 = crypto.getRandomValues(new Uint8Array(32))
    const key1 = await importAesGcmKey(rawKey1)
    const key2 = await importAesGcmKey(rawKey2)
    const plaintext = new Uint8Array(32).fill(0x42)
    const protectedHeaders = cborg.encode(new Map([[COSE_HEADER_ALG, -65793]]))

    const result = await scheme.encrypt(key1, plaintext, protectedHeaders, 'Encrypt0')
    await expect(
      scheme.decrypt(key2, result.ciphertext, result.iv, protectedHeaders, 'Encrypt0', {
        chunkSize: result.chunkSize,
        chunkCount: result.chunkCount,
      })
    ).rejects.toThrow(AuthenticationError)
  })

  it('authenticates the final-chunk marker against truncation', async () => {
    const scheme = new ChunkedAes256GcmStream({ chunkSize: 16 })
    const key = await importAesGcmKey(crypto.getRandomValues(new Uint8Array(32)))
    const protectedHeaders = cborg.encode(new Map([[COSE_HEADER_ALG, -65793]]))
    const encrypted = await scheme.encrypt(key, new Uint8Array(32), protectedHeaders, 'Encrypt0')
    const firstCiphertextChunk = encrypted.ciphertext.slice(0, 32)

    await expect(
      scheme.decrypt(key, firstCiphertextChunk, encrypted.iv, protectedHeaders, 'Encrypt0', {
        chunkSize: 16,
        chunkCount: 1,
      })
    ).rejects.toThrow(AuthenticationError)
  })
})

describe('deriveChunkNonce', () => {
  it('encodes chunk zero as an all-zero 96-bit nonce', () => {
    expect(deriveChunkNonce(0)).toEqual(new Uint8Array(12))
  })

  it('encodes the chunk index in the final four nonce bytes', () => {
    const nonce = deriveChunkNonce(0x01020304)
    expect(nonce.slice(0, 8)).toEqual(new Uint8Array(8))
    expect(nonce.slice(8)).toEqual(new Uint8Array([1, 2, 3, 4]))
  })

  it('rejects indexes outside an unsigned 32-bit integer', () => {
    expect(() => deriveChunkNonce(-1)).toThrow('unsigned 32-bit')
    expect(() => deriveChunkNonce(MAX_CHUNK_INDEX + 1)).toThrow('unsigned 32-bit')
  })
})

describe('ChunkedAes256GcmStream edge cases', () => {
  it('single-chunk file (smaller than chunk_size)', async () => {
    const scheme = new ChunkedAes256GcmStream({ chunkSize: 256 })
    const rawKey = crypto.getRandomValues(new Uint8Array(32))
    const key = await importAesGcmKey(rawKey)
    const plaintext = new Uint8Array(10).fill(0x42)
    const protectedHeaders = cborg.encode(new Map([[COSE_HEADER_ALG, -65793]]))

    const result = await scheme.encrypt(key, plaintext, protectedHeaders, 'Encrypt0')
    expect(result.chunkCount).toBe(1)

    const decrypted = await scheme.decrypt(key, result.ciphertext, result.iv, protectedHeaders, 'Encrypt0', {
      chunkSize: result.chunkSize,
      chunkCount: result.chunkCount,
    })
    expect(decrypted).toEqual(plaintext)
  })

  it('chunk_size=1 (degenerate)', async () => {
    const scheme = new ChunkedAes256GcmStream({ chunkSize: 1 })
    const rawKey = crypto.getRandomValues(new Uint8Array(32))
    const key = await importAesGcmKey(rawKey)
    const plaintext = new Uint8Array([0xaa, 0xbb, 0xcc])
    const protectedHeaders = cborg.encode(new Map([[COSE_HEADER_ALG, -65793]]))

    const result = await scheme.encrypt(key, plaintext, protectedHeaders, 'Encrypt0')
    expect(result.chunkCount).toBe(3)
    // Each chunk is 1 byte plaintext + 16 byte tag = 17 bytes
    expect(result.ciphertext.length).toBe(3 * 17)

    const decrypted = await scheme.decrypt(key, result.ciphertext, result.iv, protectedHeaders, 'Encrypt0', {
      chunkSize: result.chunkSize,
      chunkCount: result.chunkCount,
    })
    expect(decrypted).toEqual(plaintext)
  })

  it('decrypt rejects chunkCount exceeding 4-byte counter max', async () => {
    const scheme = new ChunkedAes256GcmStream({ chunkSize: 16 })
    const rawKey = crypto.getRandomValues(new Uint8Array(32))
    const key = await importAesGcmKey(rawKey)
    const protectedHeaders = cborg.encode(new Map([[COSE_HEADER_ALG, -65793]]))

    await expect(
      scheme.decrypt(key, new Uint8Array(0), new Uint8Array(7), protectedHeaders, 'Encrypt0', {
        chunkSize: 16,
        chunkCount: MAX_CHUNK_INDEX + 2,
      })
    ).rejects.toThrow(/exceeds the 4-byte counter maximum/)
  })

  it('decryptRange rejects chunkCount exceeding 4-byte counter max', async () => {
    const scheme = new ChunkedAes256GcmStream({ chunkSize: 16 })
    const rawKey = crypto.getRandomValues(new Uint8Array(32))
    const key = await importAesGcmKey(rawKey)
    const protectedHeaders = cborg.encode(new Map([[COSE_HEADER_ALG, -65793]]))

    await expect(
      scheme.decryptRange(
        key,
        new Uint8Array(0),
        new Uint8Array(7),
        protectedHeaders,
        'Encrypt0',
        0,
        1,
        16,
        MAX_CHUNK_INDEX + 2
      )
    ).rejects.toThrow(/exceeds the 4-byte counter maximum/)
  })
})
