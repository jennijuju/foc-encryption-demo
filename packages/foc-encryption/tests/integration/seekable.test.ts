import { describe, expect, it, vi } from 'vitest'
import { CoseAlgorithm } from '../../src/cose/headers.js'
import { decrypt, decryptRange, encrypt, parseEnvelope } from '../../src/envelope.js'
import { SchemeNotSeekableError } from '../../src/errors.js'
import type { BlobFetcher } from '../../src/types.js'

const CHUNK_SIZE = 4096

function pattern(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => index & 0xff)
}

function makeBlobFetcher(blob: Uint8Array): BlobFetcher {
  return {
    getSize: async () => blob.length,
    fetchRange: async (offset, length) => blob.slice(offset, offset + length),
  }
}

describe('seekable encryption', () => {
  it('round-trips a multi-chunk object', async () => {
    const cek = crypto.getRandomValues(new Uint8Array(32))
    const plaintext = pattern(CHUNK_SIZE * 3 + 137)
    const blob = await encrypt(plaintext, cek, {
      algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
      chunkSize: CHUNK_SIZE,
    })

    await expect(decrypt(blob, cek)).resolves.toEqual(plaintext)
  })

  it.each([
    ['first chunk', 0, 128],
    ['middle chunk', CHUNK_SIZE * 2 + 17, 500],
    ['chunk boundary', CHUNK_SIZE - 50, 200],
    ['last chunk', CHUNK_SIZE * 4 + 221, 100],
    ['whole object', 0, CHUNK_SIZE * 4 + 321],
  ])('decrypts a %s range', async (_name, offset, length) => {
    const cek = crypto.getRandomValues(new Uint8Array(32))
    const plaintext = pattern(CHUNK_SIZE * 4 + 321)
    const blob = await encrypt(plaintext, cek, {
      algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
      chunkSize: CHUNK_SIZE,
    })
    const metadata = parseEnvelope(blob)

    const result = await decryptRange(makeBlobFetcher(blob), metadata, cek, { offset, length })

    expect(result).toEqual(plaintext.slice(offset, offset + length))
  })

  it('rejects ranges that cross or start after plaintext EOF', async () => {
    const cek = crypto.getRandomValues(new Uint8Array(32))
    const plaintext = pattern(CHUNK_SIZE + 10)
    const blob = await encrypt(plaintext, cek, {
      algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
      chunkSize: CHUNK_SIZE,
    })
    const metadata = parseEnvelope(blob)
    const fetcher = makeBlobFetcher(blob)

    await expect(decryptRange(fetcher, metadata, cek, { offset: plaintext.length - 2, length: 3 })).rejects.toThrow(
      /range/i
    )
    await expect(decryptRange(fetcher, metadata, cek, { offset: plaintext.length, length: 1 })).rejects.toThrow(
      /range/i
    )
  })

  it('rejects range decryption for the non-seekable scheme', async () => {
    const cek = crypto.getRandomValues(new Uint8Array(32))
    const blob = await encrypt(new TextEncoder().encode('not seekable'), cek, {
      algorithm: CoseAlgorithm.AES_256_GCM,
    })

    await expect(
      decryptRange(makeBlobFetcher(blob), parseEnvelope(blob), cek, { offset: 0, length: 5 })
    ).rejects.toThrow(SchemeNotSeekableError)
  })

  it('parses remote metadata from the BlobFetcher interface', async () => {
    const cek = crypto.getRandomValues(new Uint8Array(32))
    const plaintext = pattern(CHUNK_SIZE * 2)
    const blob = await encrypt(plaintext, cek, {
      algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
      chunkSize: CHUNK_SIZE,
    })
    const fetcher = makeBlobFetcher(blob)

    const metadata = await parseEnvelope(fetcher)

    expect(metadata.chunkCount).toBe(2)
    expect(metadata.chunkSize).toBe(CHUNK_SIZE)
    expect(metadata.profileVersion).toBe(1)
  })

  it('does not fetch the envelope again for pre-parsed range reads', async () => {
    const cek = crypto.getRandomValues(new Uint8Array(32))
    const plaintext = pattern(CHUNK_SIZE * 2)
    const blob = await encrypt(plaintext, cek, {
      algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
      chunkSize: CHUNK_SIZE,
    })
    const metadata = parseEnvelope(blob)
    const getSize = vi.fn(async () => blob.length)
    const fetcher: BlobFetcher = {
      getSize,
      fetchRange: async (offset, length) => blob.slice(offset, offset + length),
    }

    await decryptRange(fetcher, metadata, cek, { offset: CHUNK_SIZE, length: 64 })

    expect(getSize).not.toHaveBeenCalled()
  })
})
