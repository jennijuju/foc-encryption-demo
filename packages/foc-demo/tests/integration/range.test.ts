import type { Synapse } from '@filoz/synapse-sdk'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { CoseAlgorithm, createHttpBlobFetcher, encrypt } from 'foc-encryption'
import type { BlobFetcher } from 'foc-encryption'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('foc-encryption', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>()
  return { ...actual, createHttpBlobFetcher: vi.fn() }
})

vi.mock('../../src/synapse.js', () => ({
  createSynapseClient: vi.fn(),
}))

import { rangeDecrypt } from '../../src/commands/range.js'
import { createSynapseClient } from '../../src/synapse.js'

function makeBlobFetcher(blob: Uint8Array): BlobFetcher {
  return {
    fetchEnvelope: vi.fn(async () => blob.slice(0, 4096)),
    fetchRange: vi.fn(async (offset: number, length: number) => blob.slice(offset, offset + length)),
  }
}

describe('range command', () => {
  let tempDir: string

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'foc-range-test-'))
    vi.clearAllMocks()
  })

  afterEach(async () => {
    await rm(tempDir, { recursive: true })
  })

  it('decrypts a byte range from a chunked-encrypted blob', async () => {
    const hexKey = 'aa'.repeat(32)
    const keyBytes = new Uint8Array(Buffer.from(hexKey, 'hex'))

    // Create large plaintext (> 256 KiB) to force chunked encryption
    const plaintext = new Uint8Array(300 * 1024)
    for (let i = 0; i < plaintext.length; i++) {
      plaintext[i] = i % 256
    }

    const blob = await encrypt(plaintext, keyBytes, { algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM })

    const fetcher = makeBlobFetcher(blob)
    vi.mocked(createHttpBlobFetcher).mockReturnValue(fetcher)

    const offset = 1024
    const length = 512
    const outputPath = join(tempDir, 'range.bin')

    await rangeDecrypt({
      locator: 'https://example.com/blob',
      key: hexKey,
      offset,
      length,
      output: outputPath,
    })

    const result = await readFile(outputPath)
    expect(new Uint8Array(result)).toEqual(plaintext.slice(offset, offset + length))
    expect(createSynapseClient).not.toHaveBeenCalled()
  })

  it('throws actionable error for non-seekable (AES-256-GCM) blob', async () => {
    const hexKey = 'bb'.repeat(32)
    const keyBytes = new Uint8Array(Buffer.from(hexKey, 'hex'))

    const plaintext = new TextEncoder().encode('small non-seekable plaintext')
    const blob = await encrypt(plaintext, keyBytes, { algorithm: CoseAlgorithm.AES_256_GCM })

    const fetcher = makeBlobFetcher(blob)
    vi.mocked(createHttpBlobFetcher).mockReturnValue(fetcher)

    await expect(
      rangeDecrypt({
        locator: 'https://example.com/blob',
        key: hexKey,
        offset: 0,
        length: 10,
        output: join(tempDir, 'out.bin'),
      })
    ).rejects.toThrow(/non-seekable|download/)
  })

  it('PieceCID locator: resolves URL via synapse createContext then performs range decryption', async () => {
    const hexKey = 'cc'.repeat(32)
    const keyBytes = new Uint8Array(Buffer.from(hexKey, 'hex'))

    const plaintext = new Uint8Array(300 * 1024).fill(0x42)
    const blob = await encrypt(plaintext, keyBytes, { algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM })

    const fakeUrl = 'https://retrieval.example.com/piece/baga6ea4seaqtest'
    const mockGetPieceUrl = vi.fn().mockReturnValue(fakeUrl)

    const synapse = {
      storage: {
        createContext: vi.fn().mockResolvedValue({
          getPieceUrl: mockGetPieceUrl,
        }),
      },
    }
    // The SDK client surface is wider; this test exercises only storage.createContext.
    vi.mocked(createSynapseClient).mockReturnValue(synapse as unknown as Synapse)

    const fetcher = makeBlobFetcher(blob)
    vi.mocked(createHttpBlobFetcher).mockReturnValue(fetcher)

    const outputPath = join(tempDir, 'cid-range.bin')
    await rangeDecrypt({
      locator: 'baga6ea4seaqtest',
      key: hexKey,
      offset: 0,
      length: 100,
      output: outputPath,
      privateKey: '0x' + 'ab'.repeat(32),
    })

    const result = await readFile(outputPath)
    expect(new Uint8Array(result)).toEqual(plaintext.slice(0, 100))
    expect(createSynapseClient).toHaveBeenCalledWith(expect.objectContaining({ privateKey: '0x' + 'ab'.repeat(32) }))
    expect(createHttpBlobFetcher).toHaveBeenCalledWith(fakeUrl)
  })

  it('throws error when PieceCID locator used without private key', async () => {
    const origEnv = process.env.PRIVATE_KEY
    delete process.env.PRIVATE_KEY

    try {
      await expect(
        rangeDecrypt({
          locator: 'baga6ea4seaqtest',
          key: 'dd'.repeat(32),
          offset: 0,
          length: 100,
        })
      ).rejects.toThrow('PRIVATE_KEY')
    } finally {
      if (origEnv !== undefined) {
        process.env.PRIVATE_KEY = origEnv
      }
    }
  })
})
