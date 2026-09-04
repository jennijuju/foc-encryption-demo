import { Tagged, decode, decodeFirst, encode } from 'cborg'
import { describe, expect, it } from 'vitest'
import { CoseAlgorithm } from '../../src/cose/headers.js'
import { encrypt, parseEnvelope } from '../../src/envelope.js'
import type { BlobFetcher } from '../../src/types.js'

describe('FEE v1 wire profile', () => {
  it('authenticates every behavior-driving envelope parameter', async () => {
    const cek = new Uint8Array(32).fill(0x11)
    const plaintext = new Uint8Array(5000).fill(0x42)
    const blob = await encrypt(plaintext, cek, {
      algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
      chunkSize: 4096,
      appMetadata: {
        content_type: 'application/zip',
        pbkdf2_iterations: 600_000,
        plaintext_size: plaintext.length,
      },
    })

    const [value] = decodeFirst(blob, { tags: Tagged.preserve(16), useMaps: true })
    expect(value).toBeInstanceOf(Tagged)
    const envelope = (value as Tagged).value as unknown[]
    const protectedHeaders = decode(envelope[0] as Uint8Array, { useMaps: true }) as Map<number, unknown>
    const unprotectedHeaders = envelope[1] as Map<number, unknown>

    expect((value as Tagged).tag).toBe(16)
    expect(envelope).toHaveLength(3)
    expect(envelope[2]).toBeNull()
    expect(protectedHeaders).toEqual(
      new Map<number, unknown>([
        [1, -65793],
        [16, 'application/vnd.filecoin-encryption+cose'],
        [-65794, 1],
        [-1, 4096],
        [
          -65792,
          new Map<string, unknown>([
            ['content_type', 'application/zip'],
            ['pbkdf2_iterations', 600_000],
            ['plaintext_size', plaintext.length],
          ]),
        ],
      ])
    )
    expect([...unprotectedHeaders.keys()]).toEqual([5])
  })

  it('derives chunk geometry from the complete encrypted object', async () => {
    const cek = new Uint8Array(32).fill(0x22)
    const plaintext = new Uint8Array(5000).fill(0x33)
    const blob = await encrypt(plaintext, cek, {
      algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
      chunkSize: 4096,
      appMetadata: { plaintext_size: plaintext.length },
    })

    const metadata = parseEnvelope(blob)

    expect(metadata.profileVersion).toBe(1)
    expect(metadata.chunkSize).toBe(4096)
    expect(metadata.chunkCount).toBe(2)
    expect(metadata.appMetadata).toEqual({ plaintext_size: plaintext.length })
  })

  it('rejects structures outside the bounded Encrypt0 v1 profile', () => {
    const validProtected = () =>
      new Map<number, unknown>([
        [1, 3],
        [16, 'application/vnd.filecoin-encryption+cose'],
        [-65794, 1],
      ])
    const validUnprotected = () => new Map<number, unknown>([[5, new Uint8Array(12)]])
    const blob = (tag: number, value: unknown[]) => {
      const envelope = encode(new Tagged(tag, value))
      const result = new Uint8Array(envelope.length + 16)
      result.set(envelope)
      return result
    }
    const cases: Array<[string, Uint8Array]> = [
      ['recipient envelope', blob(96, [encode(validProtected()), validUnprotected(), null, []])],
      [
        'wrong media type',
        blob(16, [
          encode(
            new Map([
              [1, 3],
              [16, 'application/example'],
              [-65794, 1],
            ])
          ),
          validUnprotected(),
          null,
        ]),
      ],
      [
        'unsupported version',
        blob(16, [
          encode(
            new Map([
              [1, 3],
              [16, 'application/vnd.filecoin-encryption+cose'],
              [-65794, 2],
            ])
          ),
          validUnprotected(),
          null,
        ]),
      ],
      ['embedded payload', blob(16, [encode(validProtected()), validUnprotected(), new Uint8Array()])],
      ['invalid IV length', blob(16, [encode(validProtected()), new Map([[5, new Uint8Array(11)]]), null])],
      [
        'unknown unprotected parameter',
        blob(16, [
          encode(validProtected()),
          new Map([
            [5, new Uint8Array(12)],
            [99, true],
          ]),
          null,
        ]),
      ],
      [
        'unknown protected parameter',
        blob(16, [encode(new Map([...validProtected(), [99, true]])), validUnprotected(), null]),
      ],
      [
        'non-string metadata key',
        blob(16, [encode(new Map([...validProtected(), [-65792, new Map([[1, 'value']])]])), validUnprotected(), null]),
      ],
      [
        'nested metadata value',
        blob(16, [
          encode(new Map([...validProtected(), [-65792, new Map([['nested', new Map()]])]])),
          validUnprotected(),
          null,
        ]),
      ],
    ]

    for (const [name, candidate] of cases) {
      expect(() => parseEnvelope(candidate), name).toThrow()
    }
  })

  it('rejects an encoded envelope larger than one MiB', () => {
    const protectedHeaders = encode(
      new Map<number, unknown>([
        [1, 3],
        [16, 'application/vnd.filecoin-encryption+cose'],
        [-65794, 1],
        [-65792, new Map([['oversized', 'x'.repeat(1024 * 1024)]])],
      ])
    )
    const envelope = encode(new Tagged(16, [protectedHeaders, new Map([[5, new Uint8Array(12)]]), null]))
    const blob = new Uint8Array(envelope.length + 16)
    blob.set(envelope)

    expect(() => parseEnvelope(blob)).toThrow(/(?:metadata|envelope).*large/i)
  })

  it('refuses to emit an envelope outside the profile bounds', async () => {
    await expect(
      encrypt(new Uint8Array(), new Uint8Array(32).fill(0x55), {
        algorithm: CoseAlgorithm.AES_256_GCM,
        appMetadata: { oversized: 'x'.repeat(1024 * 1024) },
      })
    ).rejects.toThrow(/metadata.*large/i)
  })

  it('refuses sub-profile chunk sizes', async () => {
    await expect(
      encrypt(new Uint8Array(), new Uint8Array(32).fill(0x66), {
        algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
        chunkSize: 2048,
      })
    ).rejects.toThrow(/chunk size/i)
  })

  it('grows a remote envelope probe and derives geometry from total size', async () => {
    const plaintext = new Uint8Array(9000).fill(0x77)
    const blob = await encrypt(plaintext, new Uint8Array(32).fill(0x77), {
      algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
      chunkSize: 4096,
      appMetadata: { note: 'n'.repeat(5000), plaintext_size: plaintext.length },
    })
    const requests: number[] = []
    const fetcher = {
      getSize: async () => blob.length,
      fetchEnvelope: async () => blob.slice(0, 4096),
      fetchRange: async (offset: number, length: number) => {
        requests.push(length)
        return blob.slice(offset, offset + length)
      },
    } as BlobFetcher

    const metadata = await parseEnvelope(fetcher)

    expect(metadata.chunkCount).toBe(3)
    expect(metadata.appMetadata?.plaintext_size).toBe(plaintext.length)
    expect(requests).toEqual([4096, 8192])
  })
})
