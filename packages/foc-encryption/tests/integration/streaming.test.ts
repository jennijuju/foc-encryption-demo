import { describe, expect, it } from 'vitest'
import { CoseAlgorithm, MAX_CHUNK_SIZE, decrypt, decryptRange, encryptStream, parseEnvelope } from '../../src/index.js'
import type { BlobFetcher, Recipient, StreamEncryptOptions } from '../../src/index.js'

const KiB = 1024
const MiB = 1024 * KiB
const CHUNK_SIZE = 256 * KiB
const MEMORY_LIMIT = 64 * MiB

function concatenate(chunks: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(chunks.reduce((length, chunk) => length + chunk.length, 0))
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.length
  }
  return result
}

async function collect(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  try {
    while (true) {
      const next = await reader.read()
      if (next.done) break
      chunks.push(next.value)
    }
  } finally {
    reader.releaseLock()
  }
  return concatenate(chunks)
}

function streamFromChunks(chunks: readonly Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk)
      controller.close()
    },
  })
}

function makeBlobFetcher(blob: Uint8Array): BlobFetcher {
  const metadata = parseEnvelope(blob)
  return {
    fetchEnvelope: async () => blob.slice(0, metadata.envelopeSize),
    fetchRange: async (offset, length) => blob.slice(offset, offset + length),
  }
}

async function expectLengthError(
  source: ReadableStream<Uint8Array>,
  plaintextLength: number,
  message: RegExp
): Promise<void> {
  const cek = crypto.getRandomValues(new Uint8Array(32))
  const encrypted = await encryptStream(source, cek, {
    algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
    plaintextLength,
    chunkSize: 4,
  })
  const reader = encrypted.getReader()
  const envelope = await reader.read()
  expect(envelope.done).toBe(false)
  await expect(reader.read()).rejects.toThrow(message)
  reader.releaseLock()
}

async function expectBoundedEncryption(plaintextLength: number): Promise<void> {
  let remaining = plaintextLength
  const source = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (remaining === 0) {
        controller.close()
        return
      }
      const length = Math.min(CHUNK_SIZE, remaining)
      controller.enqueue(new Uint8Array(length).fill(0x5a))
      remaining -= length
    },
  })
  const cek = crypto.getRandomValues(new Uint8Array(32))
  const options: StreamEncryptOptions = {
    algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
    plaintextLength,
    chunkSize: CHUNK_SIZE,
  }
  const baseline = process.memoryUsage().arrayBuffers
  const encrypted = await encryptStream(source, cek, options)
  let peak = Math.max(baseline, process.memoryUsage().arrayBuffers)
  let outputChunks = 0
  let outputBytes = 0
  const reader = encrypted.getReader()
  try {
    while (true) {
      const next = await reader.read()
      peak = Math.max(peak, process.memoryUsage().arrayBuffers)
      if (next.done) break
      outputChunks += 1
      outputBytes += next.value.length
    }
  } finally {
    reader.releaseLock()
  }

  expect(outputChunks).toBe(1 + Math.max(1, Math.ceil(plaintextLength / CHUNK_SIZE)))
  expect(outputBytes).toBeGreaterThan(plaintextLength)
  expect(peak - baseline).toBeLessThan(MEMORY_LIMIT)
}

describe('encryptStream', () => {
  it('re-chunks uneven input and remains compatible with whole-file and cross-chunk decryption', async () => {
    const chunks = [new Uint8Array([1, 2, 3]), new Uint8Array(300_000).fill(7), new Uint8Array([8, 9])]
    const expected = concatenate(chunks)
    const cek = crypto.getRandomValues(new Uint8Array(32))

    const stream = await encryptStream(streamFromChunks(chunks), cek, {
      algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
      plaintextLength: expected.length,
      chunkSize: CHUNK_SIZE,
    })
    const blob = await collect(stream)

    expect(await decrypt(blob, cek)).toEqual(expected)
    expect(
      await decryptRange(makeBlobFetcher(blob), parseEnvelope(blob), cek, { offset: 262_140, length: 12 })
    ).toEqual(expected.slice(262_140, 262_152))
  })
  it('batches unaligned range decryption across maximum-sized chunks', async () => {
    const plaintext = new Uint8Array(MAX_CHUNK_SIZE + 2).fill(0x4a)
    const cek = crypto.getRandomValues(new Uint8Array(32))
    const blob = await collect(
      await encryptStream(streamFromChunks([plaintext]), cek, {
        algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
        plaintextLength: plaintext.length,
        chunkSize: MAX_CHUNK_SIZE,
      })
    )
    const metadata = parseEnvelope(blob)
    const requests: number[] = []
    const fetcher: BlobFetcher = {
      fetchEnvelope: async () => blob.slice(0, metadata.envelopeSize),
      fetchRange: async (offset, length) => {
        requests.push(length)
        return blob.slice(offset, offset + length)
      },
    }

    const result = await decryptRange(fetcher, metadata, cek, {
      offset: MAX_CHUNK_SIZE - 1,
      length: 3,
    })

    expect(result).toEqual(plaintext.slice(MAX_CHUNK_SIZE - 1, MAX_CHUNK_SIZE + 2))
    expect(requests).toHaveLength(2)
    expect(requests.every((length) => length <= MAX_CHUNK_SIZE + 16)).toBe(true)
  })

  it('uses the COSE_Encrypt authentication context when recipients are present', async () => {
    const plaintext = new Uint8Array([1, 2, 3, 4, 5])
    const cek = crypto.getRandomValues(new Uint8Array(32))
    const recipients: Recipient[] = [{ algorithm: -3, wrappedKey: new Uint8Array([6, 7, 8]) }]
    const blob = await collect(
      await encryptStream(
        streamFromChunks([plaintext]),
        cek,
        {
          algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
          plaintextLength: plaintext.length,
          chunkSize: 4,
        },
        recipients
      )
    )

    expect(parseEnvelope(blob).tag).toBe(96)
    expect(await decrypt(blob, cek)).toEqual(plaintext)
  })

  it('rejects early EOF before emitting a final encrypted chunk', async () => {
    await expectLengthError(streamFromChunks([new Uint8Array([1, 2, 3])]), 4, /ended early/)
  })

  it('rejects excess bytes before emitting a final encrypted chunk and cancels the source', async () => {
    let cancellationReason: unknown
    const source = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3, 4, 5]))
      },
      cancel(reason: unknown) {
        cancellationReason = reason
      },
    })

    await expectLengthError(source, 4, /exceeds declared length/)
    expect(cancellationReason).toBeInstanceOf(Error)
  })

  it('encrypts empty input as one authenticated final chunk', async () => {
    const cek = crypto.getRandomValues(new Uint8Array(32))
    const blob = await collect(
      await encryptStream(streamFromChunks([]), cek, {
        algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
        plaintextLength: 0,
        chunkSize: CHUNK_SIZE,
      })
    )

    expect(parseEnvelope(blob).chunkCount).toBe(1)
    expect(await decrypt(blob, cek)).toEqual(new Uint8Array(0))
  })

  it.each([0, -1, 1.5, Number.POSITIVE_INFINITY, 16 * MiB + 1])('rejects invalid chunk size %s', async (chunkSize) => {
    const cek = crypto.getRandomValues(new Uint8Array(32))
    await expect(
      encryptStream(streamFromChunks([]), cek, {
        algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
        plaintextLength: 0,
        chunkSize,
      })
    ).rejects.toThrow(/Chunk size/)
  })

  it.each([-1, 1.5, Number.POSITIVE_INFINITY])('rejects invalid plaintext length %s', async (plaintextLength) => {
    const cek = crypto.getRandomValues(new Uint8Array(32))
    await expect(
      encryptStream(streamFromChunks([]), cek, {
        algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
        plaintextLength,
        chunkSize: CHUNK_SIZE,
      })
    ).rejects.toThrow(/Plaintext length must be a non-negative safe integer/)
  })

  it('propagates output cancellation to the plaintext source', async () => {
    let cancellationReason: unknown
    const source = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(CHUNK_SIZE))
      },
      cancel(reason: unknown) {
        cancellationReason = reason
      },
    })
    const cek = crypto.getRandomValues(new Uint8Array(32))
    const encrypted = await encryptStream(source, cek, {
      algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
      plaintextLength: 2 * CHUNK_SIZE,
      chunkSize: CHUNK_SIZE,
    })
    const reader = encrypted.getReader()

    const first = await reader.read()
    if (first.done) throw new Error('Expected the COSE envelope before ciphertext')
    expect(parseEnvelope(first.value).envelopeSize).toBe(first.value.length)
    await reader.cancel('consumer stopped')
    expect(cancellationReason).toBe('consumer stopped')
  })

  it('keeps 64 MiB streaming encryption below 64 MiB of ArrayBuffer growth', async () => {
    await expectBoundedEncryption(64 * MiB)
  }, 120_000)

  it.runIf(process.env.FEE_LARGE_STREAM_TEST === '1')(
    'keeps 1000 MiB streaming encryption below 64 MiB of ArrayBuffer growth',
    async () => {
      await expectBoundedEncryption(1000 * MiB)
    },
    600_000
  )
})
