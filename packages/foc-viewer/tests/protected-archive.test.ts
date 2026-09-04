import { Uint8ArrayReader, Uint8ArrayWriter, ZipWriter } from '@zip.js/zip.js'
import { AuthenticationError, CoseAlgorithm, deriveKey, encrypt, parseEnvelope } from 'foc-encryption'
import type { AppMetadata } from 'foc-encryption'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { openProtectedArchive } from '../src/protected-archive.js'

const CID = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3udhvy6o2x4i5woy4vgr3vnz4'
const PASSWORD = 'alpha-bravo-charlie-delta-echo-foxtrot'
const SALT = new Uint8Array(16).fill(7)
const CHUNK_SIZE = 4096

interface ZipInput {
  path: string
  data?: Uint8Array
  directory?: boolean
}

interface RecordedRequest {
  url: string
  start: number
  end: number
}

interface FixtureOptions {
  chunkSize?: number
  mutateMetadata?: (metadata: AppMetadata) => void
}

interface ProtectedFixture {
  encrypted: Uint8Array
  fetchFn: typeof fetch
  requests: RecordedRequest[]
  activity: { active: number; maximum: number }
}

let testCek: Uint8Array = new Uint8Array()

beforeAll(async () => {
  testCek = (await deriveKey({ kind: 'password', password: PASSWORD }, SALT)).cek
})

afterAll(() => {
  testCek.fill(0)
})

async function createZip(entries: readonly ZipInput[]): Promise<Uint8Array> {
  const writer = new ZipWriter(new Uint8ArrayWriter(), {
    compressionMethod: 0,
    level: 0,
    useWebWorkers: false,
  })
  for (const entry of entries) {
    await writer.add(entry.path, entry.directory ? undefined : new Uint8ArrayReader(entry.data ?? new Uint8Array()), {
      compressionMethod: 0,
      directory: entry.directory,
      level: 0,
    })
  }
  return writer.close()
}

async function createFixture(zip: Uint8Array, options: FixtureOptions = {}): Promise<ProtectedFixture> {
  const metadata: AppMetadata = {
    pbkdf2_salt: SALT,
    pbkdf2_iterations: 600_000,
    pbkdf2_hash: 'SHA-256',
    content_type: 'application/zip',
    plaintext_size: zip.length,
  }
  options.mutateMetadata?.(metadata)

  const encrypted = await encrypt(zip, testCek, {
    algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
    chunkSize: options.chunkSize ?? CHUNK_SIZE,
    appMetadata: metadata,
  })
  const requests: RecordedRequest[] = []
  const activity = { active: 0, maximum: 0 }
  const fetchFn: typeof fetch = async (input, init) => {
    const range = new Headers(init?.headers).get('Range')
    const match = range ? /^bytes=(\d+)-(\d+)$/.exec(range) : null
    if (!match) throw new Error('Expected one bounded Range request')

    const start = Number(match[1])
    const end = Number(match[2])
    requests.push({ url: String(input), start, end })
    activity.active++
    activity.maximum = Math.max(activity.maximum, activity.active)
    await Promise.resolve()
    const responseEnd = Math.min(end, encrypted.length - 1)
    const body = Uint8Array.from(encrypted.subarray(start, responseEnd + 1)).buffer
    activity.active--
    return new Response(body, {
      status: 206,
      headers: { 'Content-Range': `bytes ${start}-${responseEnd}/${encrypted.length}` },
    })
  }

  return { encrypted, fetchFn, requests, activity }
}

async function collect(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let length = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(value)
    length += value.length
  }

  const result = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.length
  }
  return result
}

function duplicateCentralDirectoryName(zip: Uint8Array, from: string, to: string): Uint8Array {
  const fromBytes = new TextEncoder().encode(from)
  const toBytes = new TextEncoder().encode(to)
  if (fromBytes.length !== toBytes.length) throw new Error('Replacement names must have equal byte lengths')

  const result = new Uint8Array(zip)
  const view = new DataView(result.buffer)
  for (let offset = 0; offset <= result.length - 46; offset++) {
    if (view.getUint32(offset, true) !== 0x02014b50) continue
    const filenameLength = view.getUint16(offset + 28, true)
    const filenameOffset = offset + 46
    const filename = result.subarray(filenameOffset, filenameOffset + filenameLength)
    if (filename.length === fromBytes.length && filename.every((byte, index) => byte === fromBytes[index])) {
      result.set(toBytes, filenameOffset)
      return result
    }
  }
  throw new Error(`Central directory entry not found: ${from}`)
}

function indexOfBytes(data: Uint8Array, target: Uint8Array): number {
  for (let offset = 0; offset <= data.length - target.length; offset++) {
    if (target.every((byte, index) => data[offset + index] === byte)) return offset
  }
  return -1
}

describe('openProtectedArchive', () => {
  it('validates protected ZIP metadata before deriving or listing', async () => {
    const zip = await createZip([{ path: 'file.txt', data: new TextEncoder().encode('safe') }])
    const invalidCases: Array<{ name: string; mutate: (metadata: AppMetadata) => void }> = [
      { name: 'salt', mutate: (metadata) => (metadata.pbkdf2_salt = new Uint8Array(8)) },
      { name: 'iterations', mutate: (metadata) => (metadata.pbkdf2_iterations = 1) },
      { name: 'hash', mutate: (metadata) => (metadata.pbkdf2_hash = 'SHA-1') },
      { name: 'content type', mutate: (metadata) => (metadata.content_type = 'text/plain') },
    ]

    for (const invalidCase of invalidCases) {
      const fixture = await createFixture(zip, { mutateMetadata: invalidCase.mutate })
      await expect(openProtectedArchive(CID, PASSWORD, fixture.fetchFn), invalidCase.name).rejects.toThrow(/metadata/)
      expect(fixture.requests.length).toBeGreaterThanOrEqual(2)
    }
  })

  it('lists a folder from authenticated ranges and serializes every request', async () => {
    const zip = await createZip([
      { path: 'folder/', directory: true },
      { path: 'folder/note.txt', data: new TextEncoder().encode('hello') },
      { path: 'photo.png', data: new Uint8Array([0x89, 0x50, 0x4e, 0x47]) },
    ])
    const fixture = await createFixture(zip)

    const archive = await openProtectedArchive(CID, PASSWORD, fixture.fetchFn)

    expect(archive.list()).toEqual([
      { path: 'folder/', directory: true, size: 0, contentType: 'inode/directory' },
      { path: 'folder/note.txt', directory: false, size: 5, contentType: 'text/plain' },
      { path: 'photo.png', directory: false, size: 4, contentType: 'image/png' },
    ])
    expect(fixture.requests[0]).toEqual({
      url: `https://${CID}.ipfs.dweb.link/`,
      start: 0,
      end: 0,
    })
    expect(fixture.requests[1]).toEqual({
      url: `https://${CID}.ipfs.dweb.link/`,
      start: 0,
      end: fixture.encrypted.length - 1,
    })
    expect(fixture.requests.length).toBeGreaterThan(1)
    expect(fixture.activity.maximum).toBe(1)
  })

  it('reports wrong passwords and tampering as authentication failures', async () => {
    const zip = await createZip([{ path: 'secret.txt', data: new TextEncoder().encode('private') }])
    const wrongPasswordFixture = await createFixture(zip)
    await expect(openProtectedArchive(CID, 'wrong-password', wrongPasswordFixture.fetchFn)).rejects.toBeInstanceOf(
      AuthenticationError
    )

    const tamperedFixture = await createFixture(zip)
    tamperedFixture.encrypted[tamperedFixture.encrypted.length - 1] ^= 1
    await expect(openProtectedArchive(CID, PASSWORD, tamperedFixture.fetchFn)).rejects.toBeInstanceOf(
      AuthenticationError
    )
  })

  it('rejects unsafe and duplicate ZIP names', async () => {
    const unsafeZip = await createZip([{ path: '../escape.txt', data: new Uint8Array([1]) }])
    const unsafeFixture = await createFixture(unsafeZip)
    await expect(openProtectedArchive(CID, PASSWORD, unsafeFixture.fetchFn)).rejects.toThrow(/unsafe path/)

    const duplicateZip = duplicateCentralDirectoryName(
      await createZip([
        { path: 'first.txt', data: new Uint8Array([1]) },
        { path: 'other.txt', data: new Uint8Array([2]) },
      ]),
      'other.txt',
      'first.txt'
    )
    const duplicateFixture = await createFixture(duplicateZip)
    await expect(openProtectedArchive(CID, PASSWORD, duplicateFixture.fetchFn)).rejects.toThrow(/duplicate path/)
  })

  it('streams only the selected entry body', async () => {
    const first = new Uint8Array(8192).fill(0x31)
    const second = new Uint8Array(8192).fill(0xe2)
    const zip = await createZip([
      { path: 'first.bin', data: first },
      { path: 'second.bin', data: second },
    ])
    const fixture = await createFixture(zip)
    const archive = await openProtectedArchive(CID, PASSWORD, fixture.fetchFn)
    fixture.requests.length = 0

    expect(await collect(await archive.open('first.bin'))).toEqual(first)
    expect(fixture.requests.length).toBeGreaterThan(0)

    const metadata = parseEnvelope(fixture.encrypted)
    const secondOffset = indexOfBytes(zip, second)
    expect(secondOffset).toBeGreaterThanOrEqual(0)
    const secondFirstChunk = Math.floor(secondOffset / CHUNK_SIZE)
    const ciphertextChunkSize = CHUNK_SIZE + 16

    for (const request of fixture.requests) {
      const lastRequestedChunk = Math.floor((request.end - metadata.envelopeSize) / ciphertextChunkSize)
      expect(lastRequestedChunk).toBeLessThanOrEqual(secondFirstChunk)
    }
  })

  it('closes the archive and rejects later reads', async () => {
    const zip = await createZip([{ path: 'note.txt', data: new TextEncoder().encode('hello') }])
    const fixture = await createFixture(zip, { chunkSize: 4096 })
    const archive = await openProtectedArchive(CID, PASSWORD, fixture.fetchFn)

    await archive.close()
    await archive.close()

    await expect(archive.open('note.txt')).rejects.toThrow(/closed/)
  })
})
