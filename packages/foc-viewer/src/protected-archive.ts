import { Reader, ZipReader, getMimeType } from '@zip.js/zip.js'
import type { Entry, FileEntry } from '@zip.js/zip.js'
import { MAX_CHUNK_SIZE, createHttpBlobFetcher, decryptRange, deriveKey, parseEnvelope } from 'foc-encryption'
import type { BlobFetcher, EnvelopeMetadata } from 'foc-encryption'

const CID = /^b[a-z2-7]{20,120}$/
const CONTENT_TYPE = 'application/zip'
const PBKDF2_HASH = 'SHA-256'
const PBKDF2_ITERATIONS = 600_000
const PBKDF2_SALT_BYTES = 16
const MAX_ARCHIVE_ENTRIES = 10_000
const MAX_ZIP_READ_BYTES = 16 * 1024 * 1024

export interface ProtectedEntry {
  readonly path: string
  readonly directory: boolean
  readonly size: number
  readonly contentType: string
}

class FeeZipReader extends Reader<void> {
  readonly #fetcher: BlobFetcher
  readonly #metadata: EnvelopeMetadata
  readonly #cek: Uint8Array
  #pendingRead: Promise<void> = Promise.resolve()

  constructor(fetcher: BlobFetcher, metadata: EnvelopeMetadata, cek: Uint8Array, size: number) {
    super()
    this.#fetcher = fetcher
    this.#metadata = metadata
    this.#cek = cek
    this.size = size
  }

  readUint8Array(offset: number, length: number): Promise<Uint8Array> {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > this.size) {
      return Promise.reject(new Error('Invalid ZIP read offset'))
    }
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_ZIP_READ_BYTES) {
      return Promise.reject(new Error('Invalid ZIP read length'))
    }

    const boundedLength = Math.min(length, this.size - offset)
    if (boundedLength === 0) return Promise.resolve(new Uint8Array())

    const result = this.#pendingRead.then(() =>
      decryptRange(this.#fetcher, this.#metadata, this.#cek, { offset, length: boundedLength })
    )
    this.#pendingRead = result.then(
      () => undefined,
      () => undefined
    )
    return result
  }
}

export interface ProtectedArchive {
  list(): readonly ProtectedEntry[]
  open(path: string): Promise<ReadableStream<Uint8Array>>
}

class RangeBackedProtectedArchive implements ProtectedArchive {
  readonly #entries: readonly ProtectedEntry[]
  readonly #files: ReadonlyMap<string, FileEntry>

  constructor(entries: readonly ProtectedEntry[], files: ReadonlyMap<string, FileEntry>) {
    this.#entries = entries
    this.#files = files
  }

  list(): readonly ProtectedEntry[] {
    return this.#entries
  }

  async open(path: string): Promise<ReadableStream<Uint8Array>> {
    const entry = this.#files.get(path)
    if (!entry) throw new Error(`Protected archive file not found: ${path}`)

    const stream = new TransformStream<Uint8Array, Uint8Array>()
    void entry
      .getData(stream.writable, {
        checkSignature: true,
        useWebWorkers: false,
      })
      .catch((error: unknown) => stream.writable.abort(error).catch(() => undefined))
    return stream.readable
  }
}

function createProtectedArchive(entries: Entry[], plaintextSize: number): ProtectedArchive {
  if (entries.length > MAX_ARCHIVE_ENTRIES) {
    throw new Error(`Protected archive has more than ${MAX_ARCHIVE_ENTRIES} entries`)
  }

  const paths = new Map<string, boolean>()
  const files = new Map<string, FileEntry>()
  const protectedEntries: ProtectedEntry[] = []

  for (const entry of entries) {
    const canonicalPath = validateEntryPath(entry.filename, entry.directory)
    if (paths.has(canonicalPath)) throw new Error(`Protected archive contains duplicate path: ${canonicalPath}`)
    if (
      !Number.isSafeInteger(entry.uncompressedSize) ||
      entry.uncompressedSize < 0 ||
      entry.uncompressedSize > plaintextSize ||
      !Number.isSafeInteger(entry.compressedSize) ||
      entry.compressedSize !== entry.uncompressedSize
    ) {
      throw new Error(`Protected archive contains an invalid entry size: ${entry.filename}`)
    }
    if (entry.compressionMethod !== 0 || entry.encrypted) {
      throw new Error(`Protected archive entry is not stored plainly: ${entry.filename}`)
    }

    paths.set(canonicalPath, entry.directory)
    if (!entry.directory) files.set(entry.filename, entry)
    protectedEntries.push(
      Object.freeze({
        path: entry.filename,
        directory: entry.directory,
        size: entry.uncompressedSize,
        contentType: entry.directory ? 'inode/directory' : getMimeType(entry.filename),
      })
    )
  }

  for (const [path] of paths) {
    const segments = path.split('/')
    for (let index = 1; index < segments.length; index++) {
      if (paths.get(segments.slice(0, index).join('/')) === false) {
        throw new Error(`Protected archive path conflicts with a file: ${path}`)
      }
    }
  }

  protectedEntries.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0))
  return new RangeBackedProtectedArchive(Object.freeze(protectedEntries), files)
}

function validateEntryPath(path: string, directory: boolean): string {
  if (!path || path.includes('\\') || path.includes('\0') || path.startsWith('/') || /^[A-Za-z]:\//.test(path)) {
    throw new Error(`Protected archive contains unsafe path: ${path}`)
  }

  const canonicalPath = directory && path.endsWith('/') ? path.slice(0, -1) : path
  const segments = canonicalPath.split('/')
  if (!canonicalPath || segments.some((segment) => !segment || segment === '.' || segment === '..')) {
    throw new Error(`Protected archive contains unsafe path: ${path}`)
  }
  if (directory !== path.endsWith('/')) {
    throw new Error(`Protected archive contains an inconsistent directory path: ${path}`)
  }
  return canonicalPath
}

function validateMetadata(metadata: EnvelopeMetadata): {
  plaintextSize: number
  salt: Uint8Array
} {
  const appMetadata = metadata.appMetadata
  const salt = appMetadata?.pbkdf2_salt
  const plaintextSize = appMetadata?.plaintext_size

  if (!metadata.seekable) throw new Error('Protected archive must use seekable encryption')
  if (!(salt instanceof Uint8Array) || salt.length !== PBKDF2_SALT_BYTES) {
    throw new Error('Protected archive has invalid PBKDF2 salt metadata')
  }
  if (appMetadata?.pbkdf2_iterations !== PBKDF2_ITERATIONS) {
    throw new Error('Protected archive has invalid PBKDF2 iteration metadata')
  }
  if (appMetadata?.pbkdf2_hash !== PBKDF2_HASH) {
    throw new Error('Protected archive has invalid PBKDF2 hash metadata')
  }
  if (appMetadata?.content_type !== CONTENT_TYPE) {
    throw new Error('Protected archive has invalid content type metadata')
  }
  if (typeof plaintextSize !== 'number' || !Number.isSafeInteger(plaintextSize) || plaintextSize < 0) {
    throw new Error('Protected archive has invalid plaintext size metadata')
  }
  const chunkSize = metadata.chunkSize
  const chunkCount = metadata.chunkCount
  if (
    typeof chunkSize !== 'number' ||
    !Number.isSafeInteger(chunkSize) ||
    chunkSize <= 0 ||
    chunkSize > MAX_CHUNK_SIZE ||
    typeof chunkCount !== 'number' ||
    !Number.isSafeInteger(chunkCount) ||
    chunkCount !== Math.max(1, Math.ceil(plaintextSize / chunkSize))
  ) {
    throw new Error('Protected archive has invalid chunk metadata')
  }

  return { plaintextSize, salt }
}

export async function openProtectedArchive(
  cid: string,
  password: string,
  fetchFn?: typeof fetch
): Promise<ProtectedArchive> {
  if (!CID.test(cid)) throw new Error('Invalid encrypted Root CID')

  const fetcher = createHttpBlobFetcher(`https://${cid}.ipfs.dweb.link/`, fetchFn)
  const metadata = await parseEnvelope(fetcher)
  const { plaintextSize, salt } = validateMetadata(metadata)
  const { cek } = await deriveKey({ kind: 'password', password }, salt)
  const zipReader = new ZipReader(new FeeZipReader(fetcher, metadata, cek, plaintextSize), {
    useWebWorkers: false,
  })

  try {
    const entries: Entry[] = []
    for await (const entry of zipReader.getEntriesGenerator()) {
      if (entries.length === MAX_ARCHIVE_ENTRIES) {
        throw new Error(`Protected archive has more than ${MAX_ARCHIVE_ENTRIES} entries`)
      }
      entries.push(entry)
    }
    return createProtectedArchive(entries, plaintextSize)
  } catch (error) {
    cek.fill(0)
    await zipReader.close().catch(() => undefined)
    throw error
  }
}
