import { randomBytes, randomUUID } from 'node:crypto'
import { constants, createReadStream, createWriteStream } from 'node:fs'
import { chmod, link, lstat, mkdtemp, open, readdir, realpath, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname, isAbsolute, join, posix, relative, resolve, sep, win32 } from 'node:path'
import { Readable, Writable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { ZipWriter } from '@zip.js/zip.js'
import { CoseAlgorithm, deriveKey, encryptStream } from 'foc-encryption'

const CONTENT_KIND = 'application/zip' as const
const TEMP_PREFIX = 'foc-protect-'
const PBKDF2_ITERATIONS = 600_000
const PBKDF2_HASH = 'SHA-256'
const MAX_ARCHIVE_ENTRIES = 10_000
const MAX_SOURCE_BYTES = 1_048_576_000
const FILE_READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW

export interface ProtectPathOptions {
  input: string
  output: string
  accessKeyOutput: NodeJS.WritableStream
}
export interface ProtectResult {
  output: string
  sourceBytes: number
  encryptedBytes: number
  entryCount: number
  contentKind: typeof CONTENT_KIND
}

export interface ArchiveEntry {
  archivePath: string
  sourcePath: string
  rootPath: string
  size: number
  device: number
  inode: number
  directory: boolean
  modifiedAt: Date
  modifiedAtMs: number
  changedAtMs: number
  linkCount: number
}

export function assertProtectedZipSize(size: number): void {
  if (!Number.isSafeInteger(size)) throw new Error('ZIP is too large to represent safely')
  if (size >= MAX_SOURCE_BYTES) throw new Error('Protected ZIP must remain below 1000 MiB')
}

export function validateArchivePath(archivePath: string): string {
  const directory = archivePath.endsWith('/')
  const pathWithoutSuffix = directory ? archivePath.slice(0, -1) : archivePath
  if (
    !pathWithoutSuffix ||
    pathWithoutSuffix.includes('\\') ||
    pathWithoutSuffix.includes('\0') ||
    isAbsolute(pathWithoutSuffix) ||
    win32.isAbsolute(pathWithoutSuffix)
  ) {
    throw new Error(`Unsafe archive path: ${archivePath}`)
  }
  const segments = pathWithoutSuffix.split('/')
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new Error(`Unsafe archive path: ${archivePath}`)
  }
  return `${segments.join('/')}${directory ? '/' : ''}`
}

export function assertPathWithinRoot(rootPath: string, candidatePath: string): void {
  const fromRoot = relative(rootPath, candidatePath)
  if (fromRoot === '..' || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) {
    throw new Error('Resolved path is outside the selected root')
  }
}

function sameSourceIdentity(left: Awaited<ReturnType<typeof lstat>>, right: Awaited<ReturnType<typeof lstat>>): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs &&
    left.nlink === right.nlink
  )
}

export async function collectArchiveEntries(input: string): Promise<ArchiveEntry[]> {
  const inputPath = resolve(input)
  const inputStats = await lstat(inputPath)
  if (inputStats.isSymbolicLink()) throw new Error('Symbolic links are not allowed')
  if (inputStats.isFile() && inputStats.nlink !== 1) throw new Error('Hard-linked files are not allowed')

  const resolvedInput = await realpath(inputPath)
  const resolvedInputStats = await lstat(resolvedInput)
  if (!sameSourceIdentity(inputStats, resolvedInputStats)) {
    throw new Error('Source changed while its root path was being resolved')
  }
  if (inputStats.isFile()) {
    return [
      {
        archivePath: validateArchivePath(basename(inputPath)),
        sourcePath: resolvedInput,
        rootPath: resolvedInput,
        size: inputStats.size,
        device: inputStats.dev,
        inode: inputStats.ino,
        directory: false,
        modifiedAt: inputStats.mtime,
        modifiedAtMs: inputStats.mtimeMs,
        changedAtMs: inputStats.ctimeMs,
        linkCount: inputStats.nlink,
      },
    ]
  }
  if (!inputStats.isDirectory()) throw new Error('Input must be a regular file or directory')

  const entries: ArchiveEntry[] = []
  const visit = async (directoryPath: string, archivePrefix: string): Promise<void> => {
    const names = (await readdir(directoryPath)).sort()
    for (const name of names) {
      if (name.includes('/') || name.includes('\\') || name === '.' || name === '..') {
        throw new Error(`Unsafe archive path: ${name}`)
      }
      const sourcePath = join(directoryPath, name)
      const sourceStats = await lstat(sourcePath)
      if (sourceStats.isSymbolicLink()) throw new Error('Symbolic links are not allowed')
      if (sourceStats.isFile() && sourceStats.nlink !== 1) {
        throw new Error('Hard-linked files are not allowed')
      }
      const resolvedSource = await realpath(sourcePath)
      assertPathWithinRoot(resolvedInput, resolvedSource)
      const entryPath = validateArchivePath(archivePrefix ? posix.join(archivePrefix, name) : name)

      if (sourceStats.isDirectory()) {
        entries.push({
          archivePath: `${entryPath}/`,
          sourcePath: resolvedSource,
          rootPath: resolvedInput,
          size: 0,
          device: sourceStats.dev,
          inode: sourceStats.ino,
          directory: true,
          modifiedAt: sourceStats.mtime,
          modifiedAtMs: sourceStats.mtimeMs,
          changedAtMs: sourceStats.ctimeMs,
          linkCount: sourceStats.nlink,
        })
        await visit(resolvedSource, entryPath)
      } else if (sourceStats.isFile()) {
        entries.push({
          archivePath: entryPath,
          sourcePath: resolvedSource,
          rootPath: resolvedInput,
          size: sourceStats.size,
          device: sourceStats.dev,
          inode: sourceStats.ino,
          directory: false,
          modifiedAt: sourceStats.mtime,
          modifiedAtMs: sourceStats.mtimeMs,
          changedAtMs: sourceStats.ctimeMs,
          linkCount: sourceStats.nlink,
        })
      } else {
        throw new Error('Only regular files and directories can be protected')
      }
    }
  }

  await visit(resolvedInput, '')
  return entries.sort((left, right) =>
    left.archivePath < right.archivePath ? -1 : left.archivePath > right.archivePath ? 1 : 0
  )
}

export function generateAccessKey(): string {
  return `engram_${randomBytes(32).toString('base64url')}`
}

async function writeGeneratedAccessKey(output: NodeJS.WritableStream, accessKey: string): Promise<void> {
  const { promise, resolve, reject } = Promise.withResolvers<void>()
  output.write(accessKey, (error) => {
    if (error) reject(error)
    else resolve()
  })
  await promise
}

export async function writeZip(entries: ArchiveEntry[], outputPath: string): Promise<number> {
  const nodeOutput = createWriteStream(outputPath, { flags: 'wx', mode: 0o600 })
  const webOutput = Writable.toWeb(nodeOutput) as WritableStream<Uint8Array>
  const zipWriter = new ZipWriter(webOutput, {
    compressionMethod: 0,
    level: 0,
    useWebWorkers: false,
  })

  try {
    for (const entry of entries) {
      if (entry.directory) {
        await zipWriter.add(entry.archivePath, undefined, {
          compressionMethod: 0,
          directory: true,
          lastModDate: entry.modifiedAt,
        })
      } else {
        // libuv opens Node file descriptors close-on-exec; Node does not expose O_CLOEXEC in fs.constants.
        const sourceHandle = await open(entry.sourcePath, FILE_READ_FLAGS)
        try {
          const sourceStats = await sourceHandle.stat()
          if (
            !sourceStats.isFile() ||
            sourceStats.dev !== entry.device ||
            sourceStats.ino !== entry.inode ||
            sourceStats.size !== entry.size ||
            sourceStats.mtimeMs !== entry.modifiedAtMs ||
            sourceStats.ctimeMs !== entry.changedAtMs ||
            sourceStats.nlink !== 1
          ) {
            throw new Error('Source changed after path validation')
          }
          assertPathWithinRoot(entry.rootPath, await realpath(entry.sourcePath))
          const source = Readable.toWeb(
            entry.size === 0
              ? Readable.from([])
              : createReadStream('', { fd: sourceHandle.fd, autoClose: false, start: 0, end: entry.size - 1 })
          ) as ReadableStream<Uint8Array>
          await zipWriter.add(entry.archivePath, source, {
            compressionMethod: 0,
            level: 0,
            lastModDate: entry.modifiedAt,
            ...(entry.size > 0xffffffff ? { zip64: true } : {}),
          })
          const finalStats = await sourceHandle.stat()
          if (
            finalStats.dev !== entry.device ||
            finalStats.ino !== entry.inode ||
            finalStats.size !== entry.size ||
            finalStats.mtimeMs !== entry.modifiedAtMs ||
            finalStats.ctimeMs !== entry.changedAtMs ||
            finalStats.nlink !== 1
          ) {
            throw new Error('Source changed while it was being protected')
          }
        } finally {
          await sourceHandle.close()
        }
      }
    }
    await zipWriter.close()
  } catch (error) {
    nodeOutput.destroy(error instanceof Error ? error : new Error('Failed to write ZIP'))
    await finished(nodeOutput).catch(() => undefined)
    throw error
  }

  await chmod(outputPath, 0o600)
  return (await stat(outputPath)).size
}

async function writeEncryptedOutput(outputPath: string, encrypted: ReadableStream<Uint8Array>): Promise<void> {
  const temporaryPath = join(dirname(outputPath), `.${basename(outputPath)}.${randomUUID()}.tmp`)
  const handle = await open(temporaryPath, 'wx', 0o600)
  const output = createWriteStream('', { fd: handle.fd, autoClose: false })
  try {
    await encrypted.pipeTo(Writable.toWeb(output) as WritableStream<Uint8Array>)
    await handle.sync()
    await handle.close()
    await link(temporaryPath, outputPath)
  } catch (error) {
    output.destroy()
    await handle.close().catch(() => undefined)
    throw error
  } finally {
    await rm(temporaryPath, { force: true }).catch(() => undefined)
  }
}

export async function protectPath(options: ProtectPathOptions): Promise<ProtectResult> {
  if (!options.input || !options.output) throw new Error('Input and output paths are required')
  if (resolve(options.input) === resolve(options.output)) throw new Error('Input and output paths must differ')
  if (!options.accessKeyOutput) throw new Error('An access key output is required')

  const inputPath = resolve(options.input)
  const initialRootStats = await lstat(inputPath)
  const entries = await collectArchiveEntries(options.input)
  const collectedRootStats = await lstat(inputPath)
  if (!sameSourceIdentity(initialRootStats, collectedRootStats)) {
    throw new Error('Input root changed while it was being collected')
  }
  const sourceBytes = entries.reduce((total, entry) => total + entry.size, 0)
  if (!Number.isSafeInteger(sourceBytes)) throw new Error('Input is too large to represent safely')
  if (sourceBytes >= MAX_SOURCE_BYTES) throw new Error('Input must be below 1000 MiB')
  if (entries.length > MAX_ARCHIVE_ENTRIES) {
    throw new Error(`Input has more than ${MAX_ARCHIVE_ENTRIES} entries`)
  }

  const accessKey = generateAccessKey()
  await writeGeneratedAccessKey(options.accessKeyOutput, accessKey)

  const tempDirectory = await mkdtemp(join(tmpdir(), TEMP_PREFIX))
  try {
    await chmod(tempDirectory, 0o700)
    const zipPath = join(tempDirectory, 'payload.zip')
    const plaintextSize = await writeZip(entries, zipPath)
    assertProtectedZipSize(plaintextSize)
    const currentEntries = await collectArchiveEntries(options.input)
    const snapshotMatches =
      currentEntries.length === entries.length &&
      currentEntries.every((entry, index) => {
        const original = entries[index]
        return (
          original !== undefined &&
          entry.archivePath === original.archivePath &&
          entry.device === original.device &&
          entry.inode === original.inode &&
          entry.size === original.size &&
          entry.modifiedAtMs === original.modifiedAtMs &&
          entry.changedAtMs === original.changedAtMs &&
          entry.linkCount === original.linkCount
        )
      })
    const finalRootStats = await lstat(inputPath)
    if (!sameSourceIdentity(initialRootStats, finalRootStats)) {
      throw new Error('Input root changed while it was being protected')
    }
    if (!snapshotMatches) throw new Error('Input changed while it was being protected')
    const derived = await deriveKey({ kind: 'password', password: accessKey })
    if (!derived.salt) {
      derived.cek.fill(0)
      throw new Error('Password derivation did not return a salt')
    }

    try {
      const zipInput = Readable.toWeb(createReadStream(zipPath)) as ReadableStream<Uint8Array>
      const encrypted = await encryptStream(zipInput, derived.cek, {
        algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
        plaintextLength: plaintextSize,
        appMetadata: {
          pbkdf2_salt: derived.salt,
          pbkdf2_iterations: PBKDF2_ITERATIONS,
          pbkdf2_hash: PBKDF2_HASH,
          content_type: CONTENT_KIND,
          plaintext_size: plaintextSize,
        },
      })
      await writeEncryptedOutput(options.output, encrypted)
    } finally {
      derived.cek.fill(0)
    }

    return {
      output: options.output,
      sourceBytes,
      encryptedBytes: (await stat(options.output)).size,
      entryCount: entries.length,
      contentKind: CONTENT_KIND,
    }
  } finally {
    await rm(tempDirectory, { recursive: true, force: true })
  }
}
