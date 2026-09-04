import { ZipReader, Uint8ArrayReader, Uint8ArrayWriter } from '@zip.js/zip.js'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { execFile, spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { Writable } from 'node:stream'
import { fileURLToPath } from 'node:url'
import { decrypt, deriveKey, parseEnvelope } from 'foc-encryption'
import { protectPath } from '../../src/protect.js'

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const artifactPath = join(packageRoot, 'dist', 'foc-protect.mjs')
const ACCESS_KEY = /^engram_[A-Za-z0-9_-]{43}$/

function execNode(args: string[]): Promise<{ stdout: string; stderr: string }> {
  const { promise, resolve: resolveExecution, reject } =
    Promise.withResolvers<{ stdout: string; stderr: string }>()
  execFile(process.execPath, args, { cwd: packageRoot, encoding: 'utf8' }, (error, stdout, stderr) => {
    if (error) reject(Object.assign(error, { stdout, stderr }))
    else resolveExecution({ stdout, stderr })
  })
  return promise
}

function accessKeyCapture(): { output: Writable; value: () => string } {
  const chunks: Uint8Array[] = []
  return {
    output: new Writable({
      write(chunk: Uint8Array, _encoding, callback) {
        chunks.push(new Uint8Array(chunk))
        callback()
      },
    }),
    value: () => Buffer.concat(chunks).toString('utf8'),
  }
}

async function decryptZip(outputPath: string, accessKey: string) {
  const blob = new Uint8Array(await readFile(outputPath))
  const metadata = parseEnvelope(blob)
  const salt = metadata.appMetadata?.pbkdf2_salt
  if (!(salt instanceof Uint8Array)) throw new Error('Missing PBKDF2 salt')
  const derived = await deriveKey({ kind: 'password', password: accessKey }, salt)
  const zipBytes = await decrypt(blob, derived.cek)
  derived.cek.fill(0)
  const zipReader = new ZipReader(new Uint8ArrayReader(zipBytes))
  const entries = await zipReader.getEntries()
  const files = new Map<string, Uint8Array>()
  for (const entry of entries) {
    if (!entry.directory) files.set(entry.filename, await entry.getData(new Uint8ArrayWriter()))
  }
  await zipReader.close()
  return { blob, metadata, zipBytes, entries, files }
}

describe.sequential('protectPath', () => {
  let tempDir: string

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'foc-protect-integration-'))
  })

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true })
  })

  it('protects a file with a generated 256-bit access key and opaque metadata', async () => {
    const input = join(tempDir, 'private-name.txt')
    const output = join(tempDir, 'neutral.fee')
    const capture = accessKeyCapture()
    await writeFile(input, 'private file bytes')

    const result = await protectPath({ input, output, accessKeyOutput: capture.output })
    const accessKey = capture.value()
    const decrypted = await decryptZip(output, accessKey)

    expect(accessKey).toMatch(ACCESS_KEY)
    expect(accessKey).not.toMatch(/[\r\n]/)
    expect(result).toEqual({
      output,
      sourceBytes: 18,
      encryptedBytes: decrypted.blob.length,
      entryCount: 1,
      contentKind: 'application/zip',
    })
    expect(Object.keys(decrypted.metadata.appMetadata ?? {}).sort()).toEqual([
      'content_type',
      'pbkdf2_hash',
      'pbkdf2_iterations',
      'pbkdf2_salt',
      'plaintext_size',
    ])
    expect(decrypted.metadata.appMetadata?.plaintext_size).toBe(decrypted.zipBytes.length)
    expect(Buffer.from(decrypted.blob).includes(Buffer.from('private-name.txt'))).toBe(false)
    expect(decrypted.entries.map((entry) => [entry.filename, entry.compressionMethod])).toEqual([
      ['private-name.txt', 0],
    ])
    expect(Buffer.from(decrypted.files.get('private-name.txt') ?? []).toString()).toBe('private file bytes')
    expect((await stat(output)).mode & 0o777).toBe(0o600)
    expect((await readdir(tempDir)).some((name) => name.endsWith('.tmp'))).toBe(false)
  })

  it('never overwrites an existing output or leaves a transactional temporary file', async () => {
    const input = join(tempDir, 'input.txt')
    const output = join(tempDir, 'neutral.fee')
    const capture = accessKeyCapture()
    await writeFile(input, 'new secret')
    await writeFile(output, 'keep me')

    await expect(protectPath({ input, output, accessKeyOutput: capture.output })).rejects.toThrow()

    expect(await readFile(output, 'utf8')).toBe('keep me')
    expect((await readdir(tempDir)).some((name) => name.endsWith('.tmp'))).toBe(false)
  })

  it('protects a sorted nested folder including dotfiles', async () => {
    const input = join(tempDir, 'named-folder')
    const output = join(tempDir, 'neutral.fee')
    const capture = accessKeyCapture()
    await mkdir(join(input, 'nested'), { recursive: true })
    await writeFile(join(input, '.hidden'), 'hidden')
    await writeFile(join(input, 'root.txt'), 'root')
    await writeFile(join(input, 'nested', 'child.txt'), 'child')

    const result = await protectPath({ input, output, accessKeyOutput: capture.output })
    const decrypted = await decryptZip(output, capture.value())

    expect(result.sourceBytes).toBe(15)
    expect(result.entryCount).toBe(4)
    expect(decrypted.entries.map((entry) => entry.filename)).toEqual([
      '.hidden',
      'nested/',
      'nested/child.txt',
      'root.txt',
    ])
    expect([...decrypted.files].map(([name, bytes]) => [name, Buffer.from(bytes).toString()])).toEqual([
      ['.hidden', 'hidden'],
      ['nested/child.txt', 'child'],
      ['root.txt', 'root'],
    ])
  })

  it('removes its private ZIP and transactional output after failure', async () => {
    const scratch = join(tempDir, 'scratch')
    const input = join(tempDir, 'input.txt')
    const oldTmp = process.env.TMPDIR
    await mkdir(scratch)
    await writeFile(input, 'bytes')
    process.env.TMPDIR = scratch

    try {
      await expect(
        protectPath({ input, output: tempDir, accessKeyOutput: accessKeyCapture().output })
      ).rejects.toThrow()
      expect(await readdir(scratch)).toEqual([])
      expect((await readdir(tempDir)).some((name) => name.endsWith('.tmp'))).toBe(false)
    } finally {
      if (oldTmp === undefined) delete process.env.TMPDIR
      else process.env.TMPDIR = oldTmp
    }
  })
})

describe.sequential('standalone foc-protect command', () => {
  let tempDir: string

  beforeAll(async () => {
    await execNode([join(packageRoot, 'scripts', 'build-protect.mjs')])
  })

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'foc-protect-cli-'))
  })

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true })
  })

  afterAll(async () => {
    const artifact = await readFile(artifactPath, 'utf8')
    expect(artifact).not.toContain('@filoz/synapse-sdk')
    expect(artifact).not.toContain('@scure/bip39')
  })

  it('writes an access key only to its inherited descriptor and one result to stdout', async () => {
    const input = join(tempDir, 'input.txt')
    const output = join(tempDir, 'neutral.fee')
    await writeFile(input, 'cli bytes')
    const child = spawn(
      process.execPath,
      [artifactPath, '--input', input, '--output', output, '--access-key-output-fd', '3'],
      { cwd: packageRoot, stdio: ['ignore', 'pipe', 'pipe', 'pipe'] }
    )
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    const accessKeyOutput = child.stdio[3]
    if (!accessKeyOutput || child.pid === undefined) throw new Error('Access-key FD was not created')
    let stdout = ''
    let stderr = ''
    let accessKey = ''
    child.stdout.on('data', (chunk) => {
      stdout += String(chunk)
    })
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk)
    })
    accessKeyOutput.on('data', (chunk) => {
      accessKey += String(chunk)
    })

    const { promise: processListingPromise, resolve: resolveInspection, reject } = Promise.withResolvers<string>()
    execFile('ps', ['-p', String(child.pid), '-o', 'command='], { encoding: 'utf8' }, (error, listing) => {
      if (error) reject(error)
      else resolveInspection(String(listing))
    })
    const processListing = await processListingPromise
    const [code] = await once(child, 'close')

    expect(code).toBe(0)
    expect(accessKey).toMatch(ACCESS_KEY)
    expect(processListing).not.toContain(accessKey)
    expect(stdout).not.toContain(accessKey)
    expect(stderr).not.toContain(accessKey)
    expect(stdout.trim().split('\\n')).toHaveLength(1)
    expect(JSON.parse(stdout)).toEqual({
      output,
      sourceBytes: 9,
      encryptedBytes: (await stat(output)).size,
      entryCount: 1,
      contentKind: 'application/zip',
    })
  })

  it('cleans temporary files after a forced output failure', async () => {
    const input = join(tempDir, 'input.txt')
    const scratch = join(tempDir, 'scratch')
    await writeFile(input, 'bytes')
    await mkdir(scratch)
    const child = spawn(
      process.execPath,
      [artifactPath, '--input', input, '--output', tempDir, '--access-key-output-fd', '3'],
      {
        cwd: packageRoot,
        env: { ...process.env, TMPDIR: scratch },
        stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
      }
    )
    child.stderr.resume()
    child.stdio[3]?.resume()

    const [code] = await once(child, 'close')

    expect(code).toBe(1)
    expect(await readdir(scratch)).toEqual([])
    expect((await readdir(tempDir)).some((name) => name.endsWith('.tmp'))).toBe(false)
  })

  it.each([
    ['missing access-key descriptor', []],
    ['legacy password input', ['--password-input-fd', '3']],
    ['legacy password output', ['--password-output-fd', '3']],
  ])('rejects %s', async (_label, extraArgs) => {
    const input = join(tempDir, 'input.txt')
    const output = join(tempDir, 'neutral.fee')
    await writeFile(input, 'bytes')

    await expect(execNode([artifactPath, '--input', input, '--output', output, ...extraArgs])).rejects.toMatchObject({
      stdout: '',
    })
  })
})
