import type { Writable as NodeWritable } from 'node:stream'
import { ZipReader, Uint8ArrayReader, Uint8ArrayWriter } from '@zip.js/zip.js'
import { wordlist } from '@scure/bip39/wordlists/english'
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

function execNode(args: string[]): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolveExecution, reject) => {
    execFile(process.execPath, args, { cwd: packageRoot, encoding: 'utf8' }, (error, stdout, stderr) => {
      if (error) {
        reject(Object.assign(error, { stdout, stderr }))
      } else {
        resolveExecution({ stdout, stderr })
      }
    })
  })
}

async function decryptZip(outputPath: string, password: string) {
  const blob = new Uint8Array(await readFile(outputPath))
  const metadata = parseEnvelope(blob)
  const salt = metadata.appMetadata?.pbkdf2_salt
  if (!(salt instanceof Uint8Array)) throw new Error('Missing PBKDF2 salt')
  const derived = await deriveKey({ kind: 'password', password }, salt)
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

  it('protects a file with a generated six-word password and opaque outer metadata', async () => {
    const input = join(tempDir, 'private-name.txt')
    const output = join(tempDir, 'neutral.fee')
    const chunks: Uint8Array[] = []
    const passwordOutput = new Writable({
      write(chunk: Uint8Array, _encoding, callback) {
        chunks.push(new Uint8Array(chunk))
        callback()
      },
    })
    await writeFile(input, 'private file bytes')

    const result = await protectPath({ input, output, passwordOutput })
    const password = Buffer.concat(chunks).toString('utf8')
    const decrypted = await decryptZip(output, password)

    expect(password.split('-')).toHaveLength(6)
    expect(password.split('-').every((word) => wordlist.includes(word))).toBe(true)
    expect(password).not.toMatch(/[\r\n]/)
    expect(Object.keys(result)).toEqual(['output', 'sourceBytes', 'encryptedBytes', 'entryCount', 'contentKind'])
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
    expect(decrypted.metadata.appMetadata?.content_type).toBe('application/zip')
    expect(decrypted.metadata.appMetadata?.plaintext_size).toBe(decrypted.zipBytes.length)
    expect(decrypted.metadata.appMetadata?.pbkdf2_iterations).toBe(600_000)
    expect(decrypted.metadata.appMetadata?.pbkdf2_hash).toBe('SHA-256')
    expect(Buffer.from(decrypted.blob).includes(Buffer.from('private-name.txt'))).toBe(false)
    expect(decrypted.entries.map((entry) => [entry.filename, entry.compressionMethod])).toEqual([
      ['private-name.txt', 0],
    ])
    expect(Buffer.from(decrypted.files.get('private-name.txt') ?? []).toString()).toBe('private file bytes')
    expect((await stat(output)).mode & 0o777).toBe(0o600)
  })
  it('refuses to overwrite an existing output file', async () => {
    const input = join(tempDir, 'input.txt')
    const output = join(tempDir, 'neutral.fee')
    await writeFile(input, 'new secret')
    await writeFile(output, 'keep me')

    await expect(protectPath({ input, output, password: 'supplied-through-an-fd' })).rejects.toThrow()
    expect(await readFile(output, 'utf8')).toBe('keep me')
  })

  it('protects a sorted nested folder including dotfiles using a supplied password', async () => {
    const input = join(tempDir, 'named-folder')
    const output = join(tempDir, 'neutral.fee')
    await mkdir(join(input, 'nested'), { recursive: true })
    await writeFile(join(input, '.hidden'), 'hidden')
    await writeFile(join(input, 'root.txt'), 'root')
    await writeFile(join(input, 'nested', 'child.txt'), 'child')

    const result = await protectPath({ input, output, password: 'supplied-through-an-fd' })
    const decrypted = await decryptZip(output, 'supplied-through-an-fd')

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
    expect(decrypted.entries.every((entry) => entry.compressionMethod === 0)).toBe(true)
  })

  it('removes its private temporary ZIP after success and output failure', async () => {
    const scratch = join(tempDir, 'scratch')
    const input = join(tempDir, 'input.txt')
    const output = join(tempDir, 'success.fee')
    const oldTmp = process.env.TMPDIR
    await mkdir(scratch)
    await writeFile(input, 'bytes')
    process.env.TMPDIR = scratch

    try {
      await protectPath({ input, output, password: 'password' })
      expect(await readdir(scratch)).toEqual([])

      await expect(protectPath({ input, output: tempDir, password: 'password' })).rejects.toThrow()
      expect(await readdir(scratch)).toEqual([])
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
  })

  it('reads a supplied password only from an inherited FD and prints one non-secret JSON result', async () => {
    const password = 'fd-only-password-value'
    const input = join(tempDir, 'input.txt')
    const output = join(tempDir, 'neutral.fee')
    const scratch = join(tempDir, 'scratch')
    await mkdir(scratch)
    await writeFile(input, 'cli bytes')
    const args = [artifactPath, '--input', input, '--output', output, '--password-input-fd', '3']
    const child = spawn(process.execPath, args, {
      cwd: packageRoot,
      env: { ...process.env, TMPDIR: scratch },
      stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
    })
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => {
      stdout += String(chunk)
    })
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk)
    })
    const passwordInput = child.stdio[3] as NodeWritable | null
    if (!passwordInput || child.pid === undefined) throw new Error('Password FD was not created')

    const processListing = await new Promise<string>((resolveInspection, reject) => {
      execFile('ps', ['-p', String(child.pid), '-o', 'command='], { encoding: 'utf8' }, (error, listing) => {
        if (error) reject(error)
        else resolveInspection(String(listing))
      })
    })
    expect(processListing).not.toContain(password)

    passwordInput.end(`${password}\n`)
    const [code] = await once(child, 'close')
    expect(code).toBe(0)
    expect(stderr).not.toContain(password)
    expect(stdout).not.toContain(password)
    expect(stdout.trim().split('\n')).toHaveLength(1)
    expect(JSON.parse(stdout)).toEqual({
      output,
      sourceBytes: 9,
      encryptedBytes: (await stat(output)).size,
      entryCount: 1,
      contentKind: 'application/zip',
    })
    expect(await readdir(scratch)).toEqual([])
  })

  it('writes a generated six-word password only to its inherited output FD', async () => {
    const input = join(tempDir, 'input.txt')
    const output = join(tempDir, 'neutral.fee')
    await writeFile(input, 'bytes')
    const child = spawn(
      process.execPath,
      [artifactPath, '--input', input, '--output', output, '--password-output-fd', '3'],
      { cwd: packageRoot, stdio: ['ignore', 'pipe', 'pipe', 'pipe'] }
    )
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    const passwordOutput = child.stdio[3]
    if (!passwordOutput) throw new Error('Password FD was not created')
    let stdout = ''
    let stderr = ''
    let passwordBytes = ''
    child.stdout.on('data', (chunk) => {
      stdout += String(chunk)
    })
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk)
    })
    passwordOutput.on('data', (chunk) => {
      passwordBytes += String(chunk)
    })

    const [code] = await once(child, 'close')
    const password = passwordBytes
    expect(code).toBe(0)
    expect(password.split('-')).toHaveLength(6)
    expect(password.split('-').every((word) => wordlist.includes(word))).toBe(true)
    expect(password).not.toMatch(/[\r\n]/)
    expect(stdout).not.toContain(password)
    expect(stderr).not.toContain(password)
  })

  it('removes its private temporary ZIP after a forced CLI output failure', async () => {
    const password = 'failure-password'
    const input = join(tempDir, 'input.txt')
    const scratch = join(tempDir, 'scratch')
    await writeFile(input, 'bytes')
    await mkdir(scratch)
    const child = spawn(
      process.execPath,
      [artifactPath, '--input', input, '--output', tempDir, '--password-input-fd', '3'],
      {
        cwd: packageRoot,
        env: { ...process.env, TMPDIR: scratch },
        stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
      }
    )
    child.stderr.setEncoding('utf8')
    let stderr = ''
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk)
    })
    const passwordInput = child.stdio[3] as NodeWritable | null
    if (!passwordInput) throw new Error('Password FD was not created')
    passwordInput.end(`${password}\n`)

    const [code] = await once(child, 'close')
    expect(code).toBe(1)
    expect(stderr).not.toContain(password)
    expect(await readdir(scratch)).toEqual([])
  })

  it.each([
    ['neither', []],
    ['both', ['--password-input-fd', '3', '--password-output-fd', '4']],
  ])('rejects %s password FD selection', async (_label, passwordArgs) => {
    const input = join(tempDir, 'input.txt')
    const output = join(tempDir, 'neutral.fee')
    await writeFile(input, 'bytes')

    await expect(execNode([artifactPath, '--input', input, '--output', output, ...passwordArgs])).rejects.toMatchObject(
      { stdout: '' }
    )
  })
})
