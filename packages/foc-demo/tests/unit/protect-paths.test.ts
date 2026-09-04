import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { assertPathWithinRoot, collectArchiveEntries, validateArchivePath, writeZip } from '../../src/protect.js'

describe('protected archive paths', () => {
  let tempDir: string

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'foc-protect-paths-'))
  })

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true })
  })

  it('sorts forward-slash paths deterministically and includes dotfiles', async () => {
    const root = join(tempDir, 'folder')
    await mkdir(join(root, 'nested'), { recursive: true })
    await writeFile(join(root, 'z.txt'), 'z')
    await writeFile(join(root, '.hidden'), 'hidden')
    await writeFile(join(root, 'nested', 'b.txt'), 'b')
    await writeFile(join(root, 'nested', 'a.txt'), 'a')

    const entries = await collectArchiveEntries(root)

    expect(entries.map((entry) => entry.archivePath)).toEqual([
      '.hidden',
      'nested/',
      'nested/a.txt',
      'nested/b.txt',
      'z.txt',
    ])
    expect(entries.every((entry) => !entry.archivePath.includes('\\'))).toBe(true)
  })

  it('uses the basename for a single-file archive', async () => {
    const input = join(tempDir, 'one.txt')
    await writeFile(input, 'one')

    await expect(collectArchiveEntries(input)).resolves.toMatchObject([
      { archivePath: 'one.txt', directory: false, size: 3 },
    ])
  })

  it.each(['/absolute.txt', 'C:\\absolute.txt', '../escape.txt', 'safe/../../escape.txt'])(
    'rejects unsafe archive path %s',
    (archivePath) => {
      expect(() => validateArchivePath(archivePath)).toThrow('Unsafe archive path')
    }
  )

  it('rejects a resolved path outside the selected root', () => {
    const root = resolve(tempDir, 'selected')
    expect(() => assertPathWithinRoot(root, resolve(tempDir, 'outside.txt'))).toThrow('outside the selected root')
  })

  it('rejects input and nested symlinks', async () => {
    const target = join(tempDir, 'target.txt')
    const inputLink = join(tempDir, 'input-link')
    const root = join(tempDir, 'folder')
    await writeFile(target, 'target')
    await symlink(target, inputLink)
    await mkdir(root)
    await symlink(target, join(root, 'nested-link'))

    await expect(collectArchiveEntries(inputLink)).rejects.toThrow('Symbolic links are not allowed')
    await expect(collectArchiveEntries(root)).rejects.toThrow('Symbolic links are not allowed')
  })

  it('rejects a source file swapped for a symlink after collection', async () => {
    const root = join(tempDir, 'folder')
    const input = join(root, 'source.txt')
    const outside = join(tempDir, 'outside.txt')
    await mkdir(root)
    await writeFile(input, 'collected bytes')
    await writeFile(outside, 'outside bytes')
    const entries = await collectArchiveEntries(root)

    await rm(input)
    await symlink(outside, input)

    await expect(writeZip(entries, join(tempDir, 'payload.zip'))).rejects.toThrow()
  })
})
