import {
  MAX_BINARY_PREVIEW_BYTES,
  MAX_DOCUMENT_PREVIEW_BYTES,
  readEntryPrefix,
  readInlineEntry,
} from './decrypt.js'
import { parseFragment } from './fragment.js'
import type { ProtectedArchive, ProtectedEntry } from './protected-archive.js'
import { openProtectedArchive } from './protected-archive.js'
import { detectContentType, isBinaryPreviewType, renderContent, revokeRenderedObjectUrls } from './render.js'
import { saveArchiveFolder, saveEntry } from './save.js'
import { showAccessKeyPrompt, showMissingLink, showProtectedArchive, showSaveEntry } from './ui.js'

function getContainer(): HTMLElement {
  const element = document.getElementById('app')
  if (!element) throw new Error('Viewer root is missing')
  return element
}

const container = getContainer()
let activeArchive: ProtectedArchive | undefined
let activeEntries: readonly ProtectedEntry[] | undefined


async function closeArchive(archive: ProtectedArchive): Promise<void> {
  if (activeArchive === archive) activeArchive = undefined
  await archive.close()
}


function entryFilename(entry: ProtectedEntry): string {
  return entry.path.split('/').at(-1) ?? 'decrypted-content'
}

function prependBackBar(target: HTMLElement): void {
  const bar = document.createElement('div')
  bar.className = 'back-bar'
  const back = document.createElement('button')
  back.type = 'button'
  back.className = 'back-link'
  back.textContent = '‹ All files'
  back.addEventListener('click', () => history.back())
  bar.append(back)
  target.prepend(bar)
}

function showArchiveTree(archive: ProtectedArchive, entries: readonly ProtectedEntry[]): void {
  revokeRenderedObjectUrls(container)
  showProtectedArchive(
    container,
    entries,
    async (entry) => {
      await openAndRender(archive, entry)
      history.pushState({ engramEntry: entry.path }, '', window.location.href)
      prependBackBar(container)
    },
    () => saveArchiveFolder(entries, (path) => archive.open(path), 'engram-share')
  )
}

async function openAndRender(
  archive: ProtectedArchive,
  entry: ProtectedEntry,
  closeAfterOpen = false
): Promise<void> {
  if (entry.directory) return
  try {
    if (entry.size <= MAX_DOCUMENT_PREVIEW_BYTES) {
      const data = await readInlineEntry(
        await archive.open(entry.path),
        entry.size,
        MAX_DOCUMENT_PREVIEW_BYTES
      )
      renderContent(container, data, await detectContentType(data), entryFilename(entry))
      if (closeAfterOpen) await closeArchive(archive)
      return
    }

    if (entry.size <= MAX_BINARY_PREVIEW_BYTES) {
      const detectedType = await detectContentType(await readEntryPrefix(await archive.open(entry.path)))
      if (isBinaryPreviewType(detectedType)) {
        const data = await readInlineEntry(
          await archive.open(entry.path),
          entry.size,
          MAX_BINARY_PREVIEW_BYTES
        )
        renderContent(container, data, detectedType, entryFilename(entry))
        if (closeAfterOpen) await closeArchive(archive)
        return
      }
    }

    showSaveEntry(container, entry, async () => {
      const result = await saveEntry(
        {
          size: entry.size,
          contentType: entry.contentType,
          open: () => archive.open(entry.path),
        },
        entryFilename(entry)
      )
      if (result === 'saved' && closeAfterOpen) await closeArchive(archive)
      return result
    })
  } catch (error) {
    if (closeAfterOpen) await closeArchive(archive)
    throw error
  }
}

async function unlockArchive(cid: string, accessKey: string): Promise<void> {
  const archive = await openProtectedArchive(cid, accessKey)
  await activeArchive?.close()
  activeArchive = archive
  const entries = archive.list()
  if (entries.length === 1 && !entries[0].directory) {
    await openAndRender(archive, entries[0], true)
    return
  }
  activeEntries = entries
  showArchiveTree(archive, entries)
}

function init(): void {
  const fragment = parseFragment(window.location.hash)
  if (!fragment) {
    showMissingLink(container)
    return
  }

  showAccessKeyPrompt(container, (accessKey) => unlockArchive(fragment.cid, accessKey))
}

window.addEventListener('popstate', (event) => {
  const archive = activeArchive
  const entries = activeEntries
  if (!archive || !entries) return
  const path = (event.state as { engramEntry?: string } | null)?.engramEntry
  if (typeof path === 'string') {
    const entry = entries.find((candidate) => candidate.path === path)
    if (entry) {
      void openAndRender(archive, entry)
        .then(() => prependBackBar(container))
        .catch(() => showArchiveTree(archive, entries))
      return
    }
  }
  showArchiveTree(archive, entries)
})

window.addEventListener(
  'pagehide',
  () => {
    const archive = activeArchive
    activeArchive = undefined
    void archive?.close()
  },
  { once: true }
)

init()
