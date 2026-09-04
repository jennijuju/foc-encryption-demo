import {
  MAX_BINARY_PREVIEW_BYTES,
  MAX_DOCUMENT_PREVIEW_BYTES,
  readEntryPrefix,
  readInlineEntry,
} from './decrypt.js'
import { parseFragment } from './fragment.js'
import type { ProtectedArchive, ProtectedEntry } from './protected-archive.js'
import { openProtectedArchive } from './protected-archive.js'
import { detectContentType, isBinaryPreviewType, renderContent } from './render.js'
import { saveEntry } from './save.js'
import { showAccessKeyPrompt, showMissingLink, showProtectedArchive, showSaveEntry } from './ui.js'

function getContainer(): HTMLElement {
  const element = document.getElementById('app')
  if (!element) throw new Error('Viewer root is missing')
  return element
}

const container = getContainer()
let activeArchive: ProtectedArchive | undefined


async function closeArchive(archive: ProtectedArchive): Promise<void> {
  if (activeArchive === archive) activeArchive = undefined
  await archive.close()
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
      renderContent(container, data, await detectContentType(data))
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
        renderContent(container, data, detectedType)
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
        entry.path.split('/').at(-1) ?? 'decrypted-content'
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
  showProtectedArchive(container, entries, (entry) => openAndRender(archive, entry))
}

function init(): void {
  const fragment = parseFragment(window.location.hash)
  if (!fragment) {
    showMissingLink(container)
    return
  }

  showAccessKeyPrompt(container, (accessKey) => unlockArchive(fragment.cid, accessKey))
}

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
