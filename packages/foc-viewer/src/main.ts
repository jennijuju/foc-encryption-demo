import { MAX_BINARY_PREVIEW_BYTES, MAX_DOCUMENT_PREVIEW_BYTES, readInlineEntry } from './decrypt.js'
import { parseFragment } from './fragment.js'
import type { ProtectedArchive, ProtectedEntry } from './protected-archive.js'
import { openProtectedArchive } from './protected-archive.js'
import { detectContentType, renderContent, renderProgressiveMedia } from './render.js'
import { saveEntry } from './save.js'
import { showAccessKeyPrompt, showMissingLink, showProtectedArchive, showSaveEntry } from './ui.js'

function getContainer(): HTMLElement {
  const element = document.getElementById('app')
  if (!element) throw new Error('Viewer root is missing')
  return element
}

const container = getContainer()
let activeArchive: ProtectedArchive | undefined

function previewLimit(contentType: string): number {
  if (contentType === 'text/html' || contentType === 'text/plain') return MAX_DOCUMENT_PREVIEW_BYTES
  if (
    contentType.startsWith('image/') ||
    contentType.startsWith('audio/') ||
    contentType.startsWith('video/') ||
    contentType === 'application/pdf'
  ) {
    return MAX_BINARY_PREVIEW_BYTES
  }
  return MAX_DOCUMENT_PREVIEW_BYTES
}

async function openAndRender(archive: ProtectedArchive, entry: ProtectedEntry): Promise<void> {
  if (entry.directory) return
  const limit = previewLimit(entry.contentType)
  if (entry.size <= limit) {
    const data = await readInlineEntry(await archive.open(entry.path), entry.size, limit)
    renderContent(container, data, await detectContentType(data))
    return
  }

  const media = entry.contentType.startsWith('audio/') || entry.contentType.startsWith('video/')
  if (media) {
    const rendered = await renderProgressiveMedia(container, entry.contentType, () => archive.open(entry.path))
    if (rendered) return
  }

  showSaveEntry(
    container,
    entry,
    () =>
      saveEntry(
        {
          size: entry.size,
          contentType: entry.contentType,
          open: () => archive.open(entry.path),
        },
        entry.path.split('/').at(-1) ?? 'decrypted-content'
      ),
    media
  )
}

async function unlockArchive(cid: string, accessKey: string): Promise<void> {
  const archive = await openProtectedArchive(cid, accessKey)
  await activeArchive?.close()
  activeArchive = archive
  const entries = archive.list()
  if (entries.length === 1 && !entries[0].directory) {
    await openAndRender(archive, entries[0])
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
