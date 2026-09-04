import type { ProtectedArchive, ProtectedEntry } from './protected-archive.js'
import { MAX_INLINE_ENTRY_BYTES, readInlineEntry } from './decrypt.js'
import { parseFragment } from './fragment.js'
import { openProtectedArchive } from './protected-archive.js'
import { detectContentType, renderContent, renderProgressiveMedia } from './render.js'
import { saveEntry } from './save.js'
import { showMissingLink, showPasswordPrompt, showProtectedArchive, showSaveEntry } from './ui.js'

function getContainer(): HTMLElement {
  const element = document.getElementById('app')
  if (!element) throw new Error('Viewer root is missing')
  return element
}

const container = getContainer()

async function openAndRender(archive: ProtectedArchive, entry: ProtectedEntry): Promise<void> {
  if (entry.directory) return
  if (entry.size > MAX_INLINE_ENTRY_BYTES) {
    const rendered = await renderProgressiveMedia(container, entry.contentType, () => archive.open(entry.path))
    if (rendered) return

    showSaveEntry(container, entry, () =>
      saveEntry(
        {
          size: entry.size,
          contentType: entry.contentType,
          open: () => archive.open(entry.path),
        },
        entry.path.split('/').at(-1) ?? 'decrypted-content'
      )
    )
    return
  }

  const data = await readInlineEntry(await archive.open(entry.path), entry.size)
  renderContent(container, data, await detectContentType(data))
}

async function unlockArchive(cid: string, password: string): Promise<void> {
  const archive = await openProtectedArchive(cid, password)
  showProtectedArchive(container, archive.list(), (entry) => openAndRender(archive, entry))
}

function init(): void {
  const fragment = parseFragment(window.location.hash)
  if (!fragment) {
    showMissingLink(container)
    return
  }

  showPasswordPrompt(container, (password) => unlockArchive(fragment.cid, password))
}

init()
