import type { ProtectedEntry } from './protected-archive.js'

const MARK_URL = new URL('../assets/engram-mark.png', import.meta.url).href
const WASH_URL = new URL('../assets/engram-wash.png', import.meta.url).href

const ACCESS_KEY_ERROR = 'That access key could not decrypt this share. Check it and try again.'
const LOAD_ERROR = 'This share could not be loaded yet. It may still be propagating; try again shortly.'
const ACCESS_KEY_PATTERN = /^engram_[A-Za-z0-9_-]{43}$/

export function unlockErrorMessage(cause: unknown): string {
  if (
    cause instanceof Error &&
    (cause.name === 'AuthenticationError' ||
      cause.message.includes('AEAD authentication failed') ||
      cause.message === 'Wrong password')
  ) {
    return ACCESS_KEY_ERROR
  }
  return LOAD_ERROR
}

export function isValidAccessKey(value: string): boolean {
  return ACCESS_KEY_PATTERN.test(value)
}

export function showAccessKeyPrompt(container: HTMLElement, onSubmit: (accessKey: string) => Promise<void>): void {
  container.innerHTML = `
    <div class="evidence-gate">
      <section class="evidence">
        <p class="eyebrow">Password-protected share</p>
        <h1>Share only what you choose.</h1>
        <p>This content stays encrypted while it is stored and shared. Paste the access key to open it here.</p>
        <ul>
          <li>Decryption happens in your browser</li>
          <li>This page cannot change behind the link</li>
        </ul>
      </section>
      <form class="password-form">
        <img class="engram-corner-wash" src="${WASH_URL}" alt="" />
        <img class="engram-corner-mark" src="${MARK_URL}" alt="" />
        <div class="form-heading">
          <p class="form-kicker">Open protected content</p>
          <h2>Unlock this share</h2>
          <p>Use the access key the sender gave you separately.</p>
        </div>
        <label for="pw-input">Access key</label>
        <div class="password-input">
          <input type="password" id="pw-input" autocomplete="off" autocapitalize="none" spellcheck="false" maxlength="50" placeholder="Paste access key" />
          <button class="password-toggle" id="password-toggle" type="button" aria-label="Show access key" aria-pressed="false">
            <svg aria-hidden="true" viewBox="0 0 24 24" fill="none">
              <path d="M2.7 12s3.4-5.2 9.3-5.2S21.3 12 21.3 12s-3.4 5.2-9.3 5.2S2.7 12 2.7 12Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round" />
              <circle cx="12" cy="12" r="2.6" stroke="currentColor" stroke-width="1.7" />
            </svg>
          </button>
        </div>
        <button class="btn-primary" id="view-btn" type="submit">Unlock</button>
        <p class="hint">Only someone with the access key can unlock this share.</p>
        <p class="error" id="error" role="alert" hidden></p>
      </form>
    </div>
  `

  const form = container.querySelector('form') as HTMLFormElement
  const passwordInput = container.querySelector('#pw-input') as HTMLInputElement
  const button = container.querySelector('#view-btn') as HTMLButtonElement
  const passwordToggle = container.querySelector('#password-toggle') as HTMLButtonElement
  const error = container.querySelector('#error') as HTMLParagraphElement
  passwordInput.focus()

  passwordToggle.addEventListener('click', () => {
    const showPassword = passwordInput.type === 'password'
    const { selectionStart, selectionEnd } = passwordInput
    passwordInput.type = showPassword ? 'text' : 'password'
    passwordToggle.setAttribute('aria-label', showPassword ? 'Hide access key' : 'Show access key')
    passwordToggle.setAttribute('aria-pressed', String(showPassword))
    passwordInput.focus()
    if (selectionStart !== null && selectionEnd !== null) {
      passwordInput.setSelectionRange(selectionStart, selectionEnd)
    }
  })

  form.addEventListener('submit', async (event) => {
    event.preventDefault()
    if (button.disabled) return

    if (!passwordInput.value) {
      error.textContent = 'Paste the access key you received from the sender.'
      error.hidden = false
      return
    }
    if (!isValidAccessKey(passwordInput.value)) {
      error.textContent = 'Paste a valid 50-character Engram access key.'
      error.hidden = false
      passwordInput.select()
      return
    }

    button.disabled = true
    button.textContent = 'Decrypting…'
    error.hidden = true
    try {
      await onSubmit(passwordInput.value)
    } catch (cause) {
      error.textContent = unlockErrorMessage(cause)
      error.hidden = false
      if (error.textContent === ACCESS_KEY_ERROR) passwordInput.select()
    } finally {
      button.disabled = false
      button.textContent = 'Unlock'
    }
  })
}

export function showMissingLink(container: HTMLElement): void {
  container.innerHTML = `
    <div class="missing-link">
      <p class="eyebrow">Password-protected share</p>
      <h1>This link is incomplete.</h1>
      <p>Ask the sender for the full protected-share link and open it again.</p>
    </div>
  `
}

interface ArchiveTreeNode {
  name: string
  entry?: ProtectedEntry
  children: Map<string, ArchiveTreeNode>
}

function buildArchiveTree(entries: readonly ProtectedEntry[]): Map<string, ArchiveTreeNode> {
  const roots = new Map<string, ArchiveTreeNode>()
  for (const entry of entries) {
    const path = entry.directory ? entry.path.slice(0, -1) : entry.path
    const segments = path.split('/')
    let level = roots
    for (const [index, segment] of segments.entries()) {
      let node = level.get(segment)
      if (!node) {
        node = { name: segment, children: new Map() }
        level.set(segment, node)
      }
      if (index === segments.length - 1) node.entry = entry
      level = node.children
    }
  }
  return roots
}

const CHEVRON_SVG =
  '<svg class="chevron" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 4l4 4-4 4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>'
const FOLDER_SVG =
  '<svg class="row-icon folder" viewBox="0 0 20 20" aria-hidden="true"><path d="M2.5 5.5A1.5 1.5 0 0 1 4 4h4l1.6 1.8H16a1.5 1.5 0 0 1 1.5 1.5v7.2A1.5 1.5 0 0 1 16 16H4a1.5 1.5 0 0 1-1.5-1.5z" fill="currentColor"/></svg>'
const FILE_SVG =
  '<svg class="row-icon" viewBox="0 0 20 20" aria-hidden="true"><path d="M5.5 2.5h6L15.5 6.5v10a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1v-13a1 1 0 0 1 1-1z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M11.5 2.5v4h4" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>'
const IMAGE_SVG =
  '<svg class="row-icon" viewBox="0 0 20 20" aria-hidden="true"><rect x="2.5" y="4" width="15" height="12" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.4"/><circle cx="7" cy="8.5" r="1.4" fill="currentColor"/><path d="M4.5 14.5l3.8-3.6 2.6 2.4 2.7-3 3 4.2" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>'
const MEDIA_SVG =
  '<svg class="row-icon" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="7.25" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M8.5 7.2l4.4 2.8-4.4 2.8z" fill="currentColor"/></svg>'

function iconFor(entry: ProtectedEntry | undefined): string {
  const type = entry?.contentType ?? ''
  if (type.startsWith('image/')) return IMAGE_SVG
  if (type.startsWith('video/') || type.startsWith('audio/')) return MEDIA_SVG
  return FILE_SVG
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return ''
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB']
  let value = bytes
  let unit = 'B'
  for (const next of units) {
    if (value < 1024) break
    value /= 1024
    unit = next
  }
  return `${value >= 100 ? Math.round(value) : value.toFixed(1)} ${unit}`
}

function countFiles(node: ArchiveTreeNode): number {
  let total = node.entry && !node.entry.directory ? 1 : 0
  for (const child of node.children.values()) total += countFiles(child)
  return total
}

function makeRow(iconMarkup: string, name: string, meta: string): DocumentFragment {
  const fragment = document.createDocumentFragment()
  const template = document.createElement('template')
  template.innerHTML = iconMarkup
  fragment.append(template.content)
  const label = document.createElement('span')
  label.className = 'row-name'
  label.textContent = name
  fragment.append(label)
  const detail = document.createElement('span')
  detail.className = 'row-meta'
  detail.textContent = meta
  fragment.append(detail)
  return fragment
}

function appendArchiveTree(
  parent: HTMLElement,
  nodes: Map<string, ArchiveTreeNode>,
  onSelect: (entry: ProtectedEntry) => Promise<void>,
  error: HTMLParagraphElement
): void {
  const list = document.createElement('ul')
  list.className = 'tree-level'
  const sortedNodes = [...nodes.values()].sort((left, right) => {
    const leftDirectory = left.children.size > 0 || left.entry?.directory === true
    const rightDirectory = right.children.size > 0 || right.entry?.directory === true
    if (leftDirectory !== rightDirectory) return leftDirectory ? -1 : 1
    return left.name.localeCompare(right.name)
  })
  for (const node of sortedNodes) {
    const item = document.createElement('li')
    const isDirectory = node.children.size > 0 || node.entry?.directory === true
    if (isDirectory) {
      const details = document.createElement('details')
      details.className = 'tree-dir'
      details.open = true
      const summary = document.createElement('summary')
      summary.className = 'tree-row'
      const files = countFiles(node)
      summary.append(makeRow(CHEVRON_SVG + FOLDER_SVG, node.name, `${files} ${files === 1 ? 'item' : 'items'}`))
      details.append(summary)
      appendArchiveTree(details, node.children, onSelect, error)
      item.append(details)
    } else if (node.entry) {
      const button = document.createElement('button')
      button.type = 'button'
      button.className = 'tree-row tree-file'
      button.append(makeRow(iconFor(node.entry), node.name, formatBytes(node.entry.size)))
      button.addEventListener('click', async () => {
        if (button.disabled || !node.entry) return
        button.disabled = true
        error.hidden = true
        try {
          await onSelect(node.entry)
        } catch {
          error.textContent = 'This file could not be opened.'
          error.hidden = false
        } finally {
          if (button.isConnected) button.disabled = false
        }
      })
      item.append(button)
    }
    list.append(item)
  }
  parent.append(list)
}

export function showProtectedArchive(
  container: HTMLElement,
  entries: readonly ProtectedEntry[],
  onSelect: (entry: ProtectedEntry) => Promise<void>,
  onDownloadAll?: () => Promise<'saved' | 'unsupported' | 'cancelled'>
): void {
  const files = entries.filter((entry) => !entry.directory)
  const folders = entries.length - files.length
  const totalBytes = files.reduce((total, entry) => total + entry.size, 0)
  const singleFile = entries.length === 1 && !entries[0]?.directory
  const meta = singleFile
    ? ''
    : `${files.length} ${files.length === 1 ? 'file' : 'files'}${folders > 0 ? ` · ${folders} ${folders === 1 ? 'folder' : 'folders'}` : ''} · ${formatBytes(totalBytes)}`
  container.innerHTML = `
    <div class="content-wrapper archive-view">
      <p class="eyebrow">Password-protected share</p>
      <h1>${singleFile ? 'Ready to open.' : 'Shared folder'}</h1>
      <div class="archive-card">
        <div class="archive-toolbar" id="archive-toolbar" hidden>
          <p class="archive-meta" id="archive-meta"></p>
          <button class="download-all" id="download-all" type="button" hidden>Download folder</button>
        </div>
        <div id="archive-tree" role="tree" aria-label="Protected files"></div>
      </div>
      <p class="error" id="archive-error" role="alert" hidden></p>
    </div>
  `

  const toolbar = container.querySelector('#archive-toolbar') as HTMLDivElement
  const metaLine = container.querySelector('#archive-meta') as HTMLParagraphElement
  const error = container.querySelector('#archive-error') as HTMLParagraphElement
  if (meta) {
    metaLine.textContent = meta
    toolbar.hidden = false
  }
  const downloadAll = container.querySelector('#download-all') as HTMLButtonElement
  if (onDownloadAll && files.length > 0 && !singleFile) {
    downloadAll.hidden = false
    downloadAll.addEventListener('click', async () => {
      if (downloadAll.disabled) return
      downloadAll.disabled = true
      downloadAll.textContent = 'Preparing download…'
      error.hidden = true
      try {
        const result = await onDownloadAll()
        if (result === 'unsupported') {
          error.textContent = 'This folder is too large to download here; open the link in Chromium.'
          error.hidden = false
        }
      } catch {
        error.textContent = 'The folder could not be downloaded.'
        error.hidden = false
      } finally {
        downloadAll.disabled = false
        downloadAll.textContent = 'Download folder'
      }
    })
  }
  const tree = container.querySelector('#archive-tree') as HTMLDivElement
  if (entries.length === 0) {
    tree.textContent = 'This protected folder is empty.'
    return
  }
  appendArchiveTree(tree, buildArchiveTree(entries), onSelect, error)
}

export function showSaveEntry(
  container: HTMLElement,
  entry: ProtectedEntry,
  onSave: () => Promise<'saved' | 'unsupported'>,
  previewFailed = false
): void {
  const actionLabel = previewFailed ? 'Download instead' : 'Download file'
  container.innerHTML = `
    <div class="content-wrapper">
      <p class="eyebrow">Password-protected share</p>
      <h1>${previewFailed ? 'Preview unavailable.' : 'Ready to download.'}</h1>
      <p id="save-entry-name"></p>
      <button class="btn-primary" id="save-entry" type="button">${actionLabel}</button>
      <p class="hint" id="save-status" role="status"></p>
      <p class="error" id="save-error" role="alert" hidden></p>
    </div>
  `

  const name = container.querySelector('#save-entry-name') as HTMLParagraphElement
  const button = container.querySelector('#save-entry') as HTMLButtonElement
  const status = container.querySelector('#save-status') as HTMLParagraphElement
  const error = container.querySelector('#save-error') as HTMLParagraphElement
  name.textContent = entry.path
  button.addEventListener('click', async () => {
    if (button.disabled) return
    button.disabled = true
    button.textContent = 'Saving…'
    error.hidden = true
    status.textContent = ''
    try {
      const result = await onSave()
      if (result === 'unsupported') {
        error.textContent = 'Open this protected link in Chromium to download a file this large.'
        error.hidden = false
      } else {
        status.textContent = 'Saved.'
      }
    } catch {
      error.textContent = 'This file could not be saved.'
      error.hidden = false
    } finally {
      button.disabled = false
      button.textContent = actionLabel
    }
  })
}
