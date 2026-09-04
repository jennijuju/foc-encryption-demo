import type { ProtectedEntry } from './protected-archive.js'

const PASSWORD_ERROR = 'That password could not decrypt this share. Check all six words and try again.'
const LOAD_ERROR = 'This share could not be loaded yet. It may still be propagating; try again shortly.'

export function unlockErrorMessage(cause: unknown): string {
  if (
    cause instanceof Error &&
    (cause.name === 'AuthenticationError' ||
      cause.message.includes('AEAD authentication failed') ||
      cause.message === 'Wrong password')
  ) {
    return PASSWORD_ERROR
  }
  return LOAD_ERROR
}

export function showPasswordPrompt(container: HTMLElement, onSubmit: (password: string) => Promise<void>): void {
  container.innerHTML = `
    <div class="evidence-gate">
      <section class="evidence">
        <p class="eyebrow">Password-protected share</p>
        <h1>Protected without an account.</h1>
        <p>This page fetches public ciphertext and decrypts it only after you enter the password.</p>
        <ul>
          <li>Viewer code is fixed by its CID</li>
          <li>Password stays in this browser tab</li>
          <li>Content cannot make network requests</li>
        </ul>
      </section>
      <form class="password-form">
        <label for="pw-input">Password</label>
        <div class="password-input">
          <input type="password" id="pw-input" autocomplete="off" placeholder="Six words" />
          <button class="password-toggle" id="password-toggle" type="button" aria-label="Show password" aria-pressed="false">
            <span aria-hidden="true">👁</span>
          </button>
        </div>
        <button class="btn-primary" id="view-btn" type="submit">Unlock</button>
        <p class="hint">The password is never added to this address.</p>
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
    passwordToggle.setAttribute('aria-label', showPassword ? 'Hide password' : 'Show password')
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
      error.textContent = 'Enter the password you received from the sender.'
      error.hidden = false
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
      if (error.textContent === PASSWORD_ERROR) passwordInput.select()
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

function appendArchiveTree(
  parent: HTMLElement,
  nodes: Map<string, ArchiveTreeNode>,
  onSelect: (entry: ProtectedEntry) => Promise<void>,
  error: HTMLParagraphElement
): void {
  const list = document.createElement('ul')
  const sortedNodes = [...nodes.values()].sort((left, right) => left.name.localeCompare(right.name))
  for (const node of sortedNodes) {
    const item = document.createElement('li')
    const isDirectory = node.children.size > 0 || node.entry?.directory === true
    if (isDirectory) {
      const label = document.createElement('span')
      label.textContent = node.name
      item.append(label)
      appendArchiveTree(item, node.children, onSelect, error)
    } else if (node.entry) {
      const button = document.createElement('button')
      button.type = 'button'
      button.textContent = node.name
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
  onSelect: (entry: ProtectedEntry) => Promise<void>
): void {
  container.innerHTML = `
    <div class="content-wrapper">
      <p class="eyebrow">Password-protected share</p>
      <h1>${entries.length === 1 && !entries[0]?.directory ? 'Ready to open.' : 'Choose a file.'}</h1>
      <div id="archive-tree" aria-label="Protected files"></div>
      <p class="error" id="archive-error" role="alert" hidden></p>
    </div>
  `

  const tree = container.querySelector('#archive-tree') as HTMLDivElement
  const error = container.querySelector('#archive-error') as HTMLParagraphElement
  if (entries.length === 0) {
    tree.textContent = 'This protected folder is empty.'
    return
  }
  appendArchiveTree(tree, buildArchiveTree(entries), onSelect, error)
}

export function showSaveEntry(
  container: HTMLElement,
  entry: ProtectedEntry,
  onSave: () => Promise<'saved' | 'unsupported'>
): void {
  container.innerHTML = `
    <div class="content-wrapper">
      <p class="eyebrow">Password-protected share</p>
      <h1>Ready to save.</h1>
      <p id="save-entry-name"></p>
      <button class="btn-primary" id="save-entry" type="button">Save file</button>
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
        error.textContent = 'This browser cannot save large files without holding them in memory.'
        error.hidden = false
      } else {
        status.textContent = 'Saved.'
      }
    } catch {
      error.textContent = 'This file could not be saved.'
      error.hidden = false
    } finally {
      button.disabled = false
      button.textContent = 'Save file'
    }
  })
}
