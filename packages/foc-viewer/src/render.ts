import { filetypemime } from 'magic-bytes.js'
import { createLockedHtmlFrame } from './sandbox.js'

const activeObjectUrls = new WeakMap<HTMLElement, string[]>()

function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

export function revokeRenderedObjectUrls(container: HTMLElement): void {
  for (const objectUrl of activeObjectUrls.get(container) ?? []) URL.revokeObjectURL(objectUrl)
  activeObjectUrls.delete(container)
}

export async function detectContentType(data: Uint8Array): Promise<string> {
  const mimes = filetypemime(Array.from(data.slice(0, 100)))
  if (mimes.length > 0) return mimes[0]

  const prefix = new TextDecoder().decode(data.slice(0, 15)).trimStart().toLowerCase()
  if (prefix.startsWith('<!doctype') || prefix.startsWith('<html')) return 'text/html'

  try {
    new TextDecoder('utf-8', { fatal: true }).decode(data)
    return 'text/plain'
  } catch {
    return 'application/octet-stream'
  }
}

export function isBinaryPreviewType(contentType: string): boolean {
  return (
    contentType.startsWith('image/') ||
    contentType.startsWith('audio/') ||
    contentType.startsWith('video/') ||
    contentType === 'application/pdf'
  )
}

export function renderContent(
  container: HTMLElement,
  data: Uint8Array,
  contentType: string,
  filename = 'decrypted-content'
): void {
  revokeRenderedObjectUrls(container)
  const blob = new Blob([data as Uint8Array<ArrayBuffer>], { type: contentType })
  const objectUrl = URL.createObjectURL(blob)
  activeObjectUrls.set(container, [objectUrl])

  if (contentType === 'text/html') {
    container.classList.add('wide')
    const wrapper = document.createElement('div')
    wrapper.className = 'content-wrapper'
    wrapper.append(createLockedHtmlFrame(new TextDecoder().decode(data)))
    const download = document.createElement('a')
    download.className = 'download-link'
    download.href = objectUrl
    download.download = filename
    download.textContent = 'Download file'
    wrapper.append(download)
    container.replaceChildren(wrapper)
    return
  }

  if (contentType.startsWith('image/')) {
    container.classList.add('wide')
    container.innerHTML = `
      <div class="content-wrapper">
        <img src="${objectUrl}" alt="Decrypted image" style="max-width:100%;max-height:90vh;display:block;margin:0 auto;" />
        <a class="download-link" href="${objectUrl}" download="${escapeHtml(filename)}" style="display:block;text-align:center;">Download image</a>
      </div>
    `
    return
  }

  if (contentType.startsWith('audio/') || contentType.startsWith('video/')) {
    const tag = contentType.startsWith('audio/') ? 'audio' : 'video'
    container.classList.add('wide')
    container.innerHTML = `
      <div class="content-wrapper">
        <${tag} controls preload="metadata" src="${objectUrl}"></${tag}>
        <a class="download-link" href="${objectUrl}" download="${escapeHtml(filename)}">Download media</a>
      </div>
    `
    return
  }

  if (contentType === 'application/pdf') {
    container.innerHTML = `
      <div class="content-wrapper">
        <embed src="${objectUrl}" type="application/pdf" width="100%" height="600px" />
        <a class="download-link" href="${objectUrl}" download="${escapeHtml(filename)}">Download PDF</a>
      </div>
    `
    return
  }

  if (contentType === 'text/plain') {
    const text = new TextDecoder().decode(data)
    container.innerHTML = `
      <div class="content-wrapper">
        <pre>${escapeHtml(text)}</pre>
        <a class="download-link" href="${objectUrl}" download="${escapeHtml(filename)}">Download text</a>
      </div>
    `
    return
  }

  container.innerHTML = `
    <div class="content-wrapper">
      <p>Content decrypted successfully (${escapeHtml(contentType)}).</p>
      <a class="download-link" href="${objectUrl}" download="${escapeHtml(filename)}">Download file</a>
    </div>
  `
}

