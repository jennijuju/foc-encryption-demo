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

export function renderContent(container: HTMLElement, data: Uint8Array, contentType: string): void {
  revokeRenderedObjectUrls(container)
  if (contentType === 'text/html') {
    container.replaceChildren(createLockedHtmlFrame(new TextDecoder().decode(data)))
    return
  }

  const blob = new Blob([data as Uint8Array<ArrayBuffer>], { type: contentType })
  const objectUrl = URL.createObjectURL(blob)
  activeObjectUrls.set(container, [objectUrl])
  const filename = 'decrypted-content'

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

  if (contentType === 'application/pdf') {
    container.innerHTML = `
      <div class="content-wrapper">
        <embed src="${objectUrl}" type="application/pdf" width="100%" height="600px" />
        <a class="download-link" href="${objectUrl}" download="${escapeHtml(filename)}.pdf">Download PDF</a>
      </div>
    `
    return
  }

  if (contentType === 'text/plain') {
    const text = new TextDecoder().decode(data)
    container.innerHTML = `
      <div class="content-wrapper">
        <pre>${escapeHtml(text)}</pre>
        <a class="download-link" href="${objectUrl}" download="${escapeHtml(filename)}.txt">Download text</a>
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

export function supportsProgressiveMedia(contentType: string): boolean {
  if (!contentType.startsWith('audio/') && !contentType.startsWith('video/')) return false
  if (typeof MediaSource === 'undefined') return false
  try {
    return MediaSource.isTypeSupported(contentType)
  } catch {
    return false
  }
}

function appendMediaChunk(sourceBuffer: SourceBuffer, chunk: Uint8Array): Promise<void> {
  const { promise, resolve, reject } = Promise.withResolvers<void>()
  const cleanup = () => {
    sourceBuffer.removeEventListener('updateend', handleUpdate)
    sourceBuffer.removeEventListener('error', handleError)
  }
  const handleUpdate = () => {
    cleanup()
    resolve()
  }
  const handleError = () => {
    cleanup()
    reject(new Error('Media buffer rejected decrypted data'))
  }

  sourceBuffer.addEventListener('updateend', handleUpdate, { once: true })
  sourceBuffer.addEventListener('error', handleError, { once: true })
  try {
    sourceBuffer.appendBuffer(Uint8Array.from(chunk).buffer)
  } catch (error) {
    cleanup()
    reject(error)
  }
  return promise
}

export async function renderProgressiveMedia(
  container: HTMLElement,
  contentType: string,
  open: () => Promise<ReadableStream<Uint8Array>>
): Promise<boolean> {
  if (!supportsProgressiveMedia(contentType)) return false

  revokeRenderedObjectUrls(container)
  const mediaSource = new MediaSource()
  const objectUrl = URL.createObjectURL(mediaSource)
  const media = document.createElement(contentType.startsWith('audio/') ? 'audio' : 'video')
  media.controls = true
  media.src = objectUrl
  const wrapper = document.createElement('div')
  wrapper.className = 'content-wrapper'
  wrapper.append(media)
  container.replaceChildren(wrapper)

  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined
  try {
    const { promise, resolve, reject } = Promise.withResolvers<void>()
    mediaSource.addEventListener('sourceopen', () => resolve(), { once: true })
    mediaSource.addEventListener('sourceclose', () => reject(new Error('Media source closed')), { once: true })
    await promise

    const sourceBuffer = mediaSource.addSourceBuffer(contentType)
    reader = (await open()).getReader()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (value.length) await appendMediaChunk(sourceBuffer, value)
    }
    if (mediaSource.readyState === 'open') mediaSource.endOfStream()
    return true
  } catch {
    await reader?.cancel().catch(() => undefined)
    media.removeAttribute('src')
    media.load()
    container.replaceChildren()
    return false
  } finally {
    URL.revokeObjectURL(objectUrl)
  }
}
