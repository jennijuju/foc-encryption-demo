import { BlobWriter, Uint8ArrayReader, ZipWriter, configure } from '@zip.js/zip.js'
import { MAX_BINARY_PREVIEW_BYTES, MAX_DOCUMENT_PREVIEW_BYTES, readInlineEntry } from './decrypt.js'

export interface SaveableEntry {
  readonly size: number
  readonly contentType: string
  open(): Promise<ReadableStream<Uint8Array>>
}

interface SaveFileHandle {
  createWritable(): Promise<WritableStream<Uint8Array>>
}

interface SaveDirectoryHandle {
  getDirectoryHandle(name: string, options?: { create?: boolean }): Promise<SaveDirectoryHandle>
  getFileHandle(name: string, options?: { create?: boolean }): Promise<SaveFileHandle>
}

interface SavePickerHost {
  showSaveFilePicker?: (options: { suggestedName: string }) => Promise<SaveFileHandle>
  showDirectoryPicker?: (options?: { mode?: 'readwrite'; startIn?: 'documents' }) => Promise<SaveDirectoryHandle>
}

export async function saveEntry(entry: SaveableEntry, suggestedName: string): Promise<'saved' | 'unsupported'> {
  const picker = (globalThis as typeof globalThis & SavePickerHost).showSaveFilePicker
  if (picker) {
    const handle = await picker({ suggestedName })
    await (await entry.open()).pipeTo(await handle.createWritable())
    return 'saved'
  }

  if (entry.size > MAX_DOCUMENT_PREVIEW_BYTES) return 'unsupported'

  const data = await readInlineEntry(await entry.open(), entry.size)
  const objectUrl = URL.createObjectURL(new Blob([data as Uint8Array<ArrayBuffer>], { type: entry.contentType }))
  const link = document.createElement('a')
  link.href = objectUrl
  link.download = suggestedName
  link.hidden = true
  document.body.append(link)
  try {
    link.click()
  } finally {
    link.remove()
    URL.revokeObjectURL(objectUrl)
  }
  return 'saved'
}

export interface ZippableEntry {
  readonly path: string
  readonly directory: boolean
  readonly size: number
}

export async function saveArchiveFolder(
  entries: readonly ZippableEntry[],
  openEntry: (path: string) => Promise<ReadableStream<Uint8Array>>,
  folderName: string
): Promise<'saved' | 'unsupported' | 'cancelled'> {
  const files = entries.filter((entry) => !entry.directory)
  const host = globalThis as typeof globalThis & SavePickerHost

  if (host.showDirectoryPicker) {
    let destination: SaveDirectoryHandle
    try {
      destination = await host.showDirectoryPicker({ mode: 'readwrite', startIn: 'documents' })
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return 'cancelled'
      throw error
    }
    const root = await destination.getDirectoryHandle(folderName, { create: true })
    for (const file of files) {
      const segments = file.path.split('/')
      let directory = root
      for (const segment of segments.slice(0, -1)) {
        directory = await directory.getDirectoryHandle(segment, { create: true })
      }
      const handle = await directory.getFileHandle(segments.at(-1) ?? file.path, { create: true })
      await (await openEntry(file.path)).pipeTo(await handle.createWritable())
    }
    return 'saved'
  }

  // Fallback: one in-memory zip. Entries are buffered so zip.js knows size and
  // CRC before writing each local header (dataDescriptor: false) — streamed
  // entries would force data-descriptor/Zip64 records, which macOS Archive
  // Utility rejects as an unsupported format.
  const totalBytes = files.reduce((total, file) => total + file.size, 0)
  if (totalBytes > MAX_BINARY_PREVIEW_BYTES) return 'unsupported'

  // The page CSP has no worker-src, so zip.js blob workers can never start.
  configure({ useWebWorkers: false })
  const zipWriter = new ZipWriter(new BlobWriter('application/zip'), { level: 0, dataDescriptor: false })
  for (const file of files) {
    const data = await readInlineEntry(await openEntry(file.path), file.size, MAX_BINARY_PREVIEW_BYTES)
    await zipWriter.add(file.path, new Uint8ArrayReader(data))
  }
  const blob = await zipWriter.close()
  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = objectUrl
  link.download = `${folderName}.zip`
  link.hidden = true
  document.body.append(link)
  try {
    link.click()
  } finally {
    link.remove()
    URL.revokeObjectURL(objectUrl)
  }
  return 'saved'
}
