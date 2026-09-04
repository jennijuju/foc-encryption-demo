import { MAX_INLINE_ENTRY_BYTES, readInlineEntry } from './decrypt.js'

export interface SaveableEntry {
  readonly size: number
  readonly contentType: string
  open(): Promise<ReadableStream<Uint8Array>>
}

interface SaveFileHandle {
  createWritable(): Promise<WritableStream<Uint8Array>>
}

interface SavePickerHost {
  showSaveFilePicker?: (options: { suggestedName: string }) => Promise<SaveFileHandle>
}

export async function saveEntry(entry: SaveableEntry, suggestedName: string): Promise<'saved' | 'unsupported'> {
  const picker = (globalThis as typeof globalThis & SavePickerHost).showSaveFilePicker
  if (picker) {
    const handle = await picker({ suggestedName })
    await (await entry.open()).pipeTo(await handle.createWritable())
    return 'saved'
  }

  if (entry.size > MAX_INLINE_ENTRY_BYTES) return 'unsupported'

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
