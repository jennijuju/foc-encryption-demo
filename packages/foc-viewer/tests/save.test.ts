import { afterEach, describe, expect, it, vi } from 'vitest'
import { MAX_INLINE_ENTRY_BYTES } from '../src/decrypt.js'
import { saveEntry } from '../src/save.js'

function byteStream(...chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk)
      controller.close()
    },
  })
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('saveEntry', () => {
  it('pipes a large entry directly into the Chromium file writer', async () => {
    const written: number[] = []
    const writable = new WritableStream<Uint8Array>({
      write(chunk) {
        written.push(...chunk)
      },
    })
    const createWritable = vi.fn(async () => writable)
    const picker = vi.fn(async () => ({ createWritable }))
    vi.stubGlobal('showSaveFilePicker', picker)
    const open = vi.fn(async () => byteStream(new Uint8Array([1, 2]), new Uint8Array([3, 4])))

    await expect(
      saveEntry({ size: MAX_INLINE_ENTRY_BYTES + 1, contentType: 'application/octet-stream', open }, 'archive.bin')
    ).resolves.toBe('saved')

    expect(picker).toHaveBeenCalledWith({ suggestedName: 'archive.bin' })
    expect(createWritable).toHaveBeenCalledOnce()
    expect(open).toHaveBeenCalledOnce()
    expect(written).toEqual([1, 2, 3, 4])
  })

  it('does not open or buffer a large entry without the file picker API', async () => {
    vi.stubGlobal('showSaveFilePicker', undefined)
    const open = vi.fn(async () => byteStream(new Uint8Array([1])))

    await expect(
      saveEntry({ size: MAX_INLINE_ENTRY_BYTES + 1, contentType: 'application/octet-stream', open }, 'archive.bin')
    ).resolves.toBe('unsupported')
    expect(open).not.toHaveBeenCalled()
  })

  it('revokes the bounded fallback download URL', async () => {
    vi.stubGlobal('showSaveFilePicker', undefined)
    const click = vi.fn()
    const remove = vi.fn()
    const append = vi.fn()
    const link = { href: '', download: '', hidden: false, click, remove }
    vi.stubGlobal('document', {
      createElement: () => link as unknown as HTMLAnchorElement,
      body: { append },
    })
    const createObjectURL = vi.fn(() => 'blob:bounded-entry')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', { createObjectURL, revokeObjectURL })

    const open = vi.fn(async () => byteStream(new Uint8Array([7, 8, 9])))
    await expect(saveEntry({ size: 3, contentType: 'image/png', open }, 'small.png')).resolves.toBe('saved')

    expect(click).toHaveBeenCalledOnce()
    expect(remove).toHaveBeenCalledOnce()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:bounded-entry')
  })
})
