import { describe, expect, it, vi } from 'vitest'
import { readEntryPrefix } from '../src/decrypt.js'

function streamFrom(...chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk)
      controller.close()
    },
  })
}

describe('readEntryPrefix', () => {
  it('returns only the bounded prefix across chunks', async () => {
    await expect(
      readEntryPrefix(streamFrom(new Uint8Array([1, 2]), new Uint8Array([3, 4, 5])), 4)
    ).resolves.toEqual(new Uint8Array([1, 2, 3, 4]))
  })

  it('cancels a source after the prefix is read', async () => {
    const cancel = vi.fn()
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3, 4]))
      },
      cancel,
    })

    await readEntryPrefix(stream, 2)

    expect(cancel).toHaveBeenCalledOnce()
  })
})
