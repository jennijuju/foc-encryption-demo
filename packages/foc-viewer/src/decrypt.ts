export const MAX_INLINE_ENTRY_BYTES = 16 * 1024 * 1024
export const MAX_BUFFERED_MEDIA_BYTES = 64 * 1024 * 1024

export async function readInlineEntry(
  stream: ReadableStream<Uint8Array>,
  expectedSize: number,
  maxBytes = MAX_INLINE_ENTRY_BYTES
): Promise<Uint8Array> {
  if (!Number.isSafeInteger(expectedSize) || expectedSize < 0) {
    throw new Error('Entry has an invalid size')
  }
  if (expectedSize > maxBytes) {
    throw new Error('This entry is too large to preview in this browser.')
  }

  const output = new Uint8Array(expectedSize)
  const reader = stream.getReader()
  let offset = 0
  while (offset < expectedSize) {
    const { done, value } = await reader.read()
    if (done) throw new Error('Entry ended before its declared size')
    if (value.length > expectedSize - offset) {
      await reader.cancel()
      throw new Error('Entry exceeded its declared size')
    }
    output.set(value, offset)
    offset += value.length
  }

  const trailing = await reader.read()
  if (!trailing.done) {
    await reader.cancel()
    throw new Error('Entry exceeded its declared size')
  }
  return output
}
