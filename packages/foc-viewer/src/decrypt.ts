export const MAX_DOCUMENT_PREVIEW_BYTES = 8 * 1024 * 1024
export const MAX_BINARY_PREVIEW_BYTES = 256 * 1024 * 1024

export async function readInlineEntry(
  stream: ReadableStream<Uint8Array>,
  expectedSize: number,
  maxBytes = MAX_DOCUMENT_PREVIEW_BYTES
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

export async function readEntryPrefix(
  stream: ReadableStream<Uint8Array>,
  maxBytes = 100
): Promise<Uint8Array> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new Error('Invalid prefix size')
  const output = new Uint8Array(maxBytes)
  const reader = stream.getReader()
  let offset = 0
  try {
    while (offset < maxBytes) {
      const { done, value } = await reader.read()
      if (done) return output.slice(0, offset)
      const length = Math.min(value.length, maxBytes - offset)
      output.set(value.subarray(0, length), offset)
      offset += length
    }
    return output
  } finally {
    await reader.cancel().catch(() => undefined)
    reader.releaseLock()
  }
}
