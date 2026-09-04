import type { BlobFetcher } from './types.js'

const CONTENT_RANGE = /^bytes (\d+)-(\d+)\/(\d+)$/
const MAX_RANGE_LENGTH = 16 * 1024 * 1024 + 16

async function readBoundedBody(response: Response, expectedLength: number): Promise<Uint8Array> {
  if (!response.body) throw new Error('Gateway returned an empty range body')
  const contentLength = response.headers.get('Content-Length')
  if (contentLength !== null && Number(contentLength) > expectedLength) {
    throw new Error('Gateway returned a body larger than requested')
  }

  const output = new Uint8Array(expectedLength)
  const reader = response.body.getReader()
  let offset = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (offset + value.length > expectedLength) {
        throw new Error('Gateway returned a body larger than requested')
      }
      output.set(value, offset)
      offset += value.length
    }
  } catch (error) {
    await reader.cancel(error).catch(() => undefined)
    throw error
  } finally {
    reader.releaseLock()
  }
  if (offset !== expectedLength) throw new Error('Gateway returned an incomplete range body')
  return output
}

export function createHttpBlobFetcher(url: string, fetchFn: typeof fetch = fetch): BlobFetcher {
  let totalSize: number | undefined
  async function readRange(offset: number, length: number): Promise<Uint8Array> {
    if (
      !Number.isSafeInteger(offset) ||
      offset < 0 ||
      !Number.isSafeInteger(length) ||
      length <= 0 ||
      length > MAX_RANGE_LENGTH
    ) {
      throw new Error('Invalid byte range')
    }

    const requestedEnd = offset + length - 1
    if (!Number.isSafeInteger(requestedEnd)) {
      throw new Error('Invalid byte range')
    }
    if (totalSize !== undefined && offset >= totalSize) return new Uint8Array()
    const end = totalSize === undefined ? requestedEnd : Math.min(requestedEnd, totalSize - 1)

    const response = await fetchFn(url, { headers: { Range: `bytes=${offset}-${end}` } })
    if (response.status !== 206) {
      throw new Error('Gateway does not support byte-range retrieval')
    }

    const match = CONTENT_RANGE.exec(response.headers.get('Content-Range') ?? '')
    if (!match) throw new Error('Gateway returned an invalid Content-Range')
    const responseStart = Number(match[1])
    const responseEnd = Number(match[2])
    const total = Number(match[3])
    if (totalSize !== undefined && total !== totalSize) {
      throw new Error('Gateway returned an inconsistent total size')
    }
    totalSize = total
    if (responseStart !== offset || responseEnd < responseStart || responseEnd > end || total <= responseEnd) {
      throw new Error('Gateway returned an invalid Content-Range')
    }
    return readBoundedBody(response, responseEnd - responseStart + 1)
  }

  async function getSize(): Promise<number> {
    if (totalSize === undefined) await readRange(0, 1)
    if (totalSize === undefined) throw new Error('Gateway did not report total size')
    return totalSize
  }

  return {
    getSize,
    fetchRange: readRange,
  }
}
