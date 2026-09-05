import { describe, expect, it, vi } from 'vitest'
import { createHttpBlobFetcher } from '../../src/http-fetcher.js'

const bytes = new Uint8Array([1, 2, 3])

function partialResponse(start = 0, body = bytes, total = 10): Response {
  const end = start + body.length - 1
  return new Response(body, {
    status: 206,
    headers: {
      'Content-Length': String(body.length),
      'Content-Range': `bytes ${start}-${end}/${total}`,
    },
  })
}

describe('createHttpBlobFetcher', () => {
  it('fetches total size and ciphertext with byte ranges', async () => {
    const fetchFn = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
      const range = new Headers(init?.headers).get('Range')
      if (range === 'bytes=0-0') return partialResponse(0, bytes.slice(0, 1))
      return partialResponse(7)
    }) as unknown as typeof fetch
    const fetcher = createHttpBlobFetcher('https://example.test/blob', fetchFn)

    await expect(fetcher.getSize()).resolves.toBe(10)
    await expect(fetcher.fetchRange(7, 3)).resolves.toEqual(bytes)

    expect(fetchFn).toHaveBeenNthCalledWith(1, 'https://example.test/blob', {
      headers: { Range: 'bytes=0-0' },
      redirect: 'error',
    })
    expect(fetchFn).toHaveBeenNthCalledWith(2, 'https://example.test/blob', {
      headers: { Range: 'bytes=7-9' },
      redirect: 'error',
    })
  })

  it('clamps later ranges to the learned total size', async () => {
    const fetchFn = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
      const range = new Headers(init?.headers).get('Range')
      if (range === 'bytes=0-0') return partialResponse(0, bytes.slice(0, 1))
      return partialResponse(7)
    }) as unknown as typeof fetch
    const fetcher = createHttpBlobFetcher('https://example.test/blob', fetchFn)

    await fetcher.getSize()
    await expect(fetcher.fetchRange(7, 100)).resolves.toEqual(bytes)

    expect(fetchFn).toHaveBeenNthCalledWith(2, 'https://example.test/blob', {
      headers: { Range: 'bytes=7-9' },
      redirect: 'error',
    })
  })

  it('rejects reads past the end of the object without fetching', async () => {
    const fetchFn = vi.fn(async () => partialResponse(0, bytes.slice(0, 1))) as unknown as typeof fetch
    const fetcher = createHttpBlobFetcher('https://example.test/blob', fetchFn)

    await expect(fetcher.getSize()).resolves.toBe(10)
    await expect(fetcher.fetchRange(10, 1)).rejects.toThrow('Invalid byte range: offset is past the end of the object')

    expect(fetchFn).toHaveBeenCalledTimes(1)
  })

  it('rejects gateways that ignore range requests', async () => {
    const fetchFn = vi.fn(async () => new Response(bytes, { status: 200 })) as unknown as typeof fetch
    const fetcher = createHttpBlobFetcher('https://example.test/blob', fetchFn)

    await expect(fetcher.getSize()).rejects.toThrow('Gateway does not support byte-range retrieval')
  })

  it('rejects a mismatched Content-Range', async () => {
    const fetchFn = vi.fn(async () => partialResponse()) as unknown as typeof fetch
    const fetcher = createHttpBlobFetcher('https://example.test/blob', fetchFn)

    await expect(fetcher.fetchRange(7, 3)).rejects.toThrow('invalid Content-Range')
  })

  it('rejects a response body larger than the requested range', async () => {
    const oversized = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2]))
        controller.enqueue(new Uint8Array([3, 4]))
        controller.close()
      },
    })
    const fetchFn = vi.fn(
      async () =>
        new Response(oversized, {
          status: 206,
          headers: { 'Content-Range': 'bytes 7-9/10' },
        })
    ) as unknown as typeof fetch
    const fetcher = createHttpBlobFetcher('https://example.test/blob', fetchFn)

    await expect(fetcher.fetchRange(7, 3)).rejects.toThrow('larger than requested')
  })

  it('rejects truncated and unsafe Content-Range values', async () => {
    const truncated = vi.fn(async () => partialResponse(7, new Uint8Array([1, 2]), 10)) as unknown as typeof fetch
    await expect(createHttpBlobFetcher('https://example.test/blob', truncated).fetchRange(7, 3)).rejects.toThrow(
      'invalid Content-Range'
    )

    const unsafeTotal = vi.fn(
      async () =>
        new Response(new Uint8Array([1]), {
          status: 206,
          headers: { 'Content-Range': `bytes 0-0/${Number.MAX_SAFE_INTEGER + 1}` },
        })
    ) as unknown as typeof fetch
    await expect(createHttpBlobFetcher('https://example.test/blob', unsafeTotal).getSize()).rejects.toThrow(
      'invalid Content-Range'
    )
  })

  it('rejects invalid ranges without fetching', async () => {
    const fetchFn = vi.fn(async () => partialResponse()) as unknown as typeof fetch
    const fetcher = createHttpBlobFetcher('https://example.test/blob', fetchFn)

    await expect(fetcher.fetchRange(-1, 2)).rejects.toThrow('Invalid byte range')
    await expect(fetcher.fetchRange(0, 0)).rejects.toThrow('Invalid byte range')
    await expect(fetcher.fetchRange(0, 16 * 1024 * 1024 + 17)).rejects.toThrow('Invalid byte range')
    expect(fetchFn).not.toHaveBeenCalled()
  })
})
