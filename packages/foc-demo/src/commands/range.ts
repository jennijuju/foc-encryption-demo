import type { PieceCID } from '@filoz/synapse-sdk'
import { writeFile } from 'node:fs/promises'
import { createHttpBlobFetcher, decryptRange, parseEnvelope } from 'foc-encryption'
import { deriveKey, parseKeySource } from '../key.js'
import { parseLocator } from '../locator.js'
import { createSynapseClient } from '../synapse.js'
import { formatSize } from '../util.js'

export interface RangeFlags {
  locator: string
  key?: string
  password?: string
  offset: number
  length: number
  output?: string
  privateKey?: string
}

export async function rangeDecrypt(flags: RangeFlags): Promise<void> {
  const locator = parseLocator(flags.locator)

  let url: string
  if (locator.kind === 'url') {
    url = locator.url
  } else {
    const privateKey = flags.privateKey ?? process.env.PRIVATE_KEY
    if (!privateKey) {
      throw new Error('PRIVATE_KEY not set. Provide --private-key or set the environment variable.')
    }
    const synapse = createSynapseClient({ privateKey })
    const ctx = await synapse.storage.createContext()
    // The SDK brands the PieceCID string; this preserves the existing locator contract.
    const pieceCid = locator.pieceCid as unknown as PieceCID
    url = ctx.getPieceUrl(pieceCid)
  }

  const fetcher = createHttpBlobFetcher(url)
  const metadata = await parseEnvelope(fetcher)

  if (!metadata.seekable) {
    throw new Error("File was encrypted with AES-256-GCM (non-seekable). Use 'download' for full decryption.")
  }

  const keySource = parseKeySource({ key: flags.key, password: flags.password })
  const pbkdf2Salt =
    metadata.appMetadata?.pbkdf2_salt instanceof Uint8Array ? metadata.appMetadata.pbkdf2_salt : undefined
  const derived = await deriveKey(keySource, pbkdf2Salt)

  const result = await decryptRange(fetcher, metadata, derived.cek, {
    offset: flags.offset,
    length: flags.length,
  })

  if (flags.output) {
    await writeFile(flags.output, result)
    console.log(`Written to ${flags.output} (${formatSize(result.length)})`)
  } else {
    process.stdout.write(result)
  }
}
