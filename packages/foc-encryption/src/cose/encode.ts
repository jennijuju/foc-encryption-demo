import { Tagged, encode } from 'cborg'
import type { AppMetadata } from '../types.js'
import { COSE_HEADER_ALG, COSE_HEADER_IV, COSE_HEADER_TYP, CoseHeaderParam, FOC_ENVELOPE_TYPE } from './headers.js'
import { COSE_TAG_ENCRYPT0 } from './tags.js'

interface EncodeOptions {
  appMetadata?: AppMetadata
  chunkSize?: number
  chunkCount?: number
}

function buildUnprotectedMap(iv: Uint8Array, options?: EncodeOptions): Map<number, unknown> {
  const unprotectedMap = new Map<number, unknown>([[COSE_HEADER_IV, iv]])

  if (options?.chunkSize !== undefined) {
    unprotectedMap.set(CoseHeaderParam.CHUNK_SIZE, options.chunkSize)
  }
  if (options?.chunkCount !== undefined) {
    unprotectedMap.set(CoseHeaderParam.CHUNK_COUNT, options.chunkCount)
  }
  if (options?.appMetadata) {
    unprotectedMap.set(CoseHeaderParam.APP_METADATA, encodeAppMetadata(options.appMetadata))
  }

  return unprotectedMap
}

export function encodeCoseEncrypt0(algorithmId: number, iv: Uint8Array, options?: EncodeOptions): Uint8Array {
  const protectedBytes = getProtectedHeaderBytes(algorithmId)
  const unprotectedMap = buildUnprotectedMap(iv, options)
  return encode(new Tagged(COSE_TAG_ENCRYPT0, [protectedBytes, unprotectedMap, null]))
}

export function getProtectedHeaderBytes(algorithmId: number): Uint8Array {
  const protectedMap = new Map<number, unknown>([
    [COSE_HEADER_ALG, algorithmId],
    [COSE_HEADER_TYP, FOC_ENVELOPE_TYPE],
  ])
  return encode(protectedMap)
}

function encodeAppMetadata(meta: AppMetadata): Map<string, unknown> {
  const map = new Map<string, unknown>()
  for (const [key, value] of Object.entries(meta)) {
    if (value !== undefined) {
      map.set(key, value)
    }
  }
  return map
}
