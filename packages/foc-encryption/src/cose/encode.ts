import { Tagged, encode } from 'cborg'
import { FocEncryptionError } from '../errors.js'
import type { AppMetadata } from '../types.js'
import {
  COSE_HEADER_ALG,
  COSE_HEADER_IV,
  COSE_HEADER_TYP,
  CoseHeaderParam,
  FEE_ENVELOPE_TYPE,
  FEE_PROFILE_VERSION,
} from './headers.js'
import { COSE_TAG_ENCRYPT0 } from './tags.js'

const MAX_APP_METADATA_ENTRIES = 32
const MAX_APP_METADATA_KEY_LENGTH = 128
const MAX_APP_METADATA_VALUE_LENGTH = 64 * 1024
const MAX_PROTECTED_HEADERS_LENGTH = 1024 * 1024
const MAX_ENVELOPE_SIZE = 1024 * 1024

interface EncodeOptions {
  appMetadata?: AppMetadata
  chunkSize?: number
  /** Pre-encoded protected header bytes, used verbatim so authenticated and stored bytes are the same buffer. */
  protectedBytes?: Uint8Array
}

function buildUnprotectedMap(iv: Uint8Array): Map<number, unknown> {
  return new Map<number, unknown>([[COSE_HEADER_IV, iv]])
}

export function encodeCoseEncrypt0(algorithmId: number, iv: Uint8Array, options?: EncodeOptions): Uint8Array {
  const protectedBytes = options?.protectedBytes ?? getProtectedHeaderBytes(algorithmId, options)
  const unprotectedMap = buildUnprotectedMap(iv)
  const envelope = encode(new Tagged(COSE_TAG_ENCRYPT0, [protectedBytes, unprotectedMap, null]))
  if (envelope.length > MAX_ENVELOPE_SIZE) {
    throw new FocEncryptionError('FEE envelope is too large')
  }
  return envelope
}

export function getProtectedHeaderBytes(algorithmId: number, options?: EncodeOptions): Uint8Array {
  const protectedMap = new Map<number, unknown>([
    [COSE_HEADER_ALG, algorithmId],
    [COSE_HEADER_TYP, FEE_ENVELOPE_TYPE],
    [CoseHeaderParam.PROFILE_VERSION, FEE_PROFILE_VERSION],
  ])
  if (options?.chunkSize !== undefined) {
    protectedMap.set(CoseHeaderParam.CHUNK_SIZE, options.chunkSize)
  }
  if (options?.appMetadata) {
    protectedMap.set(CoseHeaderParam.APP_METADATA, encodeAppMetadata(options.appMetadata))
  }
  const encoded = encode(protectedMap)
  if (encoded.length > MAX_PROTECTED_HEADERS_LENGTH) {
    throw new FocEncryptionError('Protected FEE metadata is too large')
  }
  return encoded
}

function encodeAppMetadata(meta: AppMetadata): Map<string, unknown> {
  const entries = Object.entries(meta).filter(([, value]) => value !== undefined)
  if (entries.length > MAX_APP_METADATA_ENTRIES) {
    throw new FocEncryptionError('FEE metadata has too many entries')
  }
  const map = new Map<string, unknown>()
  for (const [key, value] of entries) {
    if (!key || key.length > MAX_APP_METADATA_KEY_LENGTH) {
      throw new FocEncryptionError('FEE metadata key is too large')
    }
    if (
      (typeof value === 'string' && value.length > MAX_APP_METADATA_VALUE_LENGTH) ||
      (value instanceof Uint8Array && value.length > MAX_APP_METADATA_VALUE_LENGTH)
    ) {
      throw new FocEncryptionError('FEE metadata value is too large')
    }
    if (
      typeof value !== 'string' &&
      typeof value !== 'number' &&
      typeof value !== 'boolean' &&
      !(value instanceof Uint8Array)
    ) {
      throw new FocEncryptionError('FEE metadata value has an unsupported type')
    }
    if (typeof value === 'number' && !Number.isSafeInteger(value)) {
      throw new FocEncryptionError('FEE metadata number must be a safe integer')
    }
    map.set(key, value)
  }
  return map
}
