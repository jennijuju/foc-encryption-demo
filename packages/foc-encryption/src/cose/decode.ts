import { Tagged, decode, decodeFirst } from 'cborg'
import { MalformedEnvelopeError } from '../errors.js'
import type { CoseEnvelopeTag } from '../types.js'
import {
  COSE_HEADER_ALG,
  COSE_HEADER_IV,
  COSE_HEADER_TYP,
  CoseHeaderParam,
  FEE_ENVELOPE_TYPE,
  FEE_PROFILE_VERSION,
} from './headers.js'
import { COSE_TAG_ENCRYPT0, coseDecodeOptions } from './tags.js'

const MAX_ENVELOPE_SIZE = 1024 * 1024
const MAX_APP_METADATA_ENTRIES = 32
const MAX_APP_METADATA_KEY_LENGTH = 128
const MAX_APP_METADATA_VALUE_LENGTH = 64 * 1024
const PROTECTED_PARAMS = new Set<number>([
  COSE_HEADER_ALG,
  COSE_HEADER_TYP,
  CoseHeaderParam.PROFILE_VERSION,
  CoseHeaderParam.CHUNK_SIZE,
  CoseHeaderParam.APP_METADATA,
])

export interface DecodedEnvelope {
  tag: CoseEnvelopeTag
  profileVersion: 1
  algorithm: number
  iv: Uint8Array
  protectedHeaders: Uint8Array
  chunkSize?: number
  appMetadata?: Map<string, unknown>
  envelopeSize: number
}

export function decodeCoseEnvelope(blob: Uint8Array): DecodedEnvelope {
  let decoded: unknown
  let remainder: Uint8Array
  try {
    ;[decoded, remainder] = decodeFirst(blob, coseDecodeOptions)
  } catch (err) {
    throw new MalformedEnvelopeError('Failed to decode COSE envelope: invalid CBOR', { cause: err })
  }

  if (!(decoded instanceof Tagged)) {
    throw new MalformedEnvelopeError('Expected a CBOR-tagged COSE envelope')
  }
  if (decoded.tag !== COSE_TAG_ENCRYPT0) {
    throw new MalformedEnvelopeError(`FEE v1 requires COSE_Encrypt0 (tag 16), got tag ${decoded.tag}`)
  }

  const arr = decoded.value
  if (!Array.isArray(arr) || arr.length !== 3) {
    throw new MalformedEnvelopeError('COSE_Encrypt0 envelope must contain exactly 3 elements')
  }
  if (!(arr[0] instanceof Uint8Array)) {
    throw new MalformedEnvelopeError('COSE protected headers must be a byte string')
  }
  if (!(arr[1] instanceof Map)) {
    throw new MalformedEnvelopeError('COSE unprotected headers must be a map')
  }
  if (arr[2] !== null) {
    throw new MalformedEnvelopeError('COSE ciphertext field must be nil for a detached payload')
  }

  const protectedBytes = arr[0]
  const unprotectedMap = arr[1] as Map<unknown, unknown>
  if (unprotectedMap.size !== 1 || !unprotectedMap.has(COSE_HEADER_IV)) {
    throw new MalformedEnvelopeError('FEE v1 unprotected headers may contain only the IV')
  }
  let protectedMap: unknown
  try {
    protectedMap = decode(protectedBytes, { useMaps: true })
  } catch (err) {
    throw new MalformedEnvelopeError('Failed to decode protected headers', { cause: err })
  }
  if (!(protectedMap instanceof Map)) {
    throw new MalformedEnvelopeError('COSE protected headers must encode a map')
  }
  for (const key of protectedMap.keys()) {
    if (typeof key !== 'number' || !PROTECTED_PARAMS.has(key)) {
      throw new MalformedEnvelopeError('FEE v1 protected headers contain an unknown parameter')
    }
  }

  const algorithm = protectedMap.get(COSE_HEADER_ALG)
  if (typeof algorithm !== 'number') {
    throw new MalformedEnvelopeError('Missing or invalid algorithm in protected headers')
  }
  if (protectedMap.get(COSE_HEADER_TYP) !== FEE_ENVELOPE_TYPE) {
    throw new MalformedEnvelopeError('Missing or invalid FEE media type')
  }
  const profileVersion = protectedMap.get(CoseHeaderParam.PROFILE_VERSION)
  if (profileVersion !== FEE_PROFILE_VERSION) {
    throw new MalformedEnvelopeError('Missing or unsupported FEE profile version')
  }

  const iv = unprotectedMap.get(COSE_HEADER_IV)
  if (!(iv instanceof Uint8Array)) {
    throw new MalformedEnvelopeError('Missing or invalid IV in unprotected headers')
  }
  const chunkSize = protectedMap.get(CoseHeaderParam.CHUNK_SIZE)
  if (chunkSize !== undefined && typeof chunkSize !== 'number') {
    throw new MalformedEnvelopeError('Invalid chunk size in protected headers')
  }
  const appMetadata = protectedMap.get(CoseHeaderParam.APP_METADATA)
  if (appMetadata !== undefined && !(appMetadata instanceof Map)) {
    throw new MalformedEnvelopeError('Invalid application metadata in protected headers')
  }
  if (appMetadata instanceof Map) {
    if (appMetadata.size > MAX_APP_METADATA_ENTRIES) {
      throw new MalformedEnvelopeError('FEE metadata has too many entries')
    }
    for (const [key, value] of appMetadata) {
      if (typeof key !== 'string' || !key || key.length > MAX_APP_METADATA_KEY_LENGTH) {
        throw new MalformedEnvelopeError('FEE metadata contains an invalid key')
      }
      if (
        (typeof value === 'string' && value.length > MAX_APP_METADATA_VALUE_LENGTH) ||
        (value instanceof Uint8Array && value.length > MAX_APP_METADATA_VALUE_LENGTH)
      ) {
        throw new MalformedEnvelopeError('FEE metadata value is too large')
      }
      if (
        typeof value !== 'string' &&
        typeof value !== 'number' &&
        typeof value !== 'boolean' &&
        !(value instanceof Uint8Array)
      ) {
        throw new MalformedEnvelopeError('FEE metadata value has an unsupported type')
      }
      if (typeof value === 'number' && !Number.isSafeInteger(value)) {
        throw new MalformedEnvelopeError('FEE metadata number must be a safe integer')
      }
    }
  }

  const envelopeSize = blob.length - remainder.length
  if (envelopeSize > MAX_ENVELOPE_SIZE) {
    throw new MalformedEnvelopeError('FEE envelope is too large')
  }

  return {
    tag: decoded.tag,
    profileVersion: FEE_PROFILE_VERSION,
    algorithm,
    iv,
    protectedHeaders: protectedBytes,
    chunkSize,
    appMetadata: appMetadata as Map<string, unknown> | undefined,
    envelopeSize,
  }
}
