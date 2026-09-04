import { assembleBlob, parseBlob } from './blob.js'
import { decodeCoseEnvelope } from './cose/decode.js'
import type { DecodedEnvelope } from './cose/decode.js'
import { encodeCoseEncrypt0, getProtectedHeaderBytes } from './cose/encode.js'
import { CoseAlgorithm } from './cose/headers.js'
import { FocEncryptionError, MalformedEnvelopeError, SchemeNotSeekableError, UnsupportedSchemeError } from './errors.js'
import { importAndZeroCek, validateCek } from './key-utils.js'
import { AES_GCM_IV_LENGTH, Aes256Gcm } from './schemes/aes-256-gcm.js'
import {
  AES_GCM_TAG_LENGTH,
  ChunkedAes256GcmStream,
  DEFAULT_CHUNK_SIZE,
  MAX_CHUNK_SIZE,
} from './schemes/chunked-aes-256-gcm.js'
import type { DecryptMetadata, EncryptionScheme } from './schemes/scheme.js'
import type {
  AppMetadata,
  BlobFetcher,
  ByteRange,
  CEKBytes,
  ChunkedEncryptOptions,
  CoseAlgorithmId,
  EncryptOptions,
  EnvelopeMetadata,
  StreamEncryptOptions,
} from './types.js'

function getScheme(algorithmId: number, chunkSize?: number): EncryptionScheme {
  switch (algorithmId) {
    case CoseAlgorithm.AES_256_GCM:
      return new Aes256Gcm()
    case CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM:
      if (chunkSize !== undefined && chunkSize < MIN_PROFILE_CHUNK_SIZE) {
        throw new FocEncryptionError(`Chunk size must be at least ${MIN_PROFILE_CHUNK_SIZE}`)
      }
      return new ChunkedAes256GcmStream(chunkSize !== undefined ? { chunkSize } : undefined)
    default:
      throw new UnsupportedSchemeError(algorithmId)
  }
}

const MIN_PROFILE_CHUNK_SIZE = 4096

function deriveChunkCount(envelope: DecodedEnvelope, ciphertextLength: number): number | undefined {
  if (envelope.algorithm === CoseAlgorithm.AES_256_GCM) {
    if (envelope.iv.length !== AES_GCM_IV_LENGTH || ciphertextLength < AES_GCM_TAG_LENGTH) {
      throw new MalformedEnvelopeError('Invalid AES-256-GCM envelope geometry')
    }
    if (envelope.chunkSize !== undefined) {
      throw new MalformedEnvelopeError('Simple AES-256-GCM envelope must not contain a chunk size')
    }
    return undefined
  }
  if (envelope.algorithm !== CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM) {
    throw new UnsupportedSchemeError(envelope.algorithm)
  }
  const chunkSize = envelope.chunkSize
  if (
    !Number.isSafeInteger(chunkSize) ||
    chunkSize === undefined ||
    chunkSize < MIN_PROFILE_CHUNK_SIZE ||
    chunkSize > MAX_CHUNK_SIZE ||
    envelope.iv.length !== 7
  ) {
    throw new MalformedEnvelopeError('Invalid chunked envelope geometry')
  }
  const ciphertextChunkSize = chunkSize + AES_GCM_TAG_LENGTH
  const chunkCount = Math.ceil(ciphertextLength / ciphertextChunkSize)
  const finalChunkLength = ciphertextLength - (chunkCount - 1) * ciphertextChunkSize
  if (chunkCount < 1 || finalChunkLength < AES_GCM_TAG_LENGTH || finalChunkLength > ciphertextChunkSize) {
    throw new MalformedEnvelopeError('Invalid chunked ciphertext length')
  }
  return chunkCount
}

function encodeEnvelope(
  algorithm: CoseAlgorithmId,
  iv: Uint8Array,
  appMetadata: AppMetadata | undefined,
  chunkSize: number | undefined
): Uint8Array {
  return encodeCoseEncrypt0(algorithm, iv, { appMetadata, chunkSize })
}

export async function encrypt(plaintext: Uint8Array, cek: CEKBytes, options: EncryptOptions): Promise<Uint8Array> {
  validateCek(cek)
  const chunkSize =
    options.algorithm === CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM
      ? ((options as ChunkedEncryptOptions).chunkSize ?? DEFAULT_CHUNK_SIZE)
      : undefined
  const scheme = getScheme(options.algorithm, chunkSize)
  const protectedHeaders = getProtectedHeaderBytes(options.algorithm, {
    appMetadata: options.appMetadata,
    chunkSize,
  })

  const cekCopy = new Uint8Array(cek)
  const key = await importAndZeroCek(cekCopy)

  const result = await scheme.encrypt(key, plaintext, protectedHeaders, 'Encrypt0', options.appMetadata)

  const envelope = encodeEnvelope(options.algorithm, result.iv, options.appMetadata, result.chunkSize)

  return assembleBlob(envelope, result.ciphertext)
}

export async function encryptStream(
  plaintext: ReadableStream<Uint8Array>,
  cek: CEKBytes,
  options: StreamEncryptOptions
): Promise<ReadableStream<Uint8Array>> {
  validateCek(cek)
  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE
  if (chunkSize < MIN_PROFILE_CHUNK_SIZE) {
    throw new FocEncryptionError(`Chunk size must be at least ${MIN_PROFILE_CHUNK_SIZE}`)
  }
  const scheme = new ChunkedAes256GcmStream({ chunkSize })
  const protectedHeaders = getProtectedHeaderBytes(options.algorithm, {
    appMetadata: options.appMetadata,
    chunkSize,
  })
  const cekCopy = new Uint8Array(cek)
  const key = await importAndZeroCek(cekCopy)
  const result = scheme.encryptStream(key, plaintext, options.plaintextLength, protectedHeaders, 'Encrypt0')

  let envelope: Uint8Array
  try {
    envelope = encodeEnvelope(options.algorithm, result.iv, options.appMetadata, result.chunkSize)
  } catch (error) {
    await result.ciphertext.cancel(error)
    throw error
  }

  const ciphertextReader = result.ciphertext.getReader()
  let envelopeEmitted = false
  return new ReadableStream<Uint8Array>({
    pull: async (controller) => {
      if (!envelopeEmitted) {
        envelopeEmitted = true
        controller.enqueue(envelope)
        return
      }
      try {
        const next = await ciphertextReader.read()
        if (next.done) {
          ciphertextReader.releaseLock()
          controller.close()
        } else {
          controller.enqueue(next.value)
        }
      } catch (error) {
        ciphertextReader.releaseLock()
        controller.error(error)
      }
    },
    cancel: async (reason: unknown) => {
      try {
        await ciphertextReader.cancel(reason)
      } finally {
        ciphertextReader.releaseLock()
      }
    },
  })
}

export async function decrypt(blob: Uint8Array, cek: CEKBytes): Promise<Uint8Array> {
  const parsed = parseBlob(blob)
  const envelope = decodeCoseEnvelope(parsed.envelopeBytes)
  const chunkCount = deriveChunkCount(envelope, parsed.ciphertext.length)
  const scheme = getScheme(envelope.algorithm, envelope.chunkSize)

  const cekCopy = new Uint8Array(cek)
  const key = await importAndZeroCek(cekCopy)

  const metadata: DecryptMetadata = { chunkSize: envelope.chunkSize, chunkCount }
  return scheme.decrypt(key, parsed.ciphertext, envelope.iv, envelope.protectedHeaders, 'Encrypt0', metadata)
}

const MAX_DECRYPT_RANGE = 16 * 1024 * 1024
const MAX_CIPHERTEXT_BATCH = MAX_CHUNK_SIZE + AES_GCM_TAG_LENGTH

export async function decryptRange(
  fetcher: BlobFetcher,
  metadata: EnvelopeMetadata,
  cek: CEKBytes,
  range: ByteRange
): Promise<Uint8Array> {
  if (
    !Number.isSafeInteger(range.offset) ||
    range.offset < 0 ||
    !Number.isSafeInteger(range.length) ||
    range.length < 0 ||
    range.length > MAX_DECRYPT_RANGE ||
    !Number.isSafeInteger(range.offset + range.length)
  ) {
    throw new FocEncryptionError('Invalid decryption range')
  }
  if (range.length === 0) return new Uint8Array()

  const scheme = getScheme(metadata.algorithm, metadata.chunkSize)
  if (!scheme.isSeekable) {
    throw new SchemeNotSeekableError(
      `Scheme ${scheme.name} (algorithm ${scheme.algorithmId}) does not support range decryption`
    )
  }

  const chunkCount = metadata.chunkCount
  if (!Number.isSafeInteger(chunkCount) || chunkCount === undefined || chunkCount <= 0) {
    throw new MalformedEnvelopeError('Chunk count must be a positive safe integer')
  }

  const cekCopy = new Uint8Array(cek)
  const key = await importAndZeroCek(cekCopy)
  const chunkedScheme = scheme as ChunkedAes256GcmStream
  const chunkSize = metadata.chunkSize ?? DEFAULT_CHUNK_SIZE
  const ciphertextChunkSize = chunkSize + AES_GCM_TAG_LENGTH
  const chunksPerBatch = Math.max(1, Math.floor(MAX_CIPHERTEXT_BATCH / ciphertextChunkSize))
  const firstChunk = Math.floor(range.offset / chunkSize)
  const lastChunk = Math.min(Math.floor((range.offset + range.length - 1) / chunkSize), chunkCount - 1)
  const rangeEnd = range.offset + range.length
  const output = new Uint8Array(range.length)
  let outputLength = 0
  const context = 'Encrypt0'

  for (let batchFirst = firstChunk; batchFirst <= lastChunk; ) {
    const batchLast = Math.min(lastChunk, batchFirst + chunksPerBatch - 1)
    const batchChunkCount = batchLast - batchFirst + 1
    const ciphertextStart = metadata.envelopeSize + batchFirst * ciphertextChunkSize
    const ciphertextLength = batchChunkCount * ciphertextChunkSize
    const fetched = await fetcher.fetchRange(ciphertextStart, ciphertextLength)
    const batchPlaintextStart = batchFirst * chunkSize
    const requestedStart = Math.max(range.offset, batchPlaintextStart)
    const requestedEnd = Math.min(rangeEnd, batchPlaintextStart + batchChunkCount * chunkSize)
    const requestedLength = requestedEnd - requestedStart
    const decrypted = await chunkedScheme.decryptRange(
      key,
      fetched,
      metadata.iv,
      metadata.protectedHeaders,
      context,
      requestedStart - batchPlaintextStart,
      requestedLength,
      chunkSize,
      chunkCount,
      batchFirst
    )
    output.set(decrypted, requestedStart - range.offset)
    outputLength = requestedStart - range.offset + decrypted.length
    decrypted.fill(0)
    batchFirst = batchLast + 1
  }

  return outputLength === output.length ? output : output.slice(0, outputLength)
}

function parseEnvelopeBytes(blob: Uint8Array, totalSize = blob.length): EnvelopeMetadata {
  let envelope: DecodedEnvelope
  try {
    envelope = decodeCoseEnvelope(blob)
  } catch (e) {
    if (e instanceof MalformedEnvelopeError) throw e
    throw new MalformedEnvelopeError('Failed to parse envelope')
  }

  const seekable = envelope.algorithm === CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM
  const ciphertextLength = totalSize - envelope.envelopeSize
  const chunkCount = deriveChunkCount(envelope, ciphertextLength)

  let appMetadata: AppMetadata | undefined
  if (envelope.appMetadata) {
    appMetadata = Object.fromEntries(envelope.appMetadata) as AppMetadata
  }
  const plaintextSize =
    chunkCount === undefined
      ? ciphertextLength - AES_GCM_TAG_LENGTH
      : ciphertextLength - chunkCount * AES_GCM_TAG_LENGTH
  if (
    appMetadata?.plaintext_size !== undefined &&
    (!Number.isSafeInteger(appMetadata.plaintext_size) || appMetadata.plaintext_size !== plaintextSize)
  ) {
    throw new MalformedEnvelopeError('Authenticated plaintext size does not match ciphertext geometry')
  }

  return {
    tag: envelope.tag,
    profileVersion: envelope.profileVersion,
    algorithm: envelope.algorithm as CoseAlgorithmId,
    seekable,
    iv: envelope.iv,
    protectedHeaders: envelope.protectedHeaders,
    chunkSize: envelope.chunkSize,
    chunkCount,
    appMetadata,
    envelopeSize: envelope.envelopeSize,
  }
}

const INITIAL_ENVELOPE_PROBE = 4096
const MAX_ENVELOPE_PROBE = 1024 * 1024

async function parseRemoteEnvelope(fetcher: BlobFetcher): Promise<EnvelopeMetadata> {
  const totalSize = await fetcher.getSize()
  if (!Number.isSafeInteger(totalSize) || totalSize <= 0) {
    throw new MalformedEnvelopeError('Encrypted object has an invalid total size')
  }
  let probeSize = Math.min(INITIAL_ENVELOPE_PROBE, totalSize)
  for (;;) {
    const bytes = await fetcher.fetchRange(0, probeSize)
    try {
      return parseEnvelopeBytes(bytes, totalSize)
    } catch (error) {
      if (!(error instanceof MalformedEnvelopeError) || probeSize >= totalSize) throw error
      if (probeSize >= MAX_ENVELOPE_PROBE) {
        throw new MalformedEnvelopeError('FEE envelope exceeds the maximum probe size', { cause: error })
      }
      probeSize = Math.min(totalSize, probeSize * 2, MAX_ENVELOPE_PROBE)
    }
  }
}

export function parseEnvelope(blob: Uint8Array): EnvelopeMetadata
export function parseEnvelope(fetcher: BlobFetcher): Promise<EnvelopeMetadata>
export function parseEnvelope(blob: Uint8Array | BlobFetcher): EnvelopeMetadata | Promise<EnvelopeMetadata> {
  return blob instanceof Uint8Array ? parseEnvelopeBytes(blob) : parseRemoteEnvelope(blob)
}
