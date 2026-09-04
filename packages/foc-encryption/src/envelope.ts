import { assembleBlob, parseBlob } from './blob.js'
import { decodeCoseEnvelope } from './cose/decode.js'
import type { DecodedEnvelope } from './cose/decode.js'
import { encodeCoseEncrypt, encodeCoseEncrypt0, getProtectedHeaderBytes } from './cose/encode.js'
import { CoseAlgorithm } from './cose/headers.js'
import { COSE_TAG_ENCRYPT, COSE_TAG_ENCRYPT0 } from './cose/tags.js'
import { FocEncryptionError, MalformedEnvelopeError, SchemeNotSeekableError, UnsupportedSchemeError } from './errors.js'
import { importAndZeroCek, validateCek } from './key-utils.js'
import { Aes256Gcm } from './schemes/aes-256-gcm.js'
import {
  AES_GCM_TAG_LENGTH,
  ChunkedAes256GcmStream,
  DEFAULT_CHUNK_SIZE,
  MAX_CHUNK_SIZE,
} from './schemes/chunked-aes-256-gcm.js'
import type { DecryptMetadata, EncStructureContext, EncryptionScheme } from './schemes/scheme.js'
import type {
  AppMetadata,
  BlobFetcher,
  ByteRange,
  CEKBytes,
  ChunkedEncryptOptions,
  CoseAlgorithmId,
  CoseEnvelopeTag,
  EncryptOptions,
  EnvelopeMetadata,
  Recipient,
  StreamEncryptOptions,
} from './types.js'

function getScheme(algorithmId: number, chunkSize?: number): EncryptionScheme {
  switch (algorithmId) {
    case CoseAlgorithm.AES_256_GCM:
      return new Aes256Gcm()
    case CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM:
      return new ChunkedAes256GcmStream(chunkSize !== undefined ? { chunkSize } : undefined)
    default:
      throw new UnsupportedSchemeError(algorithmId)
  }
}

/**
 * The COSE Enc_structure context follows the envelope tag (RFC 9052
 * Section 5.3): "Encrypt" for COSE_Encrypt (tag 96) and "Encrypt0" for
 * COSE_Encrypt0 (tag 16).
 */
function encStructureContext(tag: CoseEnvelopeTag): EncStructureContext {
  return tag === COSE_TAG_ENCRYPT ? 'Encrypt' : 'Encrypt0'
}

function prepareRecipients(recipients?: Recipient[]): Recipient[] | undefined {
  const envelopeRecipients = recipients?.length ? recipients : undefined
  if (envelopeRecipients) {
    for (const recipient of envelopeRecipients) {
      if (!recipient.wrappedKey || recipient.wrappedKey.length === 0) {
        throw new MalformedEnvelopeError('Recipient must have a non-empty wrappedKey')
      }
    }
  }
  return envelopeRecipients
}

function encodeEnvelope(
  algorithm: CoseAlgorithmId,
  iv: Uint8Array,
  appMetadata: AppMetadata | undefined,
  chunkSize: number | undefined,
  chunkCount: number | undefined,
  recipients: Recipient[] | undefined
): Uint8Array {
  const encodeOptions = { appMetadata, chunkSize, chunkCount }
  return recipients
    ? encodeCoseEncrypt(algorithm, iv, recipients, encodeOptions)
    : encodeCoseEncrypt0(algorithm, iv, encodeOptions)
}

export async function encrypt(
  plaintext: Uint8Array,
  cek: CEKBytes,
  options: EncryptOptions,
  recipients?: Recipient[]
): Promise<Uint8Array> {
  validateCek(cek)
  const chunkSize =
    options.algorithm === CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM
      ? (options as ChunkedEncryptOptions).chunkSize
      : undefined
  const scheme = getScheme(options.algorithm, chunkSize)
  const protectedHeaders = getProtectedHeaderBytes(options.algorithm)

  const cekCopy = new Uint8Array(cek)
  const key = await importAndZeroCek(cekCopy)

  const envelopeRecipients = prepareRecipients(recipients)
  const tag = envelopeRecipients ? COSE_TAG_ENCRYPT : COSE_TAG_ENCRYPT0
  const context = encStructureContext(tag)
  const result = await scheme.encrypt(key, plaintext, protectedHeaders, context, options.appMetadata)

  const envelope = encodeEnvelope(
    options.algorithm,
    result.iv,
    options.appMetadata,
    result.chunkSize,
    result.chunkCount,
    envelopeRecipients
  )

  return assembleBlob(envelope, result.ciphertext)
}

export async function encryptStream(
  plaintext: ReadableStream<Uint8Array>,
  cek: CEKBytes,
  options: StreamEncryptOptions,
  recipients?: Recipient[]
): Promise<ReadableStream<Uint8Array>> {
  validateCek(cek)
  const scheme = new ChunkedAes256GcmStream(
    options.chunkSize !== undefined ? { chunkSize: options.chunkSize } : undefined
  )
  const protectedHeaders = getProtectedHeaderBytes(options.algorithm)
  const cekCopy = new Uint8Array(cek)
  const key = await importAndZeroCek(cekCopy)
  const envelopeRecipients = prepareRecipients(recipients)
  const tag = envelopeRecipients ? COSE_TAG_ENCRYPT : COSE_TAG_ENCRYPT0
  const result = scheme.encryptStream(
    key,
    plaintext,
    options.plaintextLength,
    protectedHeaders,
    encStructureContext(tag)
  )

  let envelope: Uint8Array
  try {
    envelope = encodeEnvelope(
      options.algorithm,
      result.iv,
      options.appMetadata,
      result.chunkSize,
      result.chunkCount,
      envelopeRecipients
    )
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

  const scheme = getScheme(envelope.algorithm, envelope.chunkSize)

  const cekCopy = new Uint8Array(cek)
  const key = await importAndZeroCek(cekCopy)

  const context = encStructureContext(envelope.tag)
  const metadata: DecryptMetadata = { chunkSize: envelope.chunkSize, chunkCount: envelope.chunkCount }
  return scheme.decrypt(key, parsed.ciphertext, envelope.iv, envelope.protectedHeaders, context, metadata)
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
  const context = encStructureContext(metadata.tag)

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

function parseEnvelopeBytes(blob: Uint8Array): EnvelopeMetadata {
  let envelope: DecodedEnvelope
  try {
    envelope = decodeCoseEnvelope(blob)
  } catch (e) {
    if (e instanceof MalformedEnvelopeError) throw e
    throw new MalformedEnvelopeError('Failed to parse envelope')
  }

  const seekable = envelope.algorithm === CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM

  let appMetadata: AppMetadata | undefined
  if (envelope.appMetadata) {
    appMetadata = Object.fromEntries(envelope.appMetadata) as AppMetadata
  }

  return {
    tag: envelope.tag,
    algorithm: envelope.algorithm as CoseAlgorithmId,
    seekable,
    iv: envelope.iv,
    protectedHeaders: envelope.protectedHeaders,
    chunkSize: envelope.chunkSize,
    chunkCount: envelope.chunkCount,
    appMetadata,
    recipients: envelope.recipients,
    envelopeSize: envelope.envelopeSize,
  }
}

export function parseEnvelope(blob: Uint8Array): EnvelopeMetadata
export function parseEnvelope(fetcher: BlobFetcher): Promise<EnvelopeMetadata>
export function parseEnvelope(blob: Uint8Array | BlobFetcher): EnvelopeMetadata | Promise<EnvelopeMetadata> {
  if (blob instanceof Uint8Array) {
    return parseEnvelopeBytes(blob)
  }
  return blob.fetchEnvelope().then(parseEnvelopeBytes)
}
