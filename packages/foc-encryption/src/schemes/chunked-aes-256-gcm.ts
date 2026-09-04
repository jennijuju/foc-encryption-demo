import { buildEncStructure } from '../cose/structures.js'
import { aesGcmDecrypt, aesGcmEncrypt, getRandomValues } from '../crypto.js'
import { AuthenticationError, FocEncryptionError, MalformedEnvelopeError } from '../errors.js'
import type { DecryptMetadata, EncStructureContext, EncryptResult, EncryptionScheme } from './scheme.js'

const BASE_NONCE_LENGTH = 12
const AES_GCM_TAG_LENGTH = 16
const DEFAULT_CHUNK_SIZE = 262144 // 256 KiB
const MIN_CHUNK_SIZE = 4096 // 4 KiB
const MAX_CHUNK_SIZE = 16 * 1024 * 1024
const MAX_CHUNK_INDEX = 0xffffffff // 4-byte counter max

export interface ChunkedEncryptParams {
  chunkSize?: number
  objectNonce?: Uint8Array
}

export class ChunkedAes256GcmStream implements EncryptionScheme {
  readonly name = 'Chunked-AES-256-GCM-STREAM'
  readonly algorithmId = -65793
  readonly isSeekable = true

  private chunkSize: number
  private objectNonce?: Uint8Array

  constructor(params?: ChunkedEncryptParams) {
    const chunkSize = params?.chunkSize ?? DEFAULT_CHUNK_SIZE
    if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0 || chunkSize > MAX_CHUNK_SIZE) {
      throw new FocEncryptionError(
        `Chunk size must be a positive safe integer no larger than ${MAX_CHUNK_SIZE}, got ${chunkSize}`
      )
    }
    if (params?.objectNonce && params.objectNonce.length !== BASE_NONCE_LENGTH) {
      throw new FocEncryptionError(`Object nonce must be ${BASE_NONCE_LENGTH} bytes`)
    }
    this.objectNonce = params?.objectNonce ? Uint8Array.from(params.objectNonce) : undefined
    this.chunkSize = chunkSize
  }

  private createEncryptionMetadata(plaintextLength: number): { iv: Uint8Array; chunkCount: number } {
    if (!Number.isSafeInteger(plaintextLength) || plaintextLength < 0) {
      throw new FocEncryptionError(`Plaintext length must be a non-negative safe integer, got ${plaintextLength}`)
    }
    const chunkCount = Math.max(1, Math.ceil(plaintextLength / this.chunkSize))
    if (chunkCount - 1 > MAX_CHUNK_INDEX) {
      throw new FocEncryptionError(
        `Plaintext too large: ${chunkCount} chunks exceeds the 4-byte counter maximum (${MAX_CHUNK_INDEX + 1})`
      )
    }
    const iv = this.objectNonce ? Uint8Array.from(this.objectNonce) : getRandomValues(BASE_NONCE_LENGTH)
    this.objectNonce = undefined
    return { iv, chunkCount }
  }

  async encrypt(
    key: CryptoKey,
    plaintext: Uint8Array,
    protectedHeaders: Uint8Array,
    context: EncStructureContext
  ): Promise<EncryptResult> {
    const { iv: baseNonce, chunkCount } = this.createEncryptionMetadata(plaintext.length)

    const chunks: Uint8Array[] = []
    for (let i = 0; i < chunkCount; i++) {
      const isLast = i === chunkCount - 1
      const start = i * this.chunkSize
      const end = isLast ? plaintext.length : start + this.chunkSize
      const chunk = plaintext.subarray(start, end)

      const nonce = deriveChunkNonce(i)
      const aad = buildEncStructure(context, protectedHeaders, new Uint8Array([isLast ? 1 : 0]))
      const encrypted = await aesGcmEncrypt(key, nonce, chunk, aad)
      chunks.push(encrypted)
    }

    // Concatenate all chunk ciphertexts
    const totalLength = chunks.reduce((sum, c) => sum + c.length, 0)
    const ciphertext = new Uint8Array(totalLength)
    let offset = 0
    for (const chunk of chunks) {
      ciphertext.set(chunk, offset)
      offset += chunk.length
    }

    return {
      ciphertext,
      iv: baseNonce,
      chunkSize: this.chunkSize,
      chunkCount,
    }
  }

  encryptStream(
    key: CryptoKey,
    plaintext: ReadableStream<Uint8Array>,
    plaintextLength: number,
    protectedHeaders: Uint8Array,
    context: EncStructureContext
  ): {
    ciphertext: ReadableStream<Uint8Array>
    iv: Uint8Array
    chunkSize: number
    chunkCount: number
  } {
    const { iv, chunkCount } = this.createEncryptionMetadata(plaintextLength)
    const reader = plaintext.getReader()
    let sourceChunk: Uint8Array | undefined
    let sourceOffset = 0
    let chunkIndex = 0
    let readerReleased = false

    const releaseReader = () => {
      if (!readerReleased) {
        reader.releaseLock()
        readerReleased = true
      }
    }

    const cancelSource = async (reason: unknown) => {
      if (readerReleased) return
      sourceChunk?.fill(0)
      sourceChunk = undefined
      try {
        await reader.cancel(reason)
      } catch {
        // Preserve the encryption or consumer-cancellation reason.
      } finally {
        releaseReader()
      }
    }

    const readPlaintextChunk = async (length: number): Promise<Uint8Array> => {
      const chunk = new Uint8Array(length)
      let written = 0
      while (written < length) {
        if (!sourceChunk) {
          const next = await reader.read()
          if (next.done) {
            chunk.fill(0)
            throw new FocEncryptionError(
              `Plaintext ended early: expected ${plaintextLength} bytes, received ${chunkIndex * this.chunkSize + written}`
            )
          }
          if (next.value.length === 0) continue
          sourceChunk = next.value
          sourceOffset = 0
        }

        const currentSourceChunk = sourceChunk
        if (!currentSourceChunk) continue
        const copyLength = Math.min(length - written, currentSourceChunk.length - sourceOffset)
        chunk.set(currentSourceChunk.subarray(sourceOffset, sourceOffset + copyLength), written)
        sourceOffset += copyLength
        written += copyLength
        if (sourceOffset === currentSourceChunk.length) {
          sourceChunk = undefined
          sourceOffset = 0
        }
      }
      return chunk
    }

    const requireSourceEnd = async () => {
      if (sourceChunk && sourceOffset < sourceChunk.length) {
        throw new FocEncryptionError(`Plaintext exceeds declared length of ${plaintextLength} bytes`)
      }
      sourceChunk = undefined
      sourceOffset = 0
      while (true) {
        const next = await reader.read()
        if (next.done) return
        if (next.value.length > 0) {
          sourceChunk = next.value
          throw new FocEncryptionError(`Plaintext exceeds declared length of ${plaintextLength} bytes`)
        }
      }
    }

    const ciphertext = new ReadableStream<Uint8Array>(
      {
        pull: async (controller) => {
          const isLast = chunkIndex === chunkCount - 1
          const chunkLength = isLast ? plaintextLength - chunkIndex * this.chunkSize : this.chunkSize
          let chunk: Uint8Array | undefined
          try {
            chunk = await readPlaintextChunk(chunkLength)
            if (isLast) await requireSourceEnd()
            const nonce = deriveChunkNonce(chunkIndex)
            const aad = buildEncStructure(context, protectedHeaders, new Uint8Array([isLast ? 1 : 0]))
            const encrypted = await aesGcmEncrypt(key, nonce, chunk, aad)
            controller.enqueue(encrypted)
            chunkIndex += 1
            if (isLast) {
              releaseReader()
              controller.close()
            }
          } catch (error) {
            await cancelSource(error)
            controller.error(error)
          } finally {
            chunk?.fill(0)
          }
        },
        cancel: cancelSource,
      },
      { highWaterMark: 0 }
    )

    return { ciphertext, iv, chunkSize: this.chunkSize, chunkCount }
  }

  async decrypt(
    key: CryptoKey,
    ciphertext: Uint8Array,
    iv: Uint8Array,
    protectedHeaders: Uint8Array,
    context: EncStructureContext,
    metadata?: DecryptMetadata
  ): Promise<Uint8Array> {
    const effectiveChunkSize = metadata?.chunkSize ?? this.chunkSize
    const ciphertextChunkSize = effectiveChunkSize + AES_GCM_TAG_LENGTH
    const effectiveChunkCount = metadata?.chunkCount ?? Math.ceil(ciphertext.length / ciphertextChunkSize)
    if (effectiveChunkCount - 1 > MAX_CHUNK_INDEX) {
      throw new MalformedEnvelopeError(`Chunk count ${effectiveChunkCount} exceeds the 4-byte counter maximum`)
    }

    const plaintextChunks: Uint8Array[] = []
    for (let i = 0; i < effectiveChunkCount; i++) {
      const isLast = i === effectiveChunkCount - 1
      const start = i * ciphertextChunkSize
      const end = isLast ? ciphertext.length : start + ciphertextChunkSize
      const chunkCt = ciphertext.subarray(start, end)

      const nonce = deriveChunkNonce(i)
      const aad = buildEncStructure(context, protectedHeaders, new Uint8Array([isLast ? 1 : 0]))
      try {
        const decrypted = await aesGcmDecrypt(key, nonce, chunkCt, aad)
        plaintextChunks.push(decrypted)
      } catch {
        throw new AuthenticationError(`AEAD authentication failed on chunk ${i}`)
      }
    }

    const totalLength = plaintextChunks.reduce((sum, c) => sum + c.length, 0)
    const plaintext = new Uint8Array(totalLength)
    let offset = 0
    for (const chunk of plaintextChunks) {
      plaintext.set(chunk, offset)
      offset += chunk.length
    }

    return plaintext
  }

  async decryptRange(
    key: CryptoKey,
    ciphertext: Uint8Array,
    iv: Uint8Array,
    protectedHeaders: Uint8Array,
    context: EncStructureContext,
    plaintextOffset: number,
    plaintextLength: number,
    chunkSize?: number,
    chunkCount?: number,
    chunkIndexOffset = 0
  ): Promise<Uint8Array> {
    const effectiveChunkSize = chunkSize ?? this.chunkSize
    const ciphertextChunkSize = effectiveChunkSize + AES_GCM_TAG_LENGTH
    const effectiveChunkCount = chunkCount ?? Math.ceil(ciphertext.length / ciphertextChunkSize)

    const firstChunk = Math.floor(plaintextOffset / effectiveChunkSize)
    if (effectiveChunkCount - 1 > MAX_CHUNK_INDEX) {
      throw new MalformedEnvelopeError(`Chunk count ${effectiveChunkCount} exceeds the 4-byte counter maximum`)
    }
    const lastChunk = Math.min(
      Math.floor((plaintextOffset + plaintextLength - 1) / effectiveChunkSize),
      effectiveChunkCount - 1
    )

    const plaintextChunks: Uint8Array[] = []
    for (let i = firstChunk; i <= lastChunk; i++) {
      const globalIndex = i + chunkIndexOffset
      const isLast = globalIndex === effectiveChunkCount - 1
      const ctStart = i * ciphertextChunkSize
      const ctEnd = isLast ? ciphertext.length : ctStart + ciphertextChunkSize
      const chunkCt = ciphertext.subarray(ctStart, ctEnd)

      const nonce = deriveChunkNonce(globalIndex)
      const aad = buildEncStructure(context, protectedHeaders, new Uint8Array([isLast ? 1 : 0]))
      try {
        const decrypted = await aesGcmDecrypt(key, nonce, chunkCt, aad)
        plaintextChunks.push(decrypted)
      } catch {
        throw new AuthenticationError(`AEAD authentication failed on chunk ${i}`)
      }
    }

    // Concatenate decrypted chunks
    const totalLength = plaintextChunks.reduce((sum, c) => sum + c.length, 0)
    const combined = new Uint8Array(totalLength)
    let offset = 0
    for (const chunk of plaintextChunks) {
      combined.set(chunk, offset)
      offset += chunk.length
    }

    // Slice to the exact requested range within the decrypted chunk window
    const startInWindow = plaintextOffset - firstChunk * effectiveChunkSize
    return combined.slice(startInWindow, startInWindow + plaintextLength)
  }
}

/** Derive a per-chunk nonce from its unsigned 32-bit index. */
function deriveChunkNonce(chunkIndex: number): Uint8Array {
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex > MAX_CHUNK_INDEX) {
    throw new MalformedEnvelopeError('Chunk index must fit in an unsigned 32-bit integer')
  }
  const nonce = new Uint8Array(BASE_NONCE_LENGTH)
  nonce[8] = (chunkIndex >>> 24) & 0xff
  nonce[9] = (chunkIndex >>> 16) & 0xff
  nonce[10] = (chunkIndex >>> 8) & 0xff
  nonce[11] = chunkIndex & 0xff
  return nonce
}

export {
  DEFAULT_CHUNK_SIZE,
  MIN_CHUNK_SIZE,
  MAX_CHUNK_SIZE,
  AES_GCM_TAG_LENGTH,
  BASE_NONCE_LENGTH,
  MAX_CHUNK_INDEX,
  deriveChunkNonce,
}
