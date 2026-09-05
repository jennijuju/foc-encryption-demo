export const CoseAlgorithm = {
  AES_256_GCM: 3,
  CHUNKED_AES_256_GCM_STREAM: -65793,
} as const

export const CoseHeaderParam = {
  CHUNK_SIZE: -1,
  APP_METADATA: -65792,
  PROFILE_VERSION: -65794,
} as const

export type CEKBytes = Uint8Array
export type CoseAlgorithmId = 3 | -65793

export interface AppMetadata {
  [key: string]: Uint8Array | string | number | boolean | undefined
}

export interface SimpleEncryptOptions {
  algorithm: 3
  appMetadata?: AppMetadata
}

export interface ChunkedEncryptOptions {
  algorithm: -65793
  chunkSize?: number
  appMetadata?: AppMetadata
}

export interface StreamEncryptOptions extends ChunkedEncryptOptions {
  plaintextLength: number
}

export type EncryptOptions = SimpleEncryptOptions | ChunkedEncryptOptions

export interface ByteRange {
  offset: number
  length: number
}

export interface EnvelopeMetadata {
  tag: 16
  profileVersion: 1
  algorithm: CoseAlgorithmId
  seekable: boolean
  iv: Uint8Array
  protectedHeaders: Uint8Array
  chunkSize?: number
  chunkCount?: number
  appMetadata?: AppMetadata
  envelopeSize: number
}

export interface BlobFetcher {
  getSize(): Promise<number>
  fetchRange(offset: number, length: number): Promise<Uint8Array>
}

export declare function encrypt(
  plaintext: Uint8Array,
  cek: CEKBytes,
  options: EncryptOptions
): Promise<Uint8Array>

export declare function encryptStream(
  plaintext: ReadableStream<Uint8Array>,
  cek: CEKBytes,
  options: StreamEncryptOptions
): Promise<ReadableStream<Uint8Array>>

export declare function decrypt(blob: Uint8Array, cek: CEKBytes): Promise<Uint8Array>

export declare function parseEnvelope(blob: Uint8Array): EnvelopeMetadata
export declare function parseEnvelope(fetcher: BlobFetcher): Promise<EnvelopeMetadata>

export declare function decryptRange(
  fetcher: BlobFetcher,
  metadata: EnvelopeMetadata,
  cek: CEKBytes,
  range: ByteRange
): Promise<Uint8Array>
