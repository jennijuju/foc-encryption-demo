export type CEKBytes = Uint8Array

export interface ByteRange {
  offset: number
  length: number
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

export interface AppMetadata {
  cid?: Uint8Array
  [key: string]: Uint8Array | string | number | boolean | undefined
}

export type CoseEnvelopeTag = 16

export interface EnvelopeMetadata {
  tag: CoseEnvelopeTag
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

export type CoseAlgorithmId = 3 | -65793
