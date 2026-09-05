import type { AppMetadata } from '../types.js'

/** The FEE v1 body AEAD uses the COSE_Encrypt0 RFC 9052 Section 5.3 context. */
export type EncStructureContext = 'Encrypt0'

export interface DecryptMetadata {
  chunkSize?: number
  chunkCount?: number
}

export interface EncryptionScheme {
  readonly name: string
  readonly algorithmId: number
  readonly isSeekable: boolean

  encrypt(
    key: CryptoKey,
    plaintext: Uint8Array,
    protectedHeaders: Uint8Array,
    context: EncStructureContext,
    appMetadata?: AppMetadata
  ): Promise<EncryptResult>

  decrypt(
    key: CryptoKey,
    ciphertext: Uint8Array,
    iv: Uint8Array,
    protectedHeaders: Uint8Array,
    context: EncStructureContext,
    metadata?: DecryptMetadata
  ): Promise<Uint8Array>
}

export interface EncryptResult {
  ciphertext: Uint8Array
  iv: Uint8Array
  chunkSize?: number
  chunkCount?: number
}
