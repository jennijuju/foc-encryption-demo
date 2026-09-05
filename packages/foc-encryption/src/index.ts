/**
 * foc-encryption implements the versioned COSE_Encrypt0 FEE profile.
 *
 * Provides complete and streaming AES-256-GCM encryption, chunked STREAM
 * construction for authenticated range decryption, strict envelope inspection,
 * and an HTTP Range adapter for Node and modern browsers.
 *
 * @packageDocumentation
 */

/** Encrypt plaintext into a COSE envelope + ciphertext blob. */
export { decrypt, decryptRange, encrypt, encryptStream, parseEnvelope } from './envelope.js'

/** COSE algorithm identifiers and header parameter labels. */
export { CoseAlgorithm, CoseHeaderParam } from './cose/headers.js'
export { MAX_CHUNK_SIZE } from './schemes/chunked-aes-256-gcm.js'

export type {
  /** Application-level metadata stored in the COSE envelope. */
  AppMetadata,
  /** Fetcher interface for range-based decryption without loading the full blob. */
  BlobFetcher,
  /** Byte range for seekable decryption (plaintext coordinates). */
  ByteRange,
  /** 32-byte content encryption key. */
  CEKBytes,
  /** Options for chunked (seekable) encryption. */
  ChunkedEncryptOptions,
  /** Union of supported COSE algorithm IDs. */
  CoseAlgorithmId,
  /** COSE envelope tags that determine the authenticated encryption context. */
  CoseEnvelopeTag,
  /** Options for encrypt(): algorithm selection and optional metadata. */
  EncryptOptions,
  /** Parsed envelope metadata — available without a decryption key. */
  EnvelopeMetadata,
  /** Options for simple (non-seekable) encryption. */
  SimpleEncryptOptions,
  /** Options for bounded-memory chunked encryption from a byte stream. */
  StreamEncryptOptions,
} from './types.js'

/** Derive a content encryption key from a password or raw hex material. */
export type { KeySource, DerivedKey } from './kdf.js'
export { deriveKey } from './kdf.js'

export {
  /** AEAD authentication failed — tampered ciphertext or wrong key. */
  AuthenticationError,
  /** Base error class for all library errors. */
  FocEncryptionError,
  /** CEK is invalid (wrong size, all zeros). */
  InvalidKeyError,
  /** COSE envelope is malformed or cannot be parsed. */
  MalformedEnvelopeError,
  /** Range decryption requested on a non-seekable scheme. */
  SchemeNotSeekableError,
  /** Encryption scheme is not recognized or not supported. */
  UnsupportedSchemeError,
} from './errors.js'
