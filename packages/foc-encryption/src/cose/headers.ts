export const CoseAlgorithm = {
  AES_256_GCM: 3,
  CHUNKED_AES_256_GCM_STREAM: -65793,
} as const

export const CoseHeaderParam = {
  CHUNK_SIZE: -1,
  APP_METADATA: -65792,
  PROFILE_VERSION: -65794,
} as const

// Standard COSE header labels
export const COSE_HEADER_ALG = 1
export const COSE_HEADER_KID = 4
export const COSE_HEADER_IV = 5
export const COSE_HEADER_TYP = 16

export const FEE_ENVELOPE_TYPE = 'application/vnd.filecoin-encryption+cose'
export const FEE_PROFILE_VERSION = 1
