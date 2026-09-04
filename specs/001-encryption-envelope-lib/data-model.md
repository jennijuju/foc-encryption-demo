# FEE v1 data model

This file describes the implemented local product profile. The normative behavior is in [`spec.md`](spec.md).

## Encrypted object

```text
FeeObject
├── envelope: COSE_Encrypt0 (CBOR tag 16)
└── ciphertext: detached authenticated bytes
```

The CBOR envelope is self-delimiting, so its encoded length is the ciphertext offset.

## Protected header map

```text
ProtectedHeaders
├── 1: algorithm
├── 16: "application/vnd.filecoin-encryption+cose"
├── -65794: profile version 1
├── -1: chunk size, chunked algorithm only
└── -65792: application metadata, optional
```

Every value in this map is included in the AES-GCM AAD through the RFC 9052 `Enc_structure` with context `Encrypt0`.

## Unprotected header map

```text
UnprotectedHeaders
└── 5: nonce or base nonce
```

No other unprotected parameter is accepted. Changing the nonce causes authentication failure.

## Algorithms

### AES-256-GCM

```text
SimpleBody
├── algorithm: 3
├── nonce: 12 bytes
├── plaintext: complete byte sequence
└── ciphertext: encrypted bytes + 16-byte tag
```

### Chunked AES-256-GCM-STREAM

```text
ChunkedBody
├── algorithm: -65793
├── base nonce: 7 bytes
├── chunk size: 4 KiB through 16 MiB; default 256 KiB
└── encrypted chunks: each plaintext chunk + 16-byte tag
```

Chunk count is derived from total ciphertext length. It is not stored in the envelope.

```text
chunk nonce = base_nonce[7] || chunk_index_u32_be[4] || final_flag[1]
```

## Public TypeScript values

```typescript
interface EnvelopeMetadata {
  tag: 16
  profileVersion: 1
  algorithm: 3 | -65793
  seekable: boolean
  iv: Uint8Array
  protectedHeaders: Uint8Array
  chunkSize?: number
  chunkCount?: number
  appMetadata?: AppMetadata
  envelopeSize: number
}

interface BlobFetcher {
  getSize(): Promise<number>
  fetchRange(offset: number, length: number): Promise<Uint8Array>
}
```

`chunkCount` appears in parsed metadata only after derivation from total size. It is never serialized.

## Engram archive profile

```text
ProtectedArchive
├── FEE v1 envelope
│   └── authenticated PBKDF2 and archive metadata
└── encrypted ZIP payload
    ├── original filenames and paths
    └── STORE entries, decrypted by authenticated ranges
```

The ZIP uses compression method 0 so selected entries remain range-addressable. Original names never appear in the outer FEE metadata.

The generated access key is a separate bearer secret:

```text
AccessKey = "engram_" || base64url(32 random bytes)
```

PBKDF2 combines that text with the authenticated random salt to derive the 32-byte CEK. The encrypted object receives its Root CID after encryption; the access key does not encode the CID or file.

## Removed from v1

`COSE_Encrypt` recipient arrays, `Recipient`, `RecipientInfo`, serialized chunk count, user-selected passphrases, X25519, and KMS are not part of the v1 production profile. They require a later version with end-to-end key wrapping, unwrapping, identity, recovery, and browser behavior.
