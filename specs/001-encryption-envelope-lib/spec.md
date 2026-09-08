# Filecoin Encryption Envelope v1 product profile

**Status:** Local independent-review candidate

**Standards status:** This document does not claim an approved Filecoin FIP or FRC. The active public proposal is [FIPs discussion #1253](https://github.com/filecoin-project/FIPs/discussions/1253).

## Purpose

FEE v1 defines one bounded, self-describing encrypted object for local encryption and content-addressed storage. It supports complete decryption and authenticated byte-range decryption without coupling the encrypted bytes to a storage provider or key-delivery system.

The v1 product profile supports a raw 32-byte content-encryption key and the Engram generated-access-key profile. It does not support recipient arrays, X25519, KMS, user-selected passphrases, identity authorization, or revocation.

## Object framing

```text
FEE object = COSE_Encrypt0 envelope || detached ciphertext
```

The envelope is CBOR tag 16 containing exactly:

```cddl
fee-envelope = #6.16([
  protected: bstr,
  unprotected: { 5: bstr },
  ciphertext: nil
])
```

The encoded envelope MUST be no larger than 1 MiB. A parser MUST reject a non-tagged value, any tag other than 16, an array whose length is not exactly three, a protected value that is not a byte string encoding a map, an unprotected value that is not a map, or a ciphertext field that is not `nil`.

## Protected header parameters

The protected map is authenticated through the RFC 9052 `Enc_structure` for context `Encrypt0` and empty external AAD.

| Label | Name | Type | Rule |
|---:|---|---|---|
| `1` | `alg` | integer | REQUIRED; `3` or `-65793` |
| `16` | `typ` | text | REQUIRED; exactly `application/vnd.filecoin-encryption+cose` |
| `-65794` | `profile_version` | unsigned integer | REQUIRED; exactly `1` |
| `-1` | `chunk_size` | unsigned integer | REQUIRED for algorithm `-65793`; forbidden for algorithm `3`; 4 KiB through 16 MiB |
| `-65792` | `app_metadata` | map | OPTIONAL; bounded string-keyed application metadata |

Unknown protected parameters are rejected by this product profile. A later profile version can add parameters explicitly.

## Unprotected header parameters

The unprotected map contains exactly one value:

| Label | Name | Type | Rule |
|---:|---|---|---|
| `5` | `iv` | byte string | REQUIRED; 12 bytes for algorithms `3` and `-65793` |

The nonce is unprotected because the decryptor needs it before AEAD verification. Changing it causes authentication failure. Every other unprotected parameter is rejected.

## Application metadata

`app_metadata` is visible but authenticated. It can contain at most 32 entries. Keys MUST be non-empty strings no longer than 128 characters. Values MUST be byte strings, strings, safe integers, or booleans. Strings and byte strings MUST be no larger than 64 KiB. Nested arrays or maps are rejected.

The Engram archive profile uses:

| Key | Type | Meaning |
|---|---|---|
| `pbkdf2_salt` | 16-byte string | Fresh salt for access-key derivation |
| `pbkdf2_iterations` | integer | Exactly `600000` |
| `pbkdf2_hash` | string | Exactly `SHA-256` |
| `content_type` | string | Exactly `application/zip` |
| `plaintext_size` | integer | Authenticated ZIP byte length; below 1000 MiB and equal to geometry derived from ciphertext |

Original filenames, folder paths, user identifiers, and private metadata MUST remain inside the encrypted ZIP.

## Algorithm 3: AES-256-GCM

- CEK: exactly 32 bytes and not all zero.
- Nonce: 12 fresh random bytes.
- Authentication tag: 16 bytes appended by AES-GCM.
- Ciphertext length: plaintext length plus 16.
- `chunk_size` MUST be absent.

Algorithm `3` is a library capability, not part of the Engram protected-share candidate surface. A library caller MUST use a fresh CEK per object or bound reuse far below the NIST SP 800-38D random-nonce limit of 2^32 invocations per key. The Engram profile always derives a fresh CEK per object from a fresh 16-byte PBKDF2 salt.

## Algorithm -65793: chunked AES-256-GCM-STREAM

- CEK: exactly 32 bytes and not all zero.
- Object nonce: 12 fresh random bytes.
- Chunk size: 256 KiB by default; accepted range 4 KiB through 16 MiB.
- Authentication tag: 16 bytes per chunk.
- At least one chunk is emitted, including for empty plaintext.
- Chunk count is derived from total ciphertext length and authenticated chunk size. It is not stored.

HKDF-SHA-256 derives an object-specific AES-256-GCM key from the 32-byte caller CEK, the object nonce as salt, and the exact UTF-8 info string `FEE v1 chunked AES-256-GCM object key`.

For chunk index `i`, the 12-byte AES-GCM nonce is eight zero bytes followed by `i` encoded as unsigned 32-bit big-endian. The maximum index is `2^32 - 1`. The `Enc_structure` external AAD is the single byte `0x01` for the final chunk and `0x00` for every other chunk. This authenticates the final marker and detects truncation. Object-key separation retains 96 bits of cross-object nonce uniqueness even when a caller reuses its CEK.

The final encrypted chunk MUST contain at least its 16-byte tag and no more than `chunk_size + 16` bytes. Geometry that leaves a shorter tag, an extra partial structure, or a plaintext size inconsistent with authenticated metadata is rejected before plaintext is trusted.

## Range decryption

Ranges use plaintext coordinates `[offset, offset + length)`. Offsets and lengths MUST be non-negative safe integers, and the end MUST NOT exceed the plaintext size derived from authenticated envelope geometry. One call is limited to 16 MiB of plaintext.

The decryptor derives the first and last chunk, fetches only the affected encrypted chunks, authenticates each independently, concatenates the resulting plaintext, and returns exactly the requested bytes. A failure in any affected chunk invalidates the entire requested result. Partial plaintext MUST NOT be rendered or saved.

## Remote source

A remote source reports total object size and returns exact byte ranges:

```typescript
interface BlobFetcher {
  getSize(): Promise<number>
  fetchRange(offset: number, length: number): Promise<Uint8Array>
}
```

Envelope parsing starts with 4 KiB and doubles the probe only when needed, up to 1 MiB. In-memory parsing also slices a bounded prefix before CBOR decoding. Duplicate CBOR map keys are rejected. An HTTP adapter MUST reject redirects and require status 206, exact safe-integer `Content-Range` start/end/total values, stable total size, and a body whose length exactly matches the response range. Shortened, oversized, inconsistent, ignored, malformed, and unsafe ranges are rejected.

Delivery trust is split. Ciphertext integrity never depends on the transport: every chunk is AEAD-authenticated under the recipient-derived key, so a hostile gateway can only deny service. Viewer-code integrity depends on CID-addressed delivery through an integrity-verifying in-browser gateway (the inbrowser.link service worker); that gateway origin's bootstrap page is a trusted component of the threat model and is stated as such rather than assumed. The v1 viewer fetches ciphertext from `https://<encrypted-root-cid>.ipfs.dweb.link/` while itself being served from `https://<viewerCid>.ipfs.inbrowser.link/`. The redirect rule above is absolute: the adapter rejects every redirect, with no approved-origin exception.

## Generated access-key profile

The local protector generates:

```text
engram_ || base64url(randomBytes(32))
```

The result contains 50 ASCII characters and 256 random bits. The prefix is part of the PBKDF2 input and adds no entropy. The random bytes do not encode the file, Root CID, wallet, or user data.

PBKDF2-HMAC-SHA-256 with 600,000 iterations, a fresh 16-byte salt, and 32-byte output derives the CEK. The generated access key MUST leave the protector only through its dedicated inherited file descriptor. It MUST NOT enter argv, stdout, stderr, logs, URLs, filenames, ledgers, indexes, or agent conversation.

## Failure behavior

- Wrong CEK, changed protected metadata, changed nonce, changed ciphertext, reordered chunks, inserted chunks, or removed chunks MUST fail authentication.
- Malformed structure, unsupported profile, unsupported algorithm, invalid metadata, invalid geometry, oversized values, and hostile range responses MUST fail with bounded work and typed errors.
- Final encrypted output MUST be transactional and no-overwrite. Source hard links and source changes during protection MUST be rejected. A failed or interrupted product operation MUST terminate its child and remove its private temporary directory, plaintext ZIP, and partial final object.
- JavaScript implementations MAY wipe mutable internal byte arrays on completion, but MUST NOT claim guaranteed erasure of strings, `CryptoKey` objects, browser caches, OS swap, or recipient-retained plaintext.

## Review gate

This profile requires independent review of its COSE construction, AES-GCM/nonce rules, chunked STREAM adaptation, metadata authentication, parser bounds, range geometry, secret transport, filesystem behavior, and browser consumption before any release-candidate or production-ready claim.
