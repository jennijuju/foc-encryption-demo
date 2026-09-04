# Filecoin Encryption Envelope TypeScript library

## Status

This repository contains a local review candidate for the Filecoin Encryption Envelope (FEE) TypeScript library, a secret-safe protector module, and a browser viewer. It is not published, audited, or production-ready. The implemented wire profile is versioned locally and must receive independent cryptographic and browser-security review before any release-candidate claim.

The live Filecoin proposal remains [FIPs discussion #1253](https://github.com/filecoin-project/FIPs/discussions/1253), not an approved FIP or FRC. This implementation follows its Encrypt0 envelope shape, Filecoin media type, authenticated metadata direction, chunked algorithm, and chunk-size bounds while adding an explicit local profile version.

## Public interface

`packages/foc-encryption/src/index.ts` exports:

- `encrypt(plaintext, cek, options)`: encrypt a complete byte array.
- `encryptStream(stream, cek, options)`: encrypt a declared-length stream with bounded memory.
- `decrypt(blob, cek)`: decrypt a complete in-memory object.
- `decryptRange(fetcher, metadata, cek, range)`: authenticate and decrypt a plaintext-coordinate range from a seekable object.
- `parseEnvelope(blob | fetcher)`: validate the FEE v1 envelope and return authenticated metadata and derived chunk geometry.
- `createHttpBlobFetcher(url, fetch?)`: strict HTTP Range adapter.
- `deriveKey(source, salt?)`: derive a 32-byte content-encryption key from a password/access key or parse raw 32-byte hexadecimal key material.
- `CoseAlgorithm`, `CoseHeaderParam`, `MAX_CHUNK_SIZE`, typed option/result interfaces, and typed errors.

The v1 product profile supports `COSE_Encrypt0` only. Multi-recipient descriptors are not part of this release. X25519 and KMS recipient modes require a complete wrapping, unwrapping, identity, recovery, and browser design rather than opaque metadata placeholders.

## FEE v1 object

A stored object is one self-delimiting CBOR/COSE envelope followed by detached ciphertext:

```text
[COSE_Encrypt0 envelope][ciphertext]
```

The protected header map is authenticated as AES-GCM additional authenticated data. It contains:

| Label | Meaning | Rule |
|---:|---|---|
| `1` | Algorithm | `3` for AES-256-GCM or `-65793` for chunked AES-256-GCM-STREAM |
| `16` | Type | `application/vnd.filecoin-encryption+cose` |
| `-65794` | Local profile version | Integer `1` |
| `-1` | Chunk size | Required only for chunked encryption; 4 KiB through 16 MiB; default 256 KiB |
| `-65792` | Application metadata | Optional string-keyed map with bounded scalar or byte-string values |

The unprotected header map contains only label `5`, a fresh 12-byte random nonce. Changing the nonce causes authentication failure.

The envelope is limited to 1 MiB. Application metadata is limited to 32 entries, 128 characters per key, and 64 KiB per string or byte-string value. Unknown protected or unprotected parameters, wrong types, unsupported versions, wrong media types, non-nil embedded payloads, invalid array lengths, and invalid chunk geometry are rejected.

Chunk count is not stored. Consumers derive it from the authenticated chunk size and total ciphertext length. The final encrypted chunk must contain at least its 16-byte authentication tag and no more than one complete encrypted chunk.

## Chunked encryption

The chunked scheme uses algorithm `-65793`. Each object carries a fresh random 96-bit object nonce. HKDF-SHA-256 derives an object-specific AES-256-GCM key from the caller’s CEK, that nonce as salt, and the fixed info string `FEE v1 chunked AES-256-GCM object key`.

Each plaintext chunk is sealed independently under that object key. Its 96-bit AES-GCM nonce is eight zero bytes followed by the unsigned 32-bit big-endian chunk index. The one-byte external AAD is `0x01` for the final chunk and `0x00` otherwise. This authenticated final marker detects truncation. Reusing a caller CEK across objects remains safe while the 96-bit object nonce stays unique; reordering, insertion, deletion, wrong keys, changed protected metadata, or changed ciphertext causes authentication failure.

`decryptRange` accepts plaintext coordinates. It rejects ranges beyond authenticated plaintext EOF, fetches only the encrypted chunks needed for an accepted range, and caps one requested plaintext range at 16 MiB. Callers must not render or save partial plaintext after an authentication failure.

## Remote object interface

A range source implements:

```typescript
interface BlobFetcher {
  getSize(): Promise<number>
  fetchRange(offset: number, length: number): Promise<Uint8Array>
}
```

`parseEnvelope(fetcher)` starts with a 4 KiB probe and doubles it only when needed, up to the 1 MiB envelope limit. Total object size is required because chunk count and plaintext geometry are derived rather than trusted from redundant metadata.

The HTTP adapter requires status `206`, an exact safe-integer `Content-Range`, an exact requested start and end, a stable total size, and a response body whose length matches the range. It rejects ignored, shortened, oversized, inconsistent, unsafe, or malformed range responses.

## Access-key profile

The Engram protector generates an access key separately from the FEE core:

```text
engram_ + base64url(randomBytes(32))
```

The result contains 50 ASCII characters and 256 random bits. Base64url encodes only fresh random bytes. It does not encode the file, filename, Root CID, wallet, or user data. PBKDF2-SHA-256 with 600,000 iterations and a fresh 16-byte salt derives the content-encryption key. The protected ciphertext receives its Root CID afterward.

The access key never belongs in arguments, ordinary process output, logs, URLs, filenames, ledgers, rendered indexes, or agent conversation. `foc-protect.mjs` writes it only to a dedicated inherited file descriptor. Engram persists it before reporting success and copies it only after an explicit request identifying the share.

## Minimal example

```typescript
import {
  CoseAlgorithm,
  decrypt,
  encrypt,
  parseEnvelope,
} from 'foc-encryption'

const plaintext = new TextEncoder().encode('hello')
const cek = crypto.getRandomValues(new Uint8Array(32))

const encrypted = await encrypt(plaintext, cek, {
  algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
  chunkSize: 4096,
  appMetadata: { content_type: 'text/plain' },
})

const metadata = parseEnvelope(encrypted)
const restored = await decrypt(encrypted, cek)
```

Callers retain ownership of their input key buffer. The implementation wipes mutable internal copies where possible, but JavaScript cannot guarantee erasure of strings, `CryptoKey` objects, browser caches, operating-system swap, or recipient-retained plaintext.

## Agent artifact

`packages/foc-demo/dist/foc-protect.mjs` is the focused agent interface. `.mjs` is Node's explicit ES-module extension and lets the prebuilt file run without a neighboring `package.json`.

```text
node foc-protect.mjs \
  --input <file-or-directory> \
  --output <new-neutral.fee> \
  --access-key-output-fd 3
```

The process writes exactly one non-secret JSON result to stdout, diagnostics to stderr, and the generated access key only to descriptor 3. It accepts no password or key in command arguments. It rejects hard-linked sources, reads each validated source file to its exact snapshotted length, rechecks file identity and timestamps, rescans the selected tree, then writes final output through a mode-0600 temporary sibling synchronized and linked into place without overwriting an existing destination.

The source-byte preflight is not the final object limit. The generated ZIP, including its headers and directory, must also remain below 1000 MiB; a source close to the ceiling can be rejected after bounded local archive construction.

## Browser contract

The viewer accepts only `#cid=<encrypted-root-cid>`. It never accepts an access key in the URL.

- Sanitized HTML and text render through 8 MiB.
- Images, PDFs, audio, and video preview through 64 MiB.
- Larger entries use an explicit download action; they are never accumulated in a `MediaSource` preview buffer.
- Unsupported download sinks show an explicit failure. The viewer never downloads automatically and never buffers the complete large object.
- The complete protected file or folder must remain below 1000 MiB.
- Large downloads stream decrypted bytes to a supported disk sink. They never fall back to buffering the complete object.

Decrypted HTML is static. Scripts, event handlers, forms, frames, refresh, anchors, active SVG, resource/navigation URLs, parent access, and top navigation are removed. The access-key field accepts only the exact 50-character generated format. The archive exposes `close()`, closes its ZIP reader, and best-effort wipes the mutable content-encryption key after one-shot render, successful one-shot download, or page disposal; folder archives remain open only while browsing.

## Review requirements

Before any release-candidate label or external publication, an independent review must cover the wire profile, nonce and key rules, authenticated metadata, hostile CBOR/COSE parsing, range geometry, partial plaintext semantics, transactional filesystem behavior, access-key transport and recovery, archive traversal, HTML sanitization, browser download paths, dependency provenance, and reproducible builds. Passing tests and cross-implementation vectors are inputs to that review, not substitutes for it.
