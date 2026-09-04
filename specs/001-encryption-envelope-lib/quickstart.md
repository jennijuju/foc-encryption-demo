# FEE TypeScript quickstart

This quickstart uses only local non-secret key material. The repository is a local review candidate and is not published or production-ready.

## Install and build

```bash
pnpm install
pnpm --filter foc-encryption build
```

## Encrypt and decrypt in memory

```typescript
import {
  CoseAlgorithm,
  decrypt,
  encrypt,
  parseEnvelope,
} from 'foc-encryption'

const plaintext = new TextEncoder().encode('hello, filecoin')
const cek = crypto.getRandomValues(new Uint8Array(32))

const encrypted = await encrypt(plaintext, cek, {
  algorithm: CoseAlgorithm.CHUNKED_AES_256_GCM_STREAM,
  chunkSize: 4096,
  appMetadata: { content_type: 'text/plain' },
})

const metadata = parseEnvelope(encrypted)
const restored = await decrypt(encrypted, cek)
```

The parsed `chunkCount` is derived from total ciphertext length. It is not stored in the envelope.

## Decrypt a remote range

```typescript
import {
  createHttpBlobFetcher,
  decryptRange,
  parseEnvelope,
} from 'foc-encryption'

const fetcher = createHttpBlobFetcher('https://example.invalid/encrypted-object')
const metadata = await parseEnvelope(fetcher)
const bytes = await decryptRange(fetcher, metadata, cek, {
  offset: 4096,
  length: 1024,
})
```

The server must implement exact HTTP byte ranges. The adapter rejects ignored, shortened, oversized, inconsistent, or malformed responses.

## Build the agent protector

```bash
pnpm --filter foc-demo build:protect
```

The standalone agent artifact is `packages/foc-demo/dist/foc-protect.mjs`. It generates the access key and writes it only to a dedicated inherited descriptor:

```text
node packages/foc-demo/dist/foc-protect.mjs \
  --input <file-or-directory> \
  --output <new-neutral.fee> \
  --access-key-output-fd 3
```

Do not substitute a command-line access-key flag. The generated key must never enter shell history, process arguments, ordinary output, logs, or URLs.

## Viewer link

The viewer accepts only the encrypted Root CID:

```text
https://<viewer-origin>/#cid=<encrypted-root-cid>
```

The recipient pastes the separately delivered access key. The link and access key are both required. Anyone who receives both can view and forward both.

## Unsupported in v1

Multi-recipient envelopes, X25519, KMS, user-selected passphrases, password-bearing URLs, and live Filecoin automated tests are outside the v1 profile.
