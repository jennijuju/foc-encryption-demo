# Filecoin Encryption Envelope

Local TypeScript implementation of the Filecoin Encryption Envelope (FEE), with a focused agent encryptor and an immutable browser viewer.

## Status

This worktree is a local independent-review candidate. It is not published, audited, or production-ready. The future repository name selected for release is `filecoin-encryption-envelope`; no repository rename, package release, public pin, or other external action is part of this implementation.

The live format proposal is [Filecoin FIPs discussion #1253](https://github.com/filecoin-project/FIPs/discussions/1253). That discussion is not an approved FIP or FRC. The local v1 product profile corrects and versions the working implementation so it can be reviewed without claiming standards approval.

## Packages

| Package | Purpose |
|---|---|
| [`foc-encryption`](packages/foc-encryption/) | TypeScript FEE library for complete, streaming, and range-based authenticated encryption |
| [`foc-demo`](packages/foc-demo/) | Development commands plus the focused `foc-protect.mjs` agent artifact |
| [`foc-viewer`](packages/foc-viewer/) | Single-file browser viewer for password-protected file and folder shares |

The production candidate contains only the focused library, protector, viewer, specifications, types, checksums, and non-secret examples. The broader demo CLI is not a production interface because some development commands accept passwords, raw keys, or storage credentials in arguments.

## Build locally

Requires Node 20 or newer and pnpm 10.

```bash
pnpm install
pnpm build
```

Build the focused agent artifact:

```bash
pnpm --filter foc-demo build:protect
```

Build the single-file viewer:

```bash
pnpm --filter foc-viewer build
```

## Agent encryption interface

The agent runs one prebuilt ES module. The generated access key leaves only through an inherited file descriptor.

```text
node packages/foc-demo/dist/foc-protect.mjs \
  --input <file-or-directory> \
  --output <new-neutral.fee> \
  --access-key-output-fd 3
```

Stdout contains one non-secret JSON result. Stderr contains diagnostics. The access key must never enter arguments, stdout, stderr, logs, URLs, filenames, ledgers, rendered indexes, or agent conversation.

New access keys use this format:

```text
engram_ + base64url(randomBytes(32))
```

This is a 50-character opaque bearer secret with 256 random bits. It is designed for copy and paste, not manual transcription. It does not encode the file or its Root CID.

## FEE v1 profile

A FEE object is one self-delimiting COSE/CBOR envelope followed by detached ciphertext:

```text
[COSE_Encrypt0 envelope][ciphertext]
```

The v1 password-share profile:

- Authenticates algorithm, media type, profile version, chunk size, and application metadata.
- Leaves only the nonce in the unprotected map.
- Supports AES-256-GCM and chunked AES-256-GCM-STREAM.
- Uses 256 KiB chunks by default and accepts 4 KiB through 16 MiB.
- Derives chunk count from authenticated chunk size and total ciphertext length.
- Limits the encoded envelope and every metadata structure.
- Rejects multi-recipient envelopes until wrapping, unwrapping, identity, recovery, and browser support exist end to end.

See [`docs/foc-encryption-library.md`](docs/foc-encryption-library.md) for the interface and security contract.

## Browser viewer

The viewer URL contains only an encrypted Root CID:

```text
https://<viewer-origin>/#cid=<encrypted-root-cid>
```

The recipient pastes the separately delivered access key. The link alone exposes public ciphertext but cannot decrypt it. Anyone who receives both the link and the access key can view and forward both; this is bearer access, not recipient identity or revocation.

The viewer sanitizes HTML into static markup, distinguishes authentication failures from retrieval failures, bounds in-memory previews, offers explicit download fallback for unsupported large media, and exposes archive disposal so mutable key material can be wiped where JavaScript permits.

## Validation

Run focused package tests while developing. Run the complete workspace validation once after the candidate and review corrections settle.

```bash
pnpm --filter foc-encryption test
pnpm --filter foc-demo test
pnpm --filter foc-viewer test
```

Generated `.fee` smoke artifacts remain in private temporary directories and are deleted. No user-data fixture is committed. Live Filecoin state is not part of deterministic tests.

## License

Apache-2.0 OR MIT
