# foc-viewer

A single-file browser viewer for password-encrypted content produced by `foc-encryption`. The build output is one self-contained `dist/index.html`.

## Usage

Open the viewer with one encrypted Root CID:

```text
https://<viewer-cid>.ipfs.inbrowser.link/#cid=<encrypted-root-cid>
```

The viewer validates the CID-shaped value, derives `https://<encrypted-root-cid>.ipfs.dweb.link/`, and shows a password prompt. It never accepts a password or arbitrary retrieval URL in the fragment. The entered password stays in the current page and is not written to history or browser storage.

Opening the viewer without a valid `#cid=` fragment shows an incomplete-link message.

## Content rendering

The viewer opens a STORE-method ZIP carried inside a seekable FEE envelope. Original filenames appear only after the password authenticates the encrypted central directory.

| Entry | Rendering |
|---|---|
| Self-contained HTML up to 16 MiB | Static markup in an opaque-origin iframe; scripts, handlers, refresh, forms, embedded contexts, anchors, SVG animation, and navigation/resource URLs are removed |
| Image, PDF, or text up to 16 MiB | Inline browser rendering |
| Supported audio/video above 16 MiB | Best-effort MediaSource stream; rejected containers fall back to Save |
| Any large entry | Progressive Chromium save through the File System Access API; other browsers show the compatibility message |

Folder entries are listed from authenticated range reads. Selecting one file decrypts only that entry’s ZIP ranges.

## Development

```sh
pnpm dev
pnpm build
pnpm test
pnpm typecheck
```

## Modules

1. `fragment.ts` parses and builds CID-only fragments.
2. `protected-archive.ts` validates FEE/ZIP metadata and adapts authenticated plaintext ranges to zip.js.
3. `decrypt.ts` bounds inline entry collection.
4. `sandbox.ts` creates the locked HTML iframe.
5. `save.ts` streams large entries to Chromium without a whole-file Blob.
6. `render.ts` renders bounded content and supported progressive media.
7. `ui.ts` owns the Evidence gate, password retry, folder tree, and save states.
8. `main.ts` connects the CID, password, archive, entry, and renderer paths.

## Encryption format

Protected objects must use seekable chunked FEE encryption around a STORE ZIP and include `pbkdf2_salt`, `pbkdf2_iterations=600000`, `pbkdf2_hash=SHA-256`, `content_type=application/zip`, and integer `plaintext_size` app metadata.
