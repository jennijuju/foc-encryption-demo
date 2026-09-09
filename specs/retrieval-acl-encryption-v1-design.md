Design specification · 2026-09-08

# Retrieval ACL and encryption v1

Implementation boundaries for v1: the production FEE TypeScript library, the key model, off-chain sharing, and the consumption paths. Companions: the v1 PRD (Notion, PM-maintained: "Retrieval ACL and encryption v1"), the FEE wire specification ([001-encryption-envelope-lib/spec.md](./001-encryption-envelope-lib/spec.md)), and the two source designs referenced in section 2. Product decisions and dispositions are PM-maintained; this file is the engineering-facing snapshot.

## 1. Scope

v1 delivers off-chain sharing of encrypted data. Data is encrypted at the application layer before upload; the CID stored, proven, and served identifies ciphertext; the decryption capability travels off-chain from owner to recipient. This specification fixes the library boundary, the key and delegation model, retrieval behavior, the two consumption paths, and what v1 deliberately does not implement.

Storage contracts, provider software, PDP, and payment rails are unchanged by v1. No on-chain component is introduced.

## 2. Relationship to the two source designs

Two design documents feed v1: the on-chain design ([Truly private data with optional read auditing in FoC](https://app.notion.com/p/filecoindev/Truly-private-data-with-optional-read-auditing-in-FoC-3d1dc41950c180c9962fd4b325e8a06d)) and the earlier off-chain design ([Private dataset retrieval (very) high level design](https://app.notion.com/p/filecoindev/Private-dataset-retrieval-very-high-level-design-3badc41950c180f38ce5c90a8baa5894)). v1 implements the on-chain design's encryption and key model without its on-chain surfaces, combined with the earlier design's off-chain capability delivery. The earlier design's central assumption, that Curio evaluates read authorization over plaintext it holds, does not survive into v1: a provider can serve any byte it holds, so enforcement is cryptographic or it is nothing.

| Topic | Current v1 decision | On-chain design | Earlier off-chain design | v1 disposition |
| --- | --- | --- | --- | --- |
| Enforcement | Key possession; no retrieval gate | Key possession; chain records grants | Curio checks EIP-712 vouchers at the piece endpoint | Included in v1; voucher checking in Curio excluded from v1 |
| Data at rest | FEE ciphertext only; encrypt before upload | Identical (FEE adopted as-is, no format change) | Plaintext held by the provider | Included in v1 (on-chain design's model) |
| Retrieval path | `GET /piece/<CID>` unchanged, unauthenticated, range-capable | Identical, stated as a goal | Same endpoint plus an authorization gate (header or query auth) | Included in v1 without the gate; gated endpoints excluded from v1 |
| Key hierarchy | Wallet-derived dataset key; piece and range keys derived beneath | Identical derivation-tree concept | None | Included in v1; concrete KDF selection is an open implementation question |
| Delegation | Rewrap the dataset key under the recipient's public key; deliver off-chain | Mode A: same rewrap, posted on chain via registries | Owner-signed voucher naming the grantee; grantee signs each request | Combined: rewrap concept from the on-chain design, off-chain delivery from the earlier design; registries deferred to v2 |
| Granularity | Dataset-level and piece-level both supported; configuration dataset-oriented | Dataset-configured; per-piece keys structurally present | Dataset-level only by assertion | Included in v1; the piece-level configuration surface is an open implementation question |
| Revocation | Lazy: cycle the dataset (new key, re-encrypt, re-upload) | Mode A identical; Mode B adds forward revocation per piece | Curio-enforced expiry, no revocation | Included in v1 as documented weak revocation; forward revocation deferred to v2 |
| Read auditing | None | Mode B threshold release leaves an on-chain request record | None | Deferred to v2 |
| Key services | None; wallets are the key management | Mode B committee (Shamir shares, threshold PRF) | None | Excluded from v1; key-server designs deferred to v2 |
| Multi-recipient envelopes | Not used; one wrapped key per delegation, outside the object | Explicitly rejected (editing recipients rewrites every ciphertext) | Not applicable | Excluded from v1, permanently for the in-object map |
| Password handling | Library accepts keys; password-to-key KDF lives in an application client | Wallet keys; optional per-piece password mixed into the IV as a later extra | Not applicable | Included in v1 (key-only boundary); per-piece password extra deferred to v2 |
| Browser reading | Whole-blob buffered decryption to approximately 256 MiB; larger content downloads and decrypts locally | Not addressed | Auth in URL query for in-browser calls | Included in v1; in-browser streaming excluded from v1; secrets in URLs excluded |
| Paid retrieval | Orthogonal, untouched | Orthogonal, kept as bandwidth control | Orthogonal by assertion | Included in v1 (all agree); outside this specification |

## 3. Package and library boundary

- The FEE implementation ships as a production TypeScript library: a new package inside the existing TypeScript monorepo, with its own package name, independently importable with no dependency on the rest of the monorepo.

- The monorepo supplies publish and maintenance infrastructure only; the package does not carry the monorepo's branding and does not require its SDK.

- The library is dataset-agnostic. It has no knowledge of datasets, wallets, ACL products, storage providers, or share UX. It takes data and a key, and returns encrypted objects or plaintext.

- Callers one layer up decide where the key comes from. Two client shapes are anticipated: a password client that derives a key through a standard KDF, and a dataset-membership client that selects wallet-derived keys. Both call the same library API.

- Consumers: CLI tools, agents, browser applications, the SDK stack, FWSS-integrated products, and FCSS-class services.

- The package name is undecided (open question).

## 4. Library inputs and outputs

The library's contract, held over from the existing FEE implementation surface:

| Operation | Contract |
| --- | --- |
| Encrypt (buffer) | Plaintext bytes plus a 32-byte key produce one FEE object (envelope plus detached ciphertext). |
| Encrypt (stream) | Declared-length streaming encryption with bounded memory, chunked scheme only. |
| Decrypt (buffer) | Complete object plus key produce plaintext with full authentication. |
| Decrypt (range) | Plaintext-coordinate range decryption over a seekable source; all-or-nothing authentication of the affected chunks; partial plaintext is never returned on failure. |
| Parse envelope | Strict envelope validation returning authenticated metadata and derived geometry; bounded probing on remote sources. |
| HTTP range source | Strict range adapter over plain HTTP: exact ranges or typed failure. |
| Errors | Typed error hierarchy with stable codes; authentication failures, malformed objects, unsupported schemes, and invalid keys are distinct. |

- **Key input is a cryptographic key, not a password.** The production boundary accepts 32-byte key material. Password-to-key derivation is an application-layer function outside this boundary; the KDF path present in the existing implementation moves out of the core API.

- The caller owns key sourcing and key lifecycle; the library wipes its internal mutable copies where possible and claims nothing beyond that.

## 5. Encryption and key derivation

- Object encryption is FEE: a self-delimiting COSE envelope followed by detached ciphertext, whole-object and authenticated-range decryption, chunked AES-256-GCM scheme for seekable objects. Wire bytes are owned by the FEE specification; v1 requests no FEE format change.

- Dataset keys are deterministically derived from the owner root: an ACL key (working name) whose seed comes from a one-time funding-wallet signature over a fixed, versioned public message (off-chain signature, no transaction), stored in a local keystore (browser storage for the console, a key file for CLI and agents). Day-to-day operation uses only the keystore; a lost keystore recovers by re-signing the same message, so the keystore is a re-derivable cache and the wallet alone always suffices to regain access. No escrow blob, registry, or on-chain component exists in the owner path. Deterministic signing (RFC 6979 is signer convention, not a consensus rule) matters at issuance and recovery only; a commitment check at issuance makes a randomizing signer fail loudly (section 15). The root identity is an application-layer rule; the library accepts any key its caller supplies.

- Derivation continues down the tree: per-piece keys beneath the dataset key, per-range keys beneath pieces. Range requests keep working because the reader derives exactly the keys for the ranges it fetches. This structure exists in the FEE design already; v1 uses it, it does not invent it.

- A per-object identifier carried in the envelope serves as derivation context, binding derived keys to the object they decrypt; the on-chain design carries a per-object salt in application metadata for this purpose. The concrete context choice belongs to the KDF question (section 15).

- KDF direction: standard NIST key-derivation functions through existing COSE/TypeScript implementations, no custom constructions. The specific function selections are an open implementation question and must be pinned before anything is stored under this profile.

## 6. Dataset, piece, and range relationships

- One dataset key per dataset per key epoch. It is the granted object for dataset-level sharing.

- Every piece is individually encrypted under a key derived from the dataset key. A piece is therefore shareable on its own: piece-level sharing hands out capability at the piece node of the derivation tree without exposing siblings.

- Derivation is one-way through KDFs: a piece key does not reveal the dataset key, sibling piece keys, other datasets, or wallet material, and a dataset key does not reveal other datasets or the wallet. Grants scope by which node key is shared, never by whose public key it is wrapped under.

- Configuration is dataset-oriented: one place to configure sharing per dataset, with piece-level links achievable beneath it. How piece-level delegation surfaces in that configuration is unresolved (open question); the requirement that it must exist is settled.

- Ranges within a piece decrypt through per-range derived keys; a reader fetches only the encrypted chunks covering the requested range.

- Cycling a dataset means a new dataset key (new epoch), re-encrypting, and re-uploading. It is the rotation and the revocation mechanism.

- FEE's optional plaintext-CID envelope field is omitted by default for private data: the ciphertext is world-readable, so a cleartext plaintext CID is a confirmation-of-file and equality oracle. The mapping travels in the application manifest (reference pattern: a manifest piece encrypted under the dataset key and stored in the dataset, recoverable through the ACL key); decrypt verification against the plaintext CID is unchanged whichever side carries it. Per-dataset opt-in remains for content where revealing identity is acceptable.

## 7. Key wrapping and recipient access

- Two capability forms exist, and either form operates at either tree node (the dataset key or a piece key). A link share delivers the node's derived key directly; no recipient keypair is involved. A wallet-to-wallet delegation rewraps the same node key under the recipient's encryption public key. In both forms the shared key is the node key from the owner's derivation tree beneath the ACL key: the owner re-derives it at will from the keystore (or after wallet recovery), no share-side secret is stored, and the key never changes per recipient.

- The capability is delivered off-chain: the owner hands the recipient a link identifying the ciphertext and, separately, the key or wrapped key that unlocks it. Channels are the owner's choice. Because per-recipient keys are out of v1, all recipients of a node share one key; reissuing a link yields the same secret, and invalidating any single share means cycling the node. A leaked bare key compromises its node; a leaked wrapped key is useless without the recipient's private key.

- A recipient holding the unwrapped key decrypts everything under the granted node (dataset or piece) for as long as they keep the key. Removing a share stops future capability delivery; it does not affect a recipient who already unwrapped. Real revocation is cycling.

- The multi-recipient map inside the encrypted object is not used: membership changes must never require rewriting ciphertext. Wrapped keys live outside the object precisely so grants scale independently of the data.

- Per-recipient encryption keys, metered delegation, threshold key release, and any key-server mechanics are out of v1 (sections 13 and 14).

## 8. Retrieval and range behavior

- Ciphertext is fetched exactly as public content is fetched today: plain HTTP GET by CID against the provider or a gateway, unauthenticated, cacheable, CDN-compatible. Curio requires no modification.

- Range GETs work unchanged. The reader maps a plaintext range to encrypted chunk ranges, fetches those, authenticates, and decrypts. A failed authentication yields an error, never partial plaintext.

- No retrieval gate exists in v1. Authorization is not evaluated at the provider, and no voucher, token, or wallet signature is presented to fetch ciphertext. Bandwidth-oriented retrieval controls (paid retrieval) are a separate mechanism and are untouched.

- Transport is untrusted: authentication of the ciphertext detects tampering; a hostile gateway can only deny service.

## 9. Browser integration

- The browser path buffers the complete encrypted blob in memory, decrypts, and renders. It is limited to approximately 256 MiB.

- The cap is the consequence of excluding in-browser streaming decryption (cross-platform streaming support in browsers is not workable; WebCrypto does not stream). It is a property of this consumption path only.

- Content above the cap is not decrypted in the page: the application directs the recipient to download the ciphertext and decrypt locally.

- Share links identify ciphertext by CID. No key, password, or derived secret appears in any URL, fragment included, and none enters browser history or storage. Reference shape: `https://<viewer-cid>.ipfs.inbrowser.link/#cid=<encrypted-piece-cid>`; both components are public identifiers. The CID-addressed viewer is integrity-verified by the gateway service worker against its own CID; the gateway bootstrap page is the trusted component of this path, as stated in the FEE specification.

- Viewer pages, landing pages ("this link is protected"), share libraries, and archive-management UX are application-layer products built on the library. Their behavior is specified by their own product docs, not here. Existing application work in this area carries forward as the scale-suite layer.

## 10. Agent/CLI integration

- Writing: the agent or CLI encrypts locally through the library and uploads ciphertext through its existing storage tooling. The plaintext never enters the upload pipeline.

- Sharing: one link plus one separately delivered capability, generated without human interaction so agents can complete the flow autonomously. The capability is the node key derived from the owner's wallet-rooted tree; no flow requires a user-chosen password.

- Reading: direct fetch of the encrypted blob (curl-class HTTP by CID) followed by local decryption through the library.

- **Open: decryption behavior on this path (application-level).** The library imposes no size limit: the chunked envelope, per-range derived keys, and the range-decryption contract already give bounded-memory reading at any size up to the 64 GiB piece ceiling, composed by the caller; no library API change is required. Whether the CLI streams or buffers, and any practical cap, is CLI policy to state explicitly (section 15). The browser's 256 MiB figure does not apply here and must not be inherited by default.

## 11. Trust boundaries

| Party | Trust in v1 |
| --- | --- |
| Storage provider / Curio | Untrusted for confidentiality and for enforcement. Holds, proves, and serves ciphertext to anyone. Needs no plaintext, no keys, no changes. A freely serving provider is a bandwidth cost, not a confidentiality failure. |
| Authorizing wallet | Root of authority. Dataset keys derive from it; the payer always reads their own data; wallet compromise is total loss for that owner's data. |
| Recipient | Trusted with what they receive, permanently. A recipient who unwrapped the key keeps decrypting after access removal and can forward key or plaintext. Stated plainly in every consuming product. |
| Transport (gateways, CDNs) | Untrusted. Ciphertext authentication converts tampering into failure; denial of service is the worst outcome. |
| Chain | Not involved in v1 read paths. No grants, delegations, or key material on chain. |
| Observers | See ciphertext, sizes, timing, dataset membership, on-chain piece CIDs, and IPNI index entries. Metadata privacy is not claimed. Encrypted pieces announce to IPNI like public pieces; the index is not the privacy boundary, since the blob is reachable from chain data regardless. |

## 12. Compatibility and size constraints

- Pieces up to 64 GiB store and share normally; encryption imposes no additional storage ceiling.

- Browser consumption: approximately 256 MiB, buffered (section 9). Not a general limit.

- Agent/CLI consumption: constraints open (section 15).

- Range decryption operates at any object size; memory follows the requested range, not the object.

- Two FEE implementations exist (TypeScript and Go). They diverge today on the envelope header location of application metadata (authenticated versus not), the media-type string, label numbering, and the Go implementation's missing application-metadata API, and their range conventions differ (inclusive end versus offset-plus-length). The production library must pin one profile, reconcile or document each divergence, and record pinned versions before data is stored under this design (section 15).

- The retrieval edge is byte-identical whether a future deployment adds on-chain delegation or not: consumption paths built for v1 keep working under v2 mechanisms, which change only how a reader acquires the key.

## 13. Explicit v1 exclusions

Each exclusion is deliberate.

- **Default on-chain read-permission enforcement.** No contract evaluates or records read permission in v1.

- **Per-piece on-chain delegation records as the default model.** Contract-local storage scaling rules them out as a default; one dataset with tens of thousands of pieces must not mean tens of thousands of records.

- **Read-permission delegation in default FWSS behavior.** Delegation never enters the FWSS core default; a future on-chain mechanism is opt-in at the application level.

- **The multi-recipient map from the POC.** Recipient lists inside the encrypted object require rewrapping and re-onboarding data on membership changes; dropped.

- **Per-recipient encryption keys as the v1 access model.** v1 wraps one dataset key per recipient rather than encrypting per recipient.

- **Metered or strongly revocable delegation.** Requires key-release infrastructure that v1 does not build.

- **MPC, Shamir key servers, and key-management services.** No committee or threshold infrastructure; wallets are the KMS.

- **Passwords as the library primitive.** The production library accepts keys only.

- **User-chosen passwords as a required mechanism.** Secrets are system-generated wherever a flow needs one; a password option, where a product adds one, is an application-layer convenience through a KDF.

- **A separate KMS for v1.** None is introduced.

- **A user-safeguarded recovery artifact.** Nothing beyond the funding wallet must be protected to keep data recoverable: no exported seed, recovery file, or secondary password is required of the user. The local ACL keystore is a re-derivable cache; losing it loses nothing.

- **Trusting Curio or a storage provider with plaintext.** Providers never hold plaintext; designs that assume otherwise do not carry forward.

- **A retrieval gate for ciphertext in v1.** No authorization is evaluated at the piece endpoint; anyone fetches ciphertext by CID. A provider-side check cannot bind the provider, so it is never the confidentiality mechanism. Deferred as a courtesy layer (section 14).

- **In-browser streaming decryption.** Excluded for v1; the browser path is buffered and capped.

- **Viewer and share-management UX inside the FEE library.** The library ships no UI; viewers, landing pages, and share libraries are applications.

## 14. Deferred mechanisms

Deferred means possibly added later, on top of v1, without changing v1's stored objects.

- **Optional on-chain delegation for application builders.** Expresses off-chain grants safely on chain as a stackable, opt-in feature.

- **A reference application-level delegation contract**: template contract deployed as a clone, each client paying its own enforcement costs. Sketched, not specced.

- **Per-recipient keys and stronger revocation.**

- **Metered delegation and key-server designs**: threshold key release by a committee, per-read on-chain records, forward revocation without re-upload.

- **Per-piece password mixed into the IV** through a KDF, layered on top of on-chain delegation.

- **Fetch-gating of ciphertext retrieval (courtesy access layer).** Retrieval-endpoint authorization (dataset privacy flag plus signed request vouchers, per the earlier off-chain design, riding the paid-retrieval gate machinery) so unauthorized parties cannot download even ciphertext. Motivated by enterprise and compliance expectations and by reducing metadata probing and ciphertext harvesting; layers on top of encryption and never becomes the enforcement mechanism against the provider.

## 15. Open implementation questions

- **Package name** for the production library.

- **Piece-level delegation surface.** The derivation tree makes piece keys available; the dataset-oriented configuration needs a defined way to issue piece-level capability, and its complexity is unassessed.

- **ACL-key implementation details.** The signed message: EIP-712 typed data (settled); the domain separator and message shape remain to pin (working shape: `foc/read/v1 master seed`), plus the commitment-check mechanism and where the non-secret commitment lives, keystore formats per surface (browser storage, CLI key file), and rotation semantics. The category's user-facing name is not final ("ACL key" is the working term).

- **Agent/CLI decryption behavior (application-level).** Streaming versus buffered and any practical cap are CLI policy: the library imposes no limit and range decryption composes into chunk-at-a-time reading at any size. State the CLI's choice explicitly; the browser cap must not be silently inherited.

- **KDF selection.** Pin the specific NIST KDF constructions (and their COSE/TypeScript implementations) for wallet-based dataset-key derivation and for the application-layer password client.

- **Recipient key discovery and wrapping construction.** The rewrap path targets a recipient encryption public key, but v1 has no registry to look one up, hardware wallets do not perform key agreement with their signing keys, and contract accounts hold no key. Define how the owner obtains the recipient key and the exact wrapping encoding so hardware and contract wallets are not excluded.

- **FEE implementation reconciliation.** Resolve the TypeScript/Go divergences of section 12, decide where application metadata lives (authenticated header placement), and pin implementation versions before first storage.

- **Ciphertext addressing versus the IPFS layer.** Encryption breaks plaintext-CID addressing of UnixFS content. The manifest pattern (section 6) carries the mapping for sharing flows; open is the UnixFS/filecoin-pin integration itself: a parallel manifest path versus block-level encryption at another layer. Gates products built on filecoin-pin.
