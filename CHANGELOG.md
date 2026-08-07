# Changelog

All notable changes to this project are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-08-07

### Fixed
- **`addressBech32` produced invalid Bitcoin addresses.** The bech32 encoder
  omitted the witness version, emitting a 41-character `bc1…` string instead of
  a valid 42-character BIP-173 P2WPKH address (`bc1q…`). Any address previously
  produced with `addressFormat: 'p2wpkh'` is unusable and must be regenerated —
  no wallet or node will accept it, so no funds can have been sent to one.
  Frozen v1 conformance vectors are unaffected: they record P2PKH addresses
  only, and all 9 matrix rows still match byte-for-byte.
- Lookup validation no longer resolves inherited `Object.prototype` members.
  `keygen({ level: 'constructor' })`, `defaultEcdsaPath('toString')`, and the
  role equivalents now throw the documented error instead of reaching a
  function-valued "coin type" and failing later with an opaque message.
- Replaced the deprecated `@noble/curves` `toCompactRawBytes()` / `toDERHex()` /
  `Signature.fromDER()` calls with `toBytes('compact')`, `toBytes('der')`, and
  `Signature.fromBytes(bytes, 'der')`. Signature bytes are unchanged.
- Removed the `proxy:dev` script and its README entry: it pointed at
  `examples/simplebsv-proxy-server.mjs`, which is not in the repository, so
  `npm run proxy:dev` always failed.
- `SECURITY.md` no longer cites `local-bsv-cdn-manifest.json`, which is not
  part of the repository; CDN-integrity guidance now points at the txid-pinned
  URLs in the README and notes that on-chain artifacts predate the 0.2.0
  `dist/*` banner.

### Added
- **TypeScript declarations** (`src/index.d.ts`, copied to `dist/*.d.ts` at
  build time) wired through `types` and the `exports` map, including a UMD
  `export as namespace MLDSA` for `<script>` consumers.
- `npm run check:types` — type-checks the declarations against a usage fixture
  (`scripts/types.check.ts`) with `tsc --noEmit`; now part of `npm run check`
  and `prepublishOnly`.
- `publishConfig.access: "public"` so the scoped package publishes publicly
  without an explicit `--access public` flag.
- `sideEffects` declaration for bundler tree-shaking, listing the IIFE bundles
  as side-effectful so `import '…/browser'` is never dropped.
- Tests: bech32 output is now pinned to a known-answer address and checked for
  a decodable v0 witness program; inherited-key rejection is covered for
  levels, chains, and roles. 32 → 34 tests.
- CI now runs the matrix on Node 20/22/24 and fails if committed `dist/`
  drifts from `src/` — jsDelivr's GitHub mode serves `dist/` verbatim, so drift
  ships stale code to CDN consumers.

### Changed
- **`engines.node` corrected from `>=18` to `>=20`.** Node 18 exposes no global
  `crypto`, so `@noble/hashes`' CSPRNG throws `crypto.getRandomValues must be
  defined`. Anything drawing randomness — `keygen()` without a `seed`,
  `generateMnemonic()` without `entropy` — has always failed there; the old
  declaration was inaccurate rather than newly broken. Deterministic paths
  (seeded keygen, mnemonic derivation, sign/verify) were unaffected. Node 18
  reached end-of-life in April 2025.
- `toBase64`, `fromBase64`, `defaultEcdsaPath`, `defaultPqPath`,
  `toEip55Address`, and `ROLE` are now ESM named exports as well as members of
  the default export, so the two surfaces match.

## [0.2.0] — 2026-05-15

### Changed
- **Package renamed to `@smartledger.technology/ml-dsa`** (was `ml-dsa-browser-cdn`).
  No prior version was ever published to npm under the old name, so this is
  a rename rather than a breaking change to existing consumers. The GitHub
  repository remains `codenlighten/ml-dsa-js`.

### Added
- v1 conformance vectors at `test/vectors/role-derivation.v1.json`, covering the
  chain × ML-DSA-level matrix (`bitcoin` / `bsv` / `ethereum` × `44` / `65` / `87`).
  Generated via `npm run gen-vectors`; pinned by `test/vectors.test.mjs` which
  performs byte-for-byte comparison against current derivation.
- `npm run proxy:dev` script binding for the SimpleBSV proxy example.
- `npm run gen-vectors` script for regenerating frozen vectors if the scheme
  changes.
- `exports` map in `package.json` so Node and bundler consumers can import the
  package via `import '@smartledger.technology/ml-dsa'`, `'@smartledger.technology/ml-dsa/browser'`, or
  `'@smartledger.technology/ml-dsa/dist/*'`.
- `engines.node >= 18` declaration (required for `node:test`).
- Attribution banner at the top of every `dist/*` bundle:
  `Gregory J. Ward, CTO SmartLedger.Technology — MIT`. Note that this rebuilds
  `dist/*` — the existing on-chain BSV plugin txids in
  `local-bsv-cdn-manifest.json` still serve the previous banner-less bundle and
  remain valid. Re-publishing to BSV is optional.
- `LICENSE` (MIT), `CHANGELOG.md`, `SECURITY.md` shipped in the npm tarball.
- `repository`, `homepage`, `bugs`, and `author` metadata in `package.json`.

### Changed
- `package.json` `main` now points to `dist/mldsa.esm.js` (was `dist/mldsa.js`,
  an IIFE bundle that was not consumable via Node `import`).
- `prepublishOnly` now runs `npm run check` (build + test) so a failing test
  cannot ship.
- All crypto dependencies are exact-pinned (no caret ranges) for reproducible
  releases.
- README plugin txid URLs refreshed to match `local-bsv-cdn-manifest.json`.
- Tests: now 32/32 (10 new vector tests added to the existing 22).

### Removed
- `scripts/` no longer ships in the npm tarball (`files` array trimmed).

### Notes
- This release does not change any public API or runtime behavior of `keygen`,
  `sign`, `verify`, mnemonic derivation, role derivation, or `buildIdentityId`.
  Consumers relying on the working CDN IIFE bundles are unaffected.
- Node consumers previously importing this package via the broken `main` are
  now resolved correctly. This is a fix, not a regression.

## [0.1.0] — 2026-03-05

### Added
- Initial browser CDN library for post-quantum ML-DSA (FIPS-204) signatures
  using `@noble/post-quantum`.
- `keygen`, `sign`, `verify` for ML-DSA levels 44, 65, 87.
- `dist/mldsa.esm.js`, `dist/mldsa.js`, `dist/mldsa.min.js` build outputs.
- BIP-39 mnemonic generation and validation (`generateMnemonic`,
  `isValidMnemonic`).
- Dual-stack derivation (ECDSA + ML-DSA) from a single BIP-39 mnemonic.
- ECDSA helpers for secp256k1: `ecdsaKeygenFromMnemonic`, `ecdsaSign`,
  `ecdsaVerify`, with support for Bitcoin (P2PKH + bech32), BSV (P2PKH),
  and Ethereum (EIP-55 checksum) addresses.
- WIF export/import for secp256k1 private keys.
- Role-based derivation API: `ROLE` constants, `defaultRolePaths`,
  `deriveRoleKeysFromMnemonic` for the 8 SmartLedger-canonical roles.
- `buildIdentityId` deterministic, domain-separated SHA-256 identity
  identifier.
- GitHub Actions CI (`.github/workflows/ci.yml`) running install + build +
  test on push and PR.
- Whatsonchain BSV plugin CDN URLs (byte-for-byte matched against local
  `dist/*`) recorded in `local-bsv-cdn-manifest.json`.

[0.3.0]: https://github.com/codenlighten/ml-dsa-js/releases/tag/v0.3.0
[0.2.0]: https://github.com/codenlighten/ml-dsa-js/releases/tag/v0.2.0
[0.1.0]: https://github.com/codenlighten/ml-dsa-js/releases/tag/v0.1.0
