# Changelog

All notable changes to this project are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-05-15

### Added
- v1 conformance vectors at `test/vectors/role-derivation.v1.json`, covering the
  chain × ML-DSA-level matrix (`bitcoin` / `bsv` / `ethereum` × `44` / `65` / `87`).
  Generated via `npm run gen-vectors`; pinned by `test/vectors.test.mjs` which
  performs byte-for-byte comparison against current derivation.
- `npm run proxy:dev` script binding for the SimpleBSV proxy example.
- `npm run gen-vectors` script for regenerating frozen vectors if the scheme
  changes.
- `exports` map in `package.json` so Node and bundler consumers can import the
  package via `import 'ml-dsa-browser-cdn'`, `'ml-dsa-browser-cdn/browser'`, or
  `'ml-dsa-browser-cdn/dist/*'`.
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

[0.2.0]: https://github.com/codenlighten/ml-dsa-js/releases/tag/v0.2.0
[0.1.0]: https://github.com/codenlighten/ml-dsa-js/releases/tag/v0.1.0
