# STATUS

## 1. Project Overview
This project is a JavaScript browser CDN library for post-quantum ML-DSA signatures (FIPS-204 / Dilithium). The goal is to provide a straightforward API and browser global (`MLDSA`) that developers can load from a CDN for key generation, signing, and verification.

Current status: **Dual-stack mnemonic support (ECDSA + ML-DSA), mnemonic generation, EIP-55, bech32, WIF helpers, role-based derivation with frozen v1 conformance vectors, tests, CI, and repo-hosted `dist` artifacts are enabled.**

## 2. Progress
Completed:
- Initialized project scaffolding (`package.json`, source, build script).
- Implemented browser API in `src/index.js`:
  - `keygen({ level, seed })`
  - `sign(message, secretKey, { level })`
  - `verify(signature, message, publicKey, { level })`
  - base64 helpers for transport
- Added build system with esbuild:
  - `dist/mldsa.esm.js`
  - `dist/mldsa.js`
  - `dist/mldsa.min.js`
- Added project documentation in `README.md`.
- Installed dependencies and generated `dist` artifacts successfully.
- Executed smoke test (`keygen -> sign -> verify`) with successful verification.
- Added automated tests (`node:test`) covering levels 44/65/87, tamper checks, base64 round-trip, and keygen validation.
- Added GitHub Actions workflow at `.github/workflows/ci.yml` to run install/build/test on push and pull requests.
- Ran `npm run check` successfully (`build + test`, 8/8 tests passing).
- Enabled direct artifact consumption from repository contents by tracking `dist/` in git.
- Added README examples for jsDelivr GitHub mode URLs.
- Added mnemonic-based dual-stack API for classic ECDSA + post-quantum ML-DSA key derivation.
- Added ECDSA helpers (`ecdsaKeygenFromMnemonic`, `ecdsaSign`, `ecdsaVerify`, `deriveDualStackFromMnemonic`).
- Expanded tests to 12/12 passing, including deterministic mnemonic derivation and dual-stack checks.
- Added Ethereum EIP-55 checksum address output.
- Added Bitcoin bech32 (`p2wpkh`) support alongside legacy `p2pkh`.
- Added WIF export/import helpers for secp256k1 private keys.
- Added user-facing mnemonic generation and validation APIs (`generateMnemonic`, `isValidMnemonic`).
- Added role-based derivation APIs:
  - `ROLE` constants for canonical app roles
  - `defaultRolePaths()` hardened role path helper
  - `deriveRoleKeysFromMnemonic()` multi-role deterministic derivation
  - `buildIdentityId()` domain-separated SHA-256 identity identifier helper
- Expanded tests for role path derivation, deterministic role-key generation, path overrides, and identity ID determinism.
- Updated README with role-based API docs and usage guidance.
- Froze v1 conformance vectors at `test/vectors/role-derivation.v1.json` covering chain ∈ {bitcoin, bsv, ethereum} × level ∈ {44, 65, 87}.
- Added `scripts/gen-vectors.mjs` regeneration helper and `test/vectors.test.mjs` byte-for-byte comparison test.
- Packaging hardened in v0.2.0: `main` points to ESM bundle, `exports` map added, `engines.node >= 18`, crypto deps exact-pinned, `prepublishOnly` runs `check` (build + test).
- Tests now 32/32 passing.
- Published `dist/mldsa.min.js`, `dist/mldsa.js`, and `dist/mldsa.esm.js` to SimpleBSV using B-format OP_RETURN fields:
  - `19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAutN`
  - `[Data]`, `[Media Type]`, `[Encoding]`, `[Filename]`
- Verified on-chain plugin payloads are byte-identical to local `dist/*` (SHA-256 + size match).
- Updated `local-bsv-cdn-manifest.json` and README plugin URLs to latest txids.

Milestone reached:
- **MVP source and CDN build config complete.**

## 3. Challenges
- Challenge: Choosing a reliable and lightweight ML-DSA implementation for browsers.
  - Solution: Selected `@noble/post-quantum` and validated available ML-DSA exports (`ml_dsa44`, `ml_dsa65`, `ml_dsa87`).
- Challenge: Creating a CDN-friendly API while keeping typed byte handling safe.
  - Solution: Added strict input normalization and clear errors for unsupported inputs.

## 4. Next Steps
1. Keep `dist/` updated in each release commit.
2. Optionally add taproot / schnorr support and additional chain formats.
3. Add a repeatable publish script for SimpleBSV raw B-format publishing to reduce manual release steps.
4. Publish v0.2.0 to npm.

Timeline:
- Dist artifact updates: every change that affects runtime bundle
- Path standardization guidance: immediate follow-up
- Extended ECDSA format support: short follow-up

## 5. Team Members
- Gregory J. Ward — Project owner / CTO / product direction
- GitHub Copilot — Implementation assistant (scaffold, API, docs, build setup)

## 6. Resources
- Runtime/library: `@noble/post-quantum`
- Build tool: `esbuild`
- CI: GitHub Actions
- Standards reference: NIST FIPS-204 (ML-DSA)
- Package research source: npm package metadata and readme

## 7. Conclusion
The project now has a working browser CDN ML-DSA library with successful local build/test validation and CI checks configured. It is ready for release automation and package publishing.
