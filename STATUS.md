# STATUS

## 1. Project Overview
This project is a JavaScript browser CDN library for post-quantum ML-DSA signatures (FIPS-204 / Dilithium). The goal is to provide a straightforward API and browser global (`MLDSA`) that developers can load from a CDN for key generation, signing, and verification.

Current status: **Dual-stack mnemonic support (ECDSA + ML-DSA), EIP-55, bech32, WIF helpers, tests, CI, and repo-hosted `dist` artifacts are enabled.**

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

Milestone reached:
- **MVP source and CDN build config complete.**

## 3. Challenges
- Challenge: Choosing a reliable and lightweight ML-DSA implementation for browsers.
  - Solution: Selected `@noble/post-quantum` and validated available ML-DSA exports (`ml_dsa44`, `ml_dsa65`, `ml_dsa87`).
- Challenge: Creating a CDN-friendly API while keeping typed byte handling safe.
  - Solution: Added strict input normalization and clear errors for unsupported inputs.

## 4. Next Steps
1. Keep `dist/` updated in each release commit.
2. Define final PQ derivation path standardization strategy for interoperability.
3. Optionally add taproot / schnorr support and additional chain formats.

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
