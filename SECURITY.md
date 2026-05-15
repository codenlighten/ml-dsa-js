# Security policy

`ml-dsa-browser-cdn` is a cryptography library. Take vulnerability reports
seriously and report them privately.

## Reporting a vulnerability

**Do not** open public GitHub issues for security reports.

Email: **greg@smartledger.technology** (Gregory J. Ward — CTO, SmartLedger.Technology)

Please include:

- A description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept.
- The affected version (`npm ls ml-dsa-browser-cdn`, the CDN URL, or the
  commit SHA you tested against).
- Any suggested remediation, if known.

You should receive an acknowledgement within 7 days. We will work with you
to validate the report, ship a fix, and coordinate disclosure timing.

## Supported versions

Security fixes are issued against the latest minor release line on the
`main` branch.

| Version | Supported |
| ------- | --------- |
| 0.2.x   | yes       |
| < 0.2.0 | no        |

## Trust model — read before deploying

- ML-DSA (FIPS-204) is post-quantum-secure for digital signatures, but the
  surrounding implementation, key management, and runtime determine the
  real-world security posture. This library is not a substitute for proper
  key custody.
- **Browser deployments**: secret keys live in the page's JavaScript memory
  and are visible to anything else running on that page (extensions,
  injected scripts, dependency supply-chain compromises). Treat the browser
  as an untrusted environment for signing keys. For production, perform
  signing in a server, secure enclave, hardware wallet, or comparable
  trusted component.
- **Mnemonic-based derivation**: A BIP-39 mnemonic re-derives both the
  ECDSA tree and the ML-DSA tree deterministically. The mnemonic is the
  ultimate secret. Treat it like a seed phrase for a high-value wallet.
- **CDN integrity**: The repository ships verified-on-chain BSV plugin URLs
  in `local-bsv-cdn-manifest.json`. Each entry is byte-matched against
  `dist/*` by SHA-256. If you pin a specific txid you get a cryptographically
  committed artifact. If you load from jsDelivr or unpkg without subresource
  integrity (SRI), the CDN is in your trust boundary.
- **Dependencies**: All crypto primitives come from `@noble/*` and
  `@scure/*`, which are audited and widely used. Versions are exact-pinned
  in `package.json`. Run `npm audit` before deploying.

## Out of scope

- Issues in `@noble/post-quantum`, `@noble/curves`, `@noble/hashes`,
  `@scure/base`, `@scure/bip32`, or `@scure/bip39`. Report those upstream.
- Issues that require an attacker to already control the page or runtime
  (the browser deployment caveat above).
