# ML-DSA Browser CDN

A JavaScript browser-friendly CDN bundle for **post-quantum ML-DSA signatures** (FIPS-204 / Dilithium) plus classic **ECDSA dual-stack**, **BIP-39 mnemonic derivation**, and **role-based key management**. Built on `@noble/post-quantum`, `@noble/curves`, and `@scure/*`.

> See [`SECURITY.md`](SECURITY.md) before deploying. This library handles signing keys; the trust model matters.

## What this provides

- ML-DSA: `keygen`, `sign`, `verify` for levels `44`, `65`, `87`.
- ECDSA (secp256k1): keygen / sign / verify, plus address derivation for Bitcoin (P2PKH + bech32), BSV (P2PKH), and Ethereum (EIP-55).
- BIP-39 mnemonic generation and validation.
- Deterministic dual-stack derivation (ECDSA + ML-DSA) from a single mnemonic.
- Role-based derivation (`identity`, `finance`, `token`, `governance`, `rewards`, `referralAttest`, `claimAuth`, `riskReview`) with frozen v1 conformance vectors.
- `buildIdentityId`: domain-separated SHA-256 identity identifier over an ECDSA + ML-DSA pair.
- Build outputs for the browser:
  - `dist/mldsa.js` — IIFE, global `MLDSA`
  - `dist/mldsa.min.js` — minified IIFE, global `MLDSA`
  - `dist/mldsa.esm.js` — ESM

## Install

### As an npm dependency (Node, bundler, or modern browser)

```bash
npm install ml-dsa-browser-cdn
```

```js
import MLDSA from 'ml-dsa-browser-cdn';
// or the minified IIFE bundle via the explicit subpath:
// import 'ml-dsa-browser-cdn/browser';
```

### From a CDN (no install)

See [Browser usage](#browser-usage-cdn) below for `unpkg`, `jsDelivr`, and on-chain `Whatsonchain` plugin URLs.

### Local development

```bash
git clone https://github.com/codenlighten/ml-dsa-js
cd ml-dsa-js
npm install
npm run check    # build + test
```

Scripts:

- `npm run build` — build `dist/*` CDN artifacts.
- `npm test` — run `node:test` suite (32 tests, including conformance vectors).
- `npm run check` — build + test.
- `npm run gen-vectors` — regenerate `test/vectors/role-derivation.v1.json`.
- `npm run proxy:dev` — start the example SimpleBSV proxy (`ADMIN_API_KEY` required).

## Browser usage (CDN)

```html
<script src="https://unpkg.com/ml-dsa-browser-cdn/dist/mldsa.min.js"></script>
<script>
  const { publicKey, secretKey } = MLDSA.keygen({ level: 65 });
  const msg = 'hello post-quantum world';
  const { signature } = MLDSA.sign(msg, secretKey, { level: 65 });
  const ok = MLDSA.verify(signature, msg, publicKey, { level: 65 });
  console.log('valid?', ok);
</script>
```

## Browser usage (direct from GitHub repo contents)

Via jsDelivr GitHub mode (recommended for direct repo files):

```html
<script src="https://cdn.jsdelivr.net/gh/codenlighten/ml-dsa-js@main/dist/mldsa.min.js"></script>
```

Pinned to a commit for deterministic builds:

```html
<script src="https://cdn.jsdelivr.net/gh/codenlighten/ml-dsa-js@e9e2034/dist/mldsa.min.js"></script>
```

You can swap `mldsa.min.js` with `mldsa.js` for the non-minified bundle.

## Browser usage (blockchain CDN via Whatsonchain plugin)

These are the verified txid-backed URLs (byte-for-byte matched against local `dist/*`):

- `mldsa.min.js`:
  - `https://plugins.whatsonchain.com/api/plugin/main/b9556de0f1dddddfacd3af3e6f01e3880b6da5d7638811d2ab87c7a33c45431e`
- `mldsa.js`:
  - `https://plugins.whatsonchain.com/api/plugin/main/3ede127085d21252b8283b64ae33d88d5b673b9e9de71cd38888ff5120728ede`
- `mldsa.esm.js`:
  - `https://plugins.whatsonchain.com/api/plugin/main/468c2a7a1e3e5e3d27226abb7b64cffdbf51cd5694b7828b137b70a5a52cbb42`

IIFE (global `MLDSA`):

```html
<script src="https://plugins.whatsonchain.com/api/plugin/main/b9556de0f1dddddfacd3af3e6f01e3880b6da5d7638811d2ab87c7a33c45431e"></script>
```

ESM:

```js
import * as MLDSA from 'https://plugins.whatsonchain.com/api/plugin/main/468c2a7a1e3e5e3d27226abb7b64cffdbf51cd5694b7828b137b70a5a52cbb42';
```

## API

### `MLDSA.generateMnemonic({ words = 24, entropy? })`

- Generates a valid BIP-39 mnemonic phrase.
- `words` can be: `12`, `15`, `18`, `21`, `24`.
- Optional `entropy` (`Uint8Array`) enables deterministic mnemonic generation:
  - 16 bytes => 12 words
  - 20 bytes => 15 words
  - 24 bytes => 18 words
  - 28 bytes => 21 words
  - 32 bytes => 24 words

### `MLDSA.isValidMnemonic(mnemonic)`

- Returns `true`/`false` for BIP-39 validity checks.

### `MLDSA.keygen({ level = 65, seed? })`

- `level`: `44 | 65 | 87`
- `seed`: optional `Uint8Array(32)` for deterministic key generation

Returns keys as bytes and Base64.

### `MLDSA.sign(message, secretKey, { level = 65 })`

- `message`: `string | Uint8Array | ArrayBuffer`
- `secretKey`: `Uint8Array | ArrayBuffer`

Returns signature as bytes and Base64.

### `MLDSA.verify(signature, message, publicKey, { level = 65 })`

Returns boolean.

### Dual-stack mnemonic APIs (ECDSA + PQ)

Use the same BIP-39 mnemonic to derive both classic ECDSA keys and post-quantum ML-DSA keys.

### `MLDSA.keygenFromMnemonic({ mnemonic, passphrase?, level?, path? })`

- Derives a deterministic 32-byte seed from mnemonic + path and generates ML-DSA keys.
- Defaults to a PQ-specific path based on level:
  - level 44: `m/44'/9003'/0'/0/0`
  - level 65: `m/44'/9005'/0'/0/0`
  - level 87: `m/44'/9007'/0'/0/0`

### `MLDSA.ecdsaKeygenFromMnemonic({ mnemonic, passphrase?, chain?, account?, change?, index?, path? })`

- Derives secp256k1 keypairs and chain-style addresses from the same mnemonic.
- Supported chains: `bitcoin`, `bsv`, `ethereum`.
- `addressFormat` options:
  - bitcoin: `p2pkh` (default), `p2wpkh` (bech32)
  - bsv: `p2pkh`
- Default BIP44 paths:
  - Bitcoin: `m/44'/0'/0'/0/0`
  - BSV: `m/44'/236'/0'/0/0`
  - Ethereum: `m/44'/60'/0'/0/0`
- Ethereum addresses are returned in EIP-55 checksum format.

### `MLDSA.ecdsaSign(message, privateKey, { hash = 'sha256' })`

- Signs with secp256k1.
- Returns compact (64-byte) and DER signatures.
- `hash` supports `sha256` or `keccak256`.

### `MLDSA.ecdsaVerify(signature, message, publicKey, { hash = 'sha256' })`

- Verifies compact or DER ECDSA signatures.

### `MLDSA.ecdsaPrivateKeyToWif(privateKey, { compressed = true, version = 0x80 })`

- Exports a 32-byte secp256k1 private key to WIF.

### `MLDSA.ecdsaPrivateKeyFromWif(wif)`

- Parses WIF and returns `{ version, compressed, privateKey, privateKeyHex }`.

### `MLDSA.deriveDualStackFromMnemonic({ mnemonic, passphrase?, chain?, pqLevel?, ecdsaPath?, pqPath? })`

- Returns both ECDSA and PQ key material in one call.

### Role-based derivation APIs (SmartLedger-ready)

### `MLDSA.ROLE`

Role constants:

- `identity`
- `finance`
- `token`
- `governance`
- `rewards`
- `referralAttest`
- `claimAuth`
- `riskReview`

### `MLDSA.defaultRolePaths({ chain = 'bsv', account = 0, index = 0, purpose = 100 })`

Returns canonical hardened role paths using:

- `m/{purpose}'/{coinType}'/{roleIndex}'/{account}/{index}`

Example (BSV):

- identity: `m/100'/236'/0'/0/0`
- finance: `m/100'/236'/1'/0/0`

### `MLDSA.deriveRoleKeysFromMnemonic(options)`

Derives deterministic ECDSA keys for all roles plus one paired PQ key.

Core options:

- `mnemonic`, `passphrase`
- `chain`, `account`, `index`, `purpose`
- `level` (PQ level: 44/65/87)
- `pqRole` (defaults to `identity`)
- `paths` (optional per-role/path overrides)
- `addressFormat` / `addressFormatByRole` (for bitcoin roles)

Returns:

- `roles.identity|finance|token|governance|rewards|referralAttest|claimAuth|riskReview`
- each role includes standard ECDSA fields plus `wif`
- `pq` bundle includes `role`, `level`, and `path`

### `MLDSA.buildIdentityId({ ecdsaIdentityPubKey, pqPublicKey, version = 'v1', domain = 'smartledger.identity' })`

Builds a deterministic, domain-separated SHA-256 identity identifier.

Returns:

- `bytes`
- `hex`
- `base64`
- `base64url`

### Example: one mnemonic, two trees

```js
const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

// In production, generate a fresh one:
// const mnemonic = MLDSA.generateMnemonic({ words: 24 });

const dual = MLDSA.deriveDualStackFromMnemonic({
  mnemonic,
  chain: 'ethereum',
  pqLevel: 65,
});

console.log('ETH address:', dual.ecdsa.address);
console.log('PQ public key bytes:', dual.pq.publicKey.length);
```

### Example: Bitcoin bech32 + WIF

```js
const btc = MLDSA.ecdsaKeygenFromMnemonic({
  mnemonic,
  chain: 'bitcoin',
  addressFormat: 'p2wpkh',
});

const wif = MLDSA.ecdsaPrivateKeyToWif(btc.privateKey);
const parsed = MLDSA.ecdsaPrivateKeyFromWif(wif);

console.log('bech32:', btc.addressBech32);
console.log('wif compressed?', parsed.compressed);
```

## Conformance vectors

Frozen v1 vectors live at [`test/vectors/role-derivation.v1.json`](test/vectors/role-derivation.v1.json), covering the `chain × ML-DSA-level` matrix (`bitcoin` / `bsv` / `ethereum` × `44` / `65` / `87`). Third-party ports can use these for byte-for-byte verification of role-derivation, role addresses, ML-DSA public keys, and `buildIdentityId` output. Regenerate via `npm run gen-vectors` if the scheme intentionally changes.

## Security notes

- ML-DSA is post-quantum, but implementation/security still depends on runtime and key management.
- Treat secret keys — especially BIP-39 mnemonics — as sensitive and never expose them in frontend production apps.
- For production architecture, perform signing in a trusted server, secure enclave, or hardware wallet whenever possible. The browser is an untrusted environment.

For reporting vulnerabilities, see [`SECURITY.md`](SECURITY.md).

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## License

[MIT](LICENSE) © Gregory J. Ward
