# ML-DSA Browser CDN

A JavaScript browser-friendly CDN bundle for **post-quantum ML-DSA signatures** (FIPS-204 / Dilithium) using `@noble/post-quantum`.

## What this provides

- `MLDSA.keygen()` for key generation
- `MLDSA.sign()` for signature creation
- `MLDSA.verify()` for signature verification
- Support for ML-DSA levels: `44`, `65`, `87`
- Build outputs for CDN:
  - `dist/mldsa.js` (IIFE, global `MLDSA`)
  - `dist/mldsa.min.js` (minified IIFE, global `MLDSA`)
  - `dist/mldsa.esm.js` (ESM)

## Install

```bash
npm install
npm run build
npm test
```

## Local validation

- `npm run build` builds CDN artifacts.
- `npm test` runs round-trip tests for ML-DSA levels 44/65/87 and input edge cases.
- `npm run check` runs both build and tests.

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

## Security notes

- ML-DSA is post-quantum, but implementation/security still depends on runtime and key management.
- Treat secret keys as sensitive and never expose them in frontend production apps.
- For production architecture, perform signing in trusted server or secure enclave components whenever possible.

## License

MIT
