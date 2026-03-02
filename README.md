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

## API

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

## Security notes

- ML-DSA is post-quantum, but implementation/security still depends on runtime and key management.
- Treat secret keys as sensitive and never expose them in frontend production apps.
- For production architecture, perform signing in trusted server or secure enclave components whenever possible.

## License

MIT
