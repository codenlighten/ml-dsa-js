import test from 'node:test';
import assert from 'node:assert/strict';

import MLDSA from '../src/index.js';

const mnemonic24 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

const levels = [44, 65, 87];

for (const level of levels) {
  test(`ML-DSA-${level}: sign/verify round-trip`, () => {
    const { publicKey, secretKey } = MLDSA.keygen({ level });
    const message = `hello from level ${level}`;
    const { signature } = MLDSA.sign(message, secretKey, { level });

    assert.equal(MLDSA.verify(signature, message, publicKey, { level }), true);
  });
}

test('rejects tampered message', () => {
  const level = 65;
  const { publicKey, secretKey } = MLDSA.keygen({ level });
  const { signature } = MLDSA.sign('hello', secretKey, { level });

  assert.equal(MLDSA.verify(signature, 'hello!', publicKey, { level }), false);
});

test('base64 round-trip keeps bytes intact', () => {
  const level = 65;
  const { publicKey } = MLDSA.keygen({ level });

  const asB64 = MLDSA.toBase64(publicKey);
  const back = MLDSA.fromBase64(asB64);

  assert.deepEqual(back, publicKey);
});

test('deterministic keygen with seed', () => {
  const level = 65;
  const seed = new Uint8Array(32).fill(7);

  const a = MLDSA.keygen({ level, seed });
  const b = MLDSA.keygen({ level, seed });

  assert.deepEqual(a.publicKey, b.publicKey);
  assert.deepEqual(a.secretKey, b.secretKey);
});

test('invalid level throws', () => {
  assert.throws(() => MLDSA.keygen({ level: 99 }), /Unsupported ML-DSA level/);
});

test('invalid seed length throws', () => {
  assert.throws(
    () => MLDSA.keygen({ level: 65, seed: new Uint8Array(31) }),
    /seed must be exactly 32 bytes/
  );
});

test('mnemonic -> ML-DSA deterministic keygen', () => {
  const a = MLDSA.keygenFromMnemonic({
    mnemonic: mnemonic24,
    level: 65,
  });
  const b = MLDSA.keygenFromMnemonic({
    mnemonic: mnemonic24,
    level: 65,
  });

  assert.deepEqual(a.publicKey, b.publicKey);
  assert.deepEqual(a.secretKey, b.secretKey);
});

test('mnemonic -> ECDSA keygen deterministic ethereum address', () => {
  const a = MLDSA.ecdsaKeygenFromMnemonic({
    mnemonic: mnemonic24,
    chain: 'ethereum',
  });
  const b = MLDSA.ecdsaKeygenFromMnemonic({
    mnemonic: mnemonic24,
    chain: 'ethereum',
  });

  assert.equal(a.address, b.address);
  assert.match(a.address, /^0x[0-9a-fA-F]{40}$/);
  assert.notEqual(a.address, a.address.toLowerCase());
});

test('ECDSA sign/verify round-trip', () => {
  const keys = MLDSA.ecdsaKeygenFromMnemonic({
    mnemonic: mnemonic24,
    chain: 'bitcoin',
  });

  const msg = 'dual stack signature test';
  const { signatureCompact, signatureDer } = MLDSA.ecdsaSign(msg, keys.privateKey);

  assert.equal(
    MLDSA.ecdsaVerify(signatureCompact, msg, keys.publicKeyCompressed),
    true
  );
  assert.equal(
    MLDSA.ecdsaVerify(signatureDer, msg, keys.publicKeyCompressed),
    true
  );
});

test('deriveDualStackFromMnemonic returns both trees', () => {
  const dual = MLDSA.deriveDualStackFromMnemonic({
    mnemonic: mnemonic24,
    chain: 'bsv',
    pqLevel: 87,
  });

  assert.ok(dual.ecdsa.privateKey.length === 32);
  assert.ok(dual.pq.publicKey.length > 1000);
});

test('bitcoin bech32 address support', () => {
  const keys = MLDSA.ecdsaKeygenFromMnemonic({
    mnemonic: mnemonic24,
    chain: 'bitcoin',
    addressFormat: 'p2wpkh',
  });

  assert.match(keys.address, /^bc1/);
  assert.match(keys.addressBech32, /^bc1/);
  assert.ok(keys.addressP2PKH.length > 20);
});

test('WIF export/import round-trip', () => {
  const keys = MLDSA.ecdsaKeygenFromMnemonic({
    mnemonic: mnemonic24,
    chain: 'bitcoin',
  });

  const wif = MLDSA.ecdsaPrivateKeyToWif(keys.privateKey);
  const parsed = MLDSA.ecdsaPrivateKeyFromWif(wif);

  assert.equal(parsed.compressed, true);
  assert.deepEqual(parsed.privateKey, keys.privateKey);
});
