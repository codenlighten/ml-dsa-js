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

test('generateMnemonic produces valid 24-word phrase by default', () => {
  const m = MLDSA.generateMnemonic();
  assert.equal(m.trim().split(/\s+/).length, 24);
  assert.equal(MLDSA.isValidMnemonic(m), true);
});

test('generateMnemonic supports 12-word output', () => {
  const m = MLDSA.generateMnemonic({ words: 12 });
  assert.equal(m.trim().split(/\s+/).length, 12);
  assert.equal(MLDSA.isValidMnemonic(m), true);
});

test('generateMnemonic deterministic from explicit entropy', () => {
  const entropy = new Uint8Array(32).fill(1);
  const a = MLDSA.generateMnemonic({ entropy });
  const b = MLDSA.generateMnemonic({ entropy });
  assert.equal(a, b);
  assert.equal(MLDSA.isValidMnemonic(a), true);
});

test('defaultRolePaths returns hardened canonical role paths', () => {
  const paths = MLDSA.defaultRolePaths({ chain: 'bsv', account: 2, index: 9, purpose: 100 });
  assert.equal(paths.identityPath, "m/100'/236'/0'/2/9");
  assert.equal(paths.financePath, "m/100'/236'/1'/2/9");
  assert.equal(paths.tokenPath, "m/100'/236'/2'/2/9");
  assert.equal(paths.governancePath, "m/100'/236'/3'/2/9");
  assert.equal(paths.rewardsPath, "m/100'/236'/4'/2/9");
  assert.equal(paths.referralAttestPath, "m/100'/236'/5'/2/9");
  assert.equal(paths.claimAuthPath, "m/100'/236'/6'/2/9");
  assert.equal(paths.riskReviewPath, "m/100'/236'/7'/2/9");
});

test('deriveRoleKeysFromMnemonic is deterministic for same inputs', () => {
  const a = MLDSA.deriveRoleKeysFromMnemonic({
    mnemonic: mnemonic24,
    chain: 'bitcoin',
    index: 1,
    level: 65,
    addressFormat: 'p2wpkh',
  });
  const b = MLDSA.deriveRoleKeysFromMnemonic({
    mnemonic: mnemonic24,
    chain: 'bitcoin',
    index: 1,
    level: 65,
    addressFormat: 'p2wpkh',
  });

  assert.equal(a.roles.identity.address, b.roles.identity.address);
  assert.equal(a.roles.finance.address, b.roles.finance.address);
  assert.deepEqual(a.pq.publicKey, b.pq.publicKey);
  assert.equal(a.pq.path, b.pq.path);
});

test('deriveRoleKeysFromMnemonic produces distinct role keys', () => {
  const out = MLDSA.deriveRoleKeysFromMnemonic({
    mnemonic: mnemonic24,
    chain: 'bsv',
    level: 87,
  });

  assert.notEqual(out.roles.identity.address, out.roles.finance.address);
  assert.notEqual(out.roles.token.address, out.roles.governance.address);
  assert.match(out.roles.identity.wif, /^[KL5]/);
  assert.equal(out.pq.role, 'identity');
});

test('deriveRoleKeysFromMnemonic supports path overrides', () => {
  const out = MLDSA.deriveRoleKeysFromMnemonic({
    mnemonic: mnemonic24,
    chain: 'bsv',
    paths: {
      identityPath: "m/44'/236'/7'/0/3",
    },
  });

  assert.equal(out.roles.identity.path, "m/44'/236'/7'/0/3");
  assert.equal(out.roles.finance.path, "m/100'/236'/1'/0/0");
});

test('buildIdentityId deterministic and domain-separated', () => {
  const derived = MLDSA.deriveRoleKeysFromMnemonic({
    mnemonic: mnemonic24,
    chain: 'bsv',
    level: 65,
  });

  const a = MLDSA.buildIdentityId({
    ecdsaIdentityPubKey: derived.roles.identity.publicKeyCompressed,
    pqPublicKey: derived.pq.publicKey,
    version: 'v1',
    domain: 'smartledger.identity',
  });

  const b = MLDSA.buildIdentityId({
    ecdsaIdentityPubKey: derived.roles.identity.publicKeyCompressed,
    pqPublicKey: derived.pq.publicKey,
    version: 'v1',
    domain: 'smartledger.identity',
  });

  const c = MLDSA.buildIdentityId({
    ecdsaIdentityPubKey: derived.roles.identity.publicKeyCompressed,
    pqPublicKey: derived.pq.publicKey,
    version: 'v2',
    domain: 'smartledger.identity',
  });

  assert.equal(a.hex, b.hex);
  assert.notEqual(a.hex, c.hex);
  assert.match(a.base64url, /^[A-Za-z0-9_-]+$/);
});
