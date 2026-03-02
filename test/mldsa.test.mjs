import test from 'node:test';
import assert from 'node:assert/strict';

import MLDSA from '../src/index.js';

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
