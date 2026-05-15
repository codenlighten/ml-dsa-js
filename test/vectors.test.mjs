import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import MLDSA from '../src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(resolve(__dirname, 'vectors', 'role-derivation.v1.json'), 'utf8')
);

test('conformance vectors: top-level metadata is intact', () => {
  assert.equal(vectors.version, 'v1');
  assert.equal(vectors.defaults.account, 0);
  assert.equal(vectors.defaults.index, 0);
  assert.equal(vectors.defaults.purpose, 100);
  assert.equal(vectors.identityId.version, 'v1');
  assert.equal(vectors.identityId.domain, 'smartledger.identity');
  assert.equal(vectors.matrix.length, 9);
});

for (const row of vectors.matrix) {
  test(`vectors: ${row.chain}/level-${row.level} matches frozen output`, () => {
    const derived = MLDSA.deriveRoleKeysFromMnemonic({
      mnemonic: vectors.mnemonic,
      chain: row.chain,
      level: row.level,
    });

    for (const expected of row.roles) {
      const actual = derived.roles[expected.role];
      assert.ok(actual, `missing role ${expected.role}`);
      assert.equal(actual.path, expected.path, `${expected.role} path`);
      assert.equal(actual.address, expected.address, `${expected.role} address`);
      assert.equal(
        actual.publicKeyHexCompressed,
        expected.publicKeyHexCompressed,
        `${expected.role} pubkey`
      );
      if (expected.wif !== undefined) {
        assert.equal(actual.wif, expected.wif, `${expected.role} wif`);
      }
    }

    assert.equal(derived.pq.role, row.pq.role);
    assert.equal(derived.pq.level, row.pq.level);
    assert.equal(derived.pq.path, row.pq.path);
    assert.equal(
      bytesToHex(derived.pq.publicKey),
      row.pq.publicKeyHex,
      'pq publicKey'
    );
    assert.equal(
      bytesToHex(sha256(derived.pq.secretKey)),
      row.pq.secretKeySha256,
      'pq secretKey sha256'
    );

    const identityId = MLDSA.buildIdentityId({
      ecdsaIdentityPubKey: derived.roles.identity.publicKeyCompressed,
      pqPublicKey: derived.pq.publicKey,
      version: vectors.identityId.version,
      domain: vectors.identityId.domain,
    });
    assert.equal(identityId.hex, row.identityId.hex, 'identityId.hex');
  });
}
