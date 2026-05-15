import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import MLDSA from '../src/index.js';

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

const CHAINS = ['bitcoin', 'bsv', 'ethereum'];
const LEVELS = [44, 65, 87];

function buildRow(chain, level) {
  const derived = MLDSA.deriveRoleKeysFromMnemonic({
    mnemonic: MNEMONIC,
    chain,
    level,
  });

  const roles = Object.values(derived.roles).map((entry) => {
    const row = {
      role: entry.role,
      path: entry.path,
      address: entry.address,
      publicKeyHexCompressed: entry.publicKeyHexCompressed,
    };
    if (chain !== 'ethereum') row.wif = entry.wif;
    return row;
  });

  const pq = {
    role: derived.pq.role,
    level: derived.pq.level,
    path: derived.pq.path,
    publicKeyHex: bytesToHex(derived.pq.publicKey),
    secretKeySha256: bytesToHex(sha256(derived.pq.secretKey)),
  };

  const identityId = MLDSA.buildIdentityId({
    ecdsaIdentityPubKey: derived.roles.identity.publicKeyCompressed,
    pqPublicKey: derived.pq.publicKey,
    version: 'v1',
    domain: 'smartledger.identity',
  });

  return {
    chain,
    level,
    roles,
    pq,
    identityId: { hex: identityId.hex },
  };
}

const matrix = [];
for (const chain of CHAINS) {
  for (const level of LEVELS) {
    matrix.push(buildRow(chain, level));
  }
}

const out = {
  version: 'v1',
  mnemonic: MNEMONIC,
  defaults: { account: 0, index: 0, purpose: 100 },
  identityId: { version: 'v1', domain: 'smartledger.identity' },
  matrix,
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const target = resolve(__dirname, '..', 'test', 'vectors', 'role-derivation.v1.json');
writeFileSync(target, `${JSON.stringify(out, null, 2)}\n`);

console.log(`Wrote ${target} (${matrix.length} matrix rows)`);
