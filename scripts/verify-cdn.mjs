/**
 * Verify that the on-chain CDN still serves bytes identical to local dist/*.
 *
 *   node scripts/verify-cdn.mjs                  # check the manifest
 *   node scripts/verify-cdn.mjs --from-readme    # check the txids in README.md
 *   node scripts/verify-cdn.mjs --allow-offline  # don't fail when the CDN is down
 *
 * Exit codes: 0 all good, 1 a mismatch or an unreachable txid, 2 bad usage.
 *
 * A mismatch means consumers pinning that txid are being served different code
 * than this repository builds — the failure this whole scheme exists to catch.
 * Being unreachable is a weaker signal (the Whatsonchain plugin host has its
 * own outages), so --allow-offline downgrades it to a warning.
 */
import { readFileSync } from 'node:fs';

import {
  BUNDLES,
  MANIFEST_PATH,
  ROOT,
  formatBytes,
  readBundle,
  readManifest,
  verifyTxid,
} from './onchain-lib.mjs';

const args = process.argv.slice(2);
const FROM_README = args.includes('--from-readme');
const ALLOW_OFFLINE = args.includes('--allow-offline');

function targetsFromManifest() {
  const manifest = readManifest();
  if (!manifest) {
    console.error(
      `No manifest at ${MANIFEST_PATH}. Publish first, or pass --from-readme to check ` +
        'the txids currently documented.'
    );
    process.exit(2);
  }
  return manifest.entries.map((e) => ({ file: e.file, txid: e.txid }));
}

function targetsFromReadme() {
  const readme = readFileSync(`${ROOT}/README.md`, 'utf8');
  const txids = [...new Set((readme.match(/plugin\/main\/([0-9a-f]{64})/g) || []).map((m) => m.slice(12)))];
  if (!txids.length) {
    console.error('No plugin txids found in README.md.');
    process.exit(2);
  }
  if (txids.length !== BUNDLES.length) {
    console.warn(
      `! README lists ${txids.length} txids but there are ${BUNDLES.length} bundles; ` +
        'pairing them positionally.'
    );
  }
  return txids.map((txid, i) => ({ file: BUNDLES[i] ?? '(unpaired)', txid }));
}

const targets = FROM_README ? targetsFromReadme() : targetsFromManifest();
const local = new Map(BUNDLES.map((p) => [p, readBundle(p)]));

console.log(`Verifying ${targets.length} on-chain bundles against local dist/`);
console.log('─'.repeat(72));

let mismatched = 0;
let unreachable = 0;

for (const target of targets) {
  const expected = local.get(target.file);
  if (!expected) {
    console.error(`  ✗ ${target.txid.slice(0, 12)}… no local bundle for ${target.file}`);
    mismatched += 1;
    continue;
  }

  const check = await verifyTxid(target.txid, expected);
  const label = `${target.file.padEnd(20)} ${target.txid.slice(0, 12)}…`;

  if (check.ok) {
    console.log(`  ✓ ${label}  ${formatBytes(check.size)}  ${check.contentType}`);
  } else if (!check.reachable) {
    unreachable += 1;
    console.warn(`  ? ${label}  unreachable — ${check.reason}`);
  } else {
    mismatched += 1;
    console.error(`  ✗ ${label}  ${check.reason}`);
  }
}

console.log('─'.repeat(72));
const ok = targets.length - mismatched - unreachable;
console.log(`${ok} verified, ${mismatched} mismatched, ${unreachable} unreachable`);

if (mismatched) {
  console.error('\nServed bytes differ from this build. Republish or correct the documented txids.');
  process.exit(1);
}
if (unreachable && !ALLOW_OFFLINE) {
  console.error('\nSome txids could not be fetched. Re-run with --allow-offline to treat this as a warning.');
  process.exit(1);
}
