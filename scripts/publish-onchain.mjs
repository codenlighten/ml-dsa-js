/**
 * Publish the dist/* bundles on-chain via the SimpleBSV API, verify each one
 * byte-for-byte through the Whatsonchain plugin endpoint, and record the
 * results in local-bsv-cdn-manifest.json.
 *
 *   node scripts/publish-onchain.mjs                 # dry run (default)
 *   node scripts/publish-onchain.mjs --broadcast     # actually spend satoshis
 *   node scripts/publish-onchain.mjs --broadcast --update-readme
 *
 * Auth: SIMPLEBSV_API_KEY (or ADMIN_API_KEY) from the environment or .env.
 * Endpoint: SIMPLEBSV_URL, default https://simplebsv.codenlighten.org.
 *
 * Dry run is the default because broadcasting spends real money and cannot be
 * undone. Nothing is written to the manifest or the README unless the bytes
 * served back by the CDN match the local bundle exactly.
 *
 * NOTE ON PAYLOAD FORMAT: `/publish/text` is the only endpoint whose schema is
 * documented by the SimpleBSV service ({ text }). Whether Whatsonchain's plugin
 * endpoint then serves that transaction with a JavaScript content type — as a
 * <script src> requires — is not something this script can know in advance, so
 * it checks and reports the served content type. Use --endpoint to switch if
 * the working bundles were published a different way.
 */
import { writeFileSync, readFileSync } from 'node:fs';

import {
  BUNDLES,
  DEFAULT_API,
  MANIFEST_PATH,
  ROOT,
  formatBytes,
  loadEnv,
  pluginUrl,
  readBundle,
  verifyTxid,
} from './onchain-lib.mjs';

loadEnv();

const args = process.argv.slice(2);
const has = (flag) => args.includes(flag);
const valueOf = (name, fallback) => {
  const hit = args.find((a) => a.startsWith(`${name}=`));
  return hit ? hit.slice(name.length + 1) : fallback;
};

const BROADCAST = has('--broadcast');
const UPDATE_README = has('--update-readme');
const ENDPOINT = valueOf('--endpoint', 'text');
const API = (process.env.SIMPLEBSV_URL || DEFAULT_API).replace(/\/+$/, '');
const API_KEY = process.env.SIMPLEBSV_API_KEY || process.env.ADMIN_API_KEY;

if (!['text', 'raw', 'json'].includes(ENDPOINT)) {
  console.error(`Unsupported --endpoint=${ENDPOINT}. Use text, raw, or json.`);
  process.exit(2);
}

function buildPayload(bundle) {
  const source = bundle.bytes.toString('utf8');
  if (ENDPOINT === 'text') return { text: source };
  if (ENDPOINT === 'json') return { json: { name: bundle.path, source } };
  // `raw` schema is not documented by the service; send the bytes plus an
  // explicit media type and let the server reject it loudly if it disagrees.
  return { data: bundle.bytes.toString('base64'), encoding: 'base64', contentType: 'application/javascript' };
}

async function api(path, { method = 'GET', body } = {}) {
  const headers = { Accept: 'application/json' };
  if (body) headers['Content-Type'] = 'application/json';
  if (API_KEY) {
    headers.Authorization = `Bearer ${API_KEY}`;
    headers['x-api-key'] = API_KEY;
  }

  const response = await fetch(`${API}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(120000),
  });

  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  if (!response.ok) {
    const detail = typeof data === 'string' ? data.slice(0, 300) : JSON.stringify(data).slice(0, 300);
    throw new Error(`${method} ${path} → HTTP ${response.status}: ${detail}`);
  }
  return data;
}

async function preflight(bundles) {
  const health = await api('/health');
  console.log(`service   : ${API} (${health.status}, ${health.wallets} wallets)`);

  const { wallets } = await api('/wallets');
  const funded = wallets.reduce((sum, w) => sum + w.balance, 0);
  console.log(`funding   : ${funded.toLocaleString()} sats across ${wallets.length} wallets`);

  const total = bundles.reduce((sum, b) => sum + b.size, 0);
  console.log(`payload   : ${bundles.length} bundles, ${formatBytes(total)} total`);
  console.log(`endpoint  : POST /publish/${ENDPOINT}?wait=true`);

  // BSV fees run well under 1 sat/byte; this is a generous ceiling, not a quote.
  const ceiling = Math.ceil(total * 1.5) + 1000 * bundles.length;
  console.log(`fee ceil. : ~${ceiling.toLocaleString()} sats (generous upper bound)`);

  if (funded < ceiling) {
    throw new Error(`insufficient funding: ${funded} sats available, ~${ceiling} may be needed`);
  }
  return { wallets };
}

async function publishOne(bundle) {
  const result = await api(`/publish/${ENDPOINT}?wait=true`, {
    method: 'POST',
    body: buildPayload(bundle),
  });

  const txid = result?.txid || result?.result?.txid;
  if (!txid) {
    throw new Error(`no txid in response: ${JSON.stringify(result).slice(0, 300)}`);
  }
  return { txid, fee: result?.fee ?? result?.result?.fee ?? null };
}

function updateReadme(entries) {
  const path = `${ROOT}/README.md`;
  let readme = readFileSync(path, 'utf8');
  let replaced = 0;

  // Replace whole plugin URLs so a stale txid cannot survive anywhere.
  const byOldest = readme.match(/plugin\/main\/[0-9a-f]{64}/g) || [];
  if (byOldest.length !== entries.length) {
    console.warn(
      `! README has ${byOldest.length} plugin URLs but ${entries.length} bundles were published; ` +
        'not rewriting. Update the README by hand.'
    );
    return 0;
  }

  // README order matches BUNDLES order: min, non-min IIFE, esm.
  entries.forEach((entry) => {
    const next = `plugin/main/${entry.txid}`;
    readme = readme.replace(/plugin\/main\/[0-9a-f]{64}/, next);
    replaced += 1;
  });

  writeFileSync(path, readme);
  return replaced;
}

async function main() {
  const bundles = BUNDLES.map(readBundle);

  console.log('ML-DSA on-chain CDN publish');
  console.log('─'.repeat(60));
  for (const b of bundles) {
    console.log(`  ${b.path.padEnd(22)} ${formatBytes(b.size).padStart(10)}  sha256 ${b.sha256.slice(0, 16)}…`);
  }
  console.log('─'.repeat(60));

  await preflight(bundles);

  if (!BROADCAST) {
    console.log('\nDry run — nothing broadcast. Re-run with --broadcast to publish.');
    return;
  }

  if (!API_KEY) {
    throw new Error('SIMPLEBSV_API_KEY (or ADMIN_API_KEY) is required to broadcast. Add it to .env.');
  }

  console.log('\nBroadcasting…');
  const entries = [];
  for (const bundle of bundles) {
    const { txid, fee } = await publishOne(bundle);
    console.log(`  ${bundle.path.padEnd(22)} txid ${txid}${fee ? ` (fee ${fee} sats)` : ''}`);
    entries.push({
      file: bundle.path,
      bytes: bundle.size,
      sha256: bundle.sha256,
      txid,
      url: pluginUrl(txid),
      fee,
    });
  }

  console.log('\nVerifying served bytes against local bundles…');
  let verified = 0;
  let unreachable = 0;
  for (const entry of entries) {
    const local = bundles.find((b) => b.path === entry.file);
    const check = await verifyTxid(entry.txid, local);
    entry.verified = check.ok;
    entry.contentType = check.contentType ?? null;

    if (check.ok) {
      verified += 1;
      console.log(`  ✓ ${entry.file.padEnd(22)} matches (served as ${check.contentType})`);
      if (!/javascript|ecmascript/i.test(check.contentType)) {
        console.warn(
          `    ! content-type is ${check.contentType} — a <script src> may refuse to execute it`
        );
      }
    } else if (!check.reachable) {
      unreachable += 1;
      console.warn(`  ? ${entry.file.padEnd(22)} unverified — ${check.reason}`);
    } else {
      console.error(`  ✗ ${entry.file.padEnd(22)} MISMATCH — ${check.reason}`);
    }
  }

  const manifest = {
    version: 'v1',
    package: JSON.parse(readFileSync(`${ROOT}/package.json`, 'utf8')).version,
    publishedAt: new Date().toISOString(),
    endpoint: `/publish/${ENDPOINT}`,
    entries,
  };
  writeFileSync(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`\nWrote ${MANIFEST_PATH}`);

  if (verified !== entries.length) {
    console.error(
      `\n${verified}/${entries.length} bundles verified (${unreachable} unreachable). ` +
        'README not updated — a txid that cannot be verified must not be documented as working.'
    );
    process.exitCode = 1;
    return;
  }

  if (UPDATE_README) {
    const n = updateReadme(entries);
    if (n) console.log(`Updated ${n} plugin URLs in README.md`);
  } else {
    console.log('\nAll bundles verified. Re-run with --update-readme to rewrite the README txids.');
  }
}

main().catch((error) => {
  console.error(`\nFailed: ${error.message}`);
  process.exit(1);
});
