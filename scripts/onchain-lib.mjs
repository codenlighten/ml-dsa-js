/**
 * Shared helpers for the on-chain CDN scripts.
 *
 * The delivery model: each `dist/*` bundle is published as a BSV transaction
 * via the SimpleBSV API, then served back by Whatsonchain's plugin endpoint at
 * `https://plugins.whatsonchain.com/api/plugin/main/<txid>`. A txid is only
 * useful to a consumer if the bytes served back match the local bundle
 * exactly, so every publish is followed by a fetch-and-compare.
 */
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const MANIFEST_PATH = resolve(ROOT, 'local-bsv-cdn-manifest.json');
export const PLUGIN_BASE = 'https://plugins.whatsonchain.com/api/plugin/main';
export const DEFAULT_API = 'https://simplebsv.codenlighten.org';

/** Bundles published on-chain, in README display order. */
export const BUNDLES = ['dist/mldsa.min.js', 'dist/mldsa.js', 'dist/mldsa.esm.js'];

/**
 * Populate process.env from a local .env for any key not already set.
 * Node's --env-file only exists from 20.6, and engines allows 20.0.
 */
export function loadEnv(file = resolve(ROOT, '.env')) {
  if (!existsSync(file)) return;
  for (const raw of readFileSync(file, 'utf8').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function readBundle(relPath) {
  const bytes = readFileSync(resolve(ROOT, relPath));
  return { path: relPath, bytes, size: bytes.length, sha256: sha256Hex(bytes) };
}

export function pluginUrl(txid) {
  return `${PLUGIN_BASE}/${txid}`;
}

export function readManifest() {
  if (!existsSync(MANIFEST_PATH)) return null;
  return JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'));
}

/**
 * Fetch a published bundle back and compare it to local bytes.
 *
 * Distinguishes "the CDN is down" from "the CDN serves the wrong bytes" —
 * only the latter is a correctness failure, and callers treat them
 * differently. `contentType` is reported because a bundle served as
 * text/plain will not execute from a <script src> under nosniff.
 */
export async function verifyTxid(txid, expected, { timeoutMs = 45000 } = {}) {
  const url = pluginUrl(txid);
  let response;
  try {
    response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  } catch (error) {
    return { ok: false, reachable: false, url, reason: `fetch failed: ${error.message}` };
  }

  if (!response.ok) {
    return {
      ok: false,
      reachable: false,
      url,
      status: response.status,
      reason: `HTTP ${response.status}`,
    };
  }

  const served = Buffer.from(await response.arrayBuffer());
  const actual = sha256Hex(served);
  const contentType = response.headers.get('content-type') || '(none)';

  if (actual !== expected.sha256) {
    return {
      ok: false,
      reachable: true,
      url,
      contentType,
      reason: `sha256 mismatch: served ${actual.slice(0, 16)}… (${served.length} bytes), ` +
        `local ${expected.sha256.slice(0, 16)}… (${expected.size} bytes)`,
    };
  }

  return { ok: true, reachable: true, url, contentType, size: served.length };
}

export function formatBytes(n) {
  return `${(n / 1024).toFixed(1)} kB`;
}

export const WOC_API = 'https://api.whatsonchain.com/v1/bsv/main';

/**
 * Pull the largest OP_PUSHDATA payload out of a raw transaction.
 *
 * SimpleBSV stores a bundle as a single push in an OP_RETURN output, so the
 * largest push in the transaction is the file. This is a deliberate heuristic
 * scan rather than a full script parser — it only has to find one very large
 * push among otherwise tiny ones, and it is cross-checked against the expected
 * length by the caller.
 */
export function extractLargestPush(raw) {
  let best = null;
  for (let i = 0; i < raw.length; i += 1) {
    const op = raw[i];
    let len = 0;
    let start = 0;
    if (op === 0x4c && i + 1 < raw.length) {
      len = raw[i + 1];
      start = i + 2;
    } else if (op === 0x4d && i + 2 < raw.length) {
      len = raw.readUInt16LE(i + 1);
      start = i + 3;
    } else if (op === 0x4e && i + 4 < raw.length) {
      len = raw.readUInt32LE(i + 1);
      start = i + 5;
    } else {
      continue;
    }
    if (len > 0 && start + len <= raw.length && (!best || len > best.length)) {
      best = raw.subarray(start, start + len);
    }
  }
  return best;
}

async function fetchWithRetry(url, { attempts = 4, timeoutMs = 240000 } = {}) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
      if (response.status === 429) {
        lastError = new Error('HTTP 429 (rate limited)');
      } else if (!response.ok) {
        return { ok: false, status: response.status };
      } else {
        return { ok: true, text: await response.text() };
      }
    } catch (error) {
      lastError = error;
    }
    // WoC rate-limits bursts; back off rather than hammering it.
    await new Promise((r) => setTimeout(r, 1500 * attempt));
  }
  throw lastError ?? new Error('fetch failed');
}

/**
 * Verify a txid against local bytes using chain data instead of the plugin
 * renderer. The chain is the authoritative record — the plugin endpoint is a
 * convenience layer that can be down (or gone) while the data is still intact
 * and retrievable, so this is the check that actually matters.
 */
export async function verifyOnChain(txid, expected) {
  let result;
  try {
    result = await fetchWithRetry(`${WOC_API}/tx/${txid}/hex`);
  } catch (error) {
    return { ok: false, reachable: false, reason: `chain fetch failed: ${error.message}` };
  }
  if (!result.ok) {
    return { ok: false, reachable: false, reason: `chain API HTTP ${result.status}` };
  }

  const hex = result.text.trim();
  if (!/^[0-9a-f]+$/i.test(hex)) {
    return { ok: false, reachable: false, reason: 'chain API returned non-hex payload' };
  }

  const raw = Buffer.from(hex, 'hex');
  const payload = extractLargestPush(raw);
  if (!payload) {
    return { ok: false, reachable: true, reason: 'no pushdata payload found in transaction' };
  }

  const actual = sha256Hex(payload);
  if (actual !== expected.sha256) {
    return {
      ok: false,
      reachable: true,
      reason: `on-chain sha256 mismatch: ${actual.slice(0, 16)}… (${payload.length} bytes) ` +
        `vs local ${expected.sha256.slice(0, 16)}… (${expected.size} bytes)`,
    };
  }

  return { ok: true, reachable: true, size: payload.length, via: 'chain' };
}
