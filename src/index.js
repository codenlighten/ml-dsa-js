import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

const variants = {
  44: ml_dsa44,
  65: ml_dsa65,
  87: ml_dsa87,
};

const encoder = new TextEncoder();

function getVariant(level = 65) {
  const variant = variants[level];
  if (!variant) {
    throw new Error(`Unsupported ML-DSA level: ${level}. Use 44, 65, or 87.`);
  }
  return variant;
}

function normalizeBytes(input, label = 'input') {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  throw new Error(`${label} must be a Uint8Array or ArrayBuffer`);
}

function normalizeMessage(message) {
  if (typeof message === 'string') return encoder.encode(message);
  return normalizeBytes(message, 'message');
}

function toBase64(bytes) {
  const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join('');
  return btoa(bin);
}

function fromBase64(b64) {
  const normalized = b64.replace(/\s+/g, '');
  const bin = atob(normalized);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function keygen(options = {}) {
  const { level = 65, seed } = options;
  const variant = getVariant(level);

  if (seed !== undefined) {
    const seedBytes = normalizeBytes(seed, 'seed');
    if (seedBytes.length !== 32) {
      throw new Error('seed must be exactly 32 bytes for ML-DSA keygen');
    }
    const keys = variant.keygen(seedBytes);
    return {
      level,
      publicKey: keys.publicKey,
      secretKey: keys.secretKey,
      publicKeyBase64: toBase64(keys.publicKey),
      secretKeyBase64: toBase64(keys.secretKey),
    };
  }

  const keys = variant.keygen();
  return {
    level,
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
    publicKeyBase64: toBase64(keys.publicKey),
    secretKeyBase64: toBase64(keys.secretKey),
  };
}

export function sign(message, secretKey, options = {}) {
  const { level = 65 } = options;
  const variant = getVariant(level);
  const msg = normalizeMessage(message);
  const sk = normalizeBytes(secretKey, 'secretKey');
  const signature = variant.sign(msg, sk);

  return {
    level,
    signature,
    signatureBase64: toBase64(signature),
  };
}

export function verify(signature, message, publicKey, options = {}) {
  const { level = 65 } = options;
  const variant = getVariant(level);
  const sig = normalizeBytes(signature, 'signature');
  const msg = normalizeMessage(message);
  const pk = normalizeBytes(publicKey, 'publicKey');
  return variant.verify(sig, msg, pk);
}

export function utils() {
  return {
    toBase64,
    fromBase64,
    normalizeMessage,
  };
}

const MLDSA = {
  keygen,
  sign,
  verify,
  toBase64,
  fromBase64,
};

export default MLDSA;
