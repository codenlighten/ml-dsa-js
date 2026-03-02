import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base58 } from '@scure/base';

const variants = {
  44: ml_dsa44,
  65: ml_dsa65,
  87: ml_dsa87,
};

const chainCoinTypes = {
  bitcoin: 0,
  bsv: 236,
  ethereum: 60,
};

const pqCoinTypes = {
  44: 9003,
  65: 9005,
  87: 9007,
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

function concatBytes(...parts) {
  const total = parts.reduce((acc, part) => acc + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function hash256(bytes) {
  return sha256(sha256(bytes));
}

function base58checkEncode(payload) {
  const checksum = hash256(payload).slice(0, 4);
  return base58.encode(concatBytes(payload, checksum));
}

function assertMnemonic(mnemonic) {
  if (typeof mnemonic !== 'string' || mnemonic.trim() === '') {
    throw new Error('mnemonic must be a non-empty string');
  }
  if (!validateMnemonic(mnemonic.trim(), wordlist)) {
    throw new Error('invalid BIP-39 mnemonic');
  }
}

function assertChain(chain) {
  if (!(chain in chainCoinTypes)) {
    throw new Error(`Unsupported chain: ${chain}. Use bitcoin, bsv, or ethereum.`);
  }
}

function defaultEcdsaPath(chain, account = 0, change = 0, index = 0) {
  assertChain(chain);
  const coinType = chainCoinTypes[chain];
  return `m/44'/${coinType}'/${account}'/${change}/${index}`;
}

function defaultPqPath(level = 65, account = 0, change = 0, index = 0) {
  const coinType = pqCoinTypes[level];
  if (!coinType) {
    throw new Error(`Unsupported ML-DSA level for path: ${level}. Use 44, 65, or 87.`);
  }
  return `m/44'/${coinType}'/${account}'/${change}/${index}`;
}

function deriveNodeFromMnemonic(mnemonic, passphrase, path) {
  assertMnemonic(mnemonic);
  const seed = mnemonicToSeedSync(mnemonic.trim(), passphrase || '');
  const root = HDKey.fromMasterSeed(seed);
  const node = root.derive(path);
  if (!node?.privateKey) {
    throw new Error(`Unable to derive private key at path: ${path}`);
  }
  return {
    seed,
    node,
  };
}

function hashForEcdsa(message, hash = 'sha256') {
  const msg = normalizeMessage(message);
  if (hash === 'sha256') return sha256(msg);
  if (hash === 'keccak256') return keccak_256(msg);
  throw new Error(`Unsupported ECDSA hash: ${hash}. Use sha256 or keccak256.`);
}

function toBase64(bytes) {
  if (typeof btoa === 'function') {
    const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join('');
    return btoa(bin);
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  throw new Error('No base64 encoder available in this runtime');
}

function fromBase64(b64) {
  const normalized = b64.replace(/\s+/g, '');
  if (typeof atob === 'function') {
    const bin = atob(normalized);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  }
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(normalized, 'base64'));
  }
  throw new Error('No base64 decoder available in this runtime');
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

export function keygenFromMnemonic(options = {}) {
  const {
    mnemonic,
    passphrase = '',
    level = 65,
    path = defaultPqPath(level),
  } = options;

  const { node } = deriveNodeFromMnemonic(mnemonic, passphrase, path);
  return {
    path,
    ...keygen({ level, seed: node.privateKey }),
  };
}

export function ecdsaKeygenFromMnemonic(options = {}) {
  const {
    mnemonic,
    passphrase = '',
    chain = 'ethereum',
    account = 0,
    change = 0,
    index = 0,
    path = defaultEcdsaPath(chain, account, change, index),
  } = options;

  const { node } = deriveNodeFromMnemonic(mnemonic, passphrase, path);
  const privateKey = node.privateKey;
  const publicKeyCompressed = secp256k1.getPublicKey(privateKey, true);
  const publicKeyUncompressed = secp256k1.getPublicKey(privateKey, false);

  let address;
  if (chain === 'ethereum') {
    const body = publicKeyUncompressed.slice(1);
    const hash = keccak_256(body);
    address = `0x${bytesToHex(hash.slice(-20))}`;
  } else {
    const version = new Uint8Array([0x00]);
    const pkHash = ripemd160(sha256(publicKeyCompressed));
    address = base58checkEncode(concatBytes(version, pkHash));
  }

  return {
    chain,
    path,
    privateKey,
    publicKeyCompressed,
    publicKeyUncompressed,
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHexCompressed: bytesToHex(publicKeyCompressed),
    publicKeyHexUncompressed: bytesToHex(publicKeyUncompressed),
    address,
  };
}

export function ecdsaSign(message, privateKey, options = {}) {
  const { hash = 'sha256' } = options;
  const digest = hashForEcdsa(message, hash);
  const pk = normalizeBytes(privateKey, 'privateKey');
  const signatureObj = secp256k1.sign(digest, pk);
  const signatureCompact = signatureObj.toCompactRawBytes();
  const signatureDer = hexToBytes(signatureObj.toDERHex());

  return {
    hash,
    signatureCompact,
    signatureDer,
    signatureCompactBase64: toBase64(signatureCompact),
    signatureDerBase64: toBase64(signatureDer),
  };
}

export function ecdsaVerify(signature, message, publicKey, options = {}) {
  const { hash = 'sha256' } = options;
  const digest = hashForEcdsa(message, hash);
  const sig = normalizeBytes(signature, 'signature');
  const pk = normalizeBytes(publicKey, 'publicKey');
  let compactSig = sig;

  if (sig.length !== 64) {
    compactSig = secp256k1.Signature.fromDER(sig).toCompactRawBytes();
  }

  return secp256k1.verify(compactSig, digest, pk);
}

export function deriveDualStackFromMnemonic(options = {}) {
  const {
    mnemonic,
    passphrase = '',
    chain = 'ethereum',
    pqLevel = 65,
    ecdsaPath,
    pqPath,
  } = options;

  const ecdsa = ecdsaKeygenFromMnemonic({
    mnemonic,
    passphrase,
    chain,
    path: ecdsaPath,
  });
  const pq = keygenFromMnemonic({
    mnemonic,
    passphrase,
    level: pqLevel,
    path: pqPath,
  });

  return {
    ecdsa,
    pq,
  };
}

export function utils() {
  return {
    toBase64,
    fromBase64,
    normalizeMessage,
    defaultEcdsaPath,
    defaultPqPath,
  };
}

const MLDSA = {
  keygen,
  sign,
  verify,
  keygenFromMnemonic,
  ecdsaKeygenFromMnemonic,
  ecdsaSign,
  ecdsaVerify,
  deriveDualStackFromMnemonic,
  toBase64,
  fromBase64,
  defaultEcdsaPath,
  defaultPqPath,
};

export default MLDSA;
