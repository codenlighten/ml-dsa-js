/**
 * Type declarations for @smartledger.technology/ml-dsa.
 *
 * These describe both the ESM bundle (`dist/mldsa.esm.js`) and the `MLDSA`
 * global exposed by the IIFE bundles, which share one surface.
 */

export type MlDsaLevel = 44 | 65 | 87;
export type Chain = 'bitcoin' | 'bsv' | 'ethereum';
export type AddressFormat = 'p2pkh' | 'p2wpkh';
export type EcdsaHash = 'sha256' | 'keccak256';
export type RoleName =
  | 'identity'
  | 'finance'
  | 'token'
  | 'governance'
  | 'rewards'
  | 'referralAttest'
  | 'claimAuth'
  | 'riskReview';

/** Byte input accepted anywhere this library takes raw bytes. */
export type BytesLike = Uint8Array | ArrayBuffer;
/** Message input: UTF-8 encoded when given as a string. */
export type MessageLike = string | BytesLike;

export interface MlDsaKeys {
  level: MlDsaLevel;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  publicKeyBase64: string;
  secretKeyBase64: string;
}

export interface MlDsaSignature {
  level: MlDsaLevel;
  signature: Uint8Array;
  signatureBase64: string;
}

export interface EcdsaKeys {
  chain: Chain;
  path: string;
  addressFormat?: AddressFormat;
  privateKey: Uint8Array;
  publicKeyCompressed: Uint8Array;
  publicKeyUncompressed: Uint8Array;
  privateKeyHex: string;
  publicKeyHexCompressed: string;
  publicKeyHexUncompressed: string;
  /** EIP-55 checksummed for `ethereum`; Base58Check or bech32 otherwise. */
  address: string;
  /** Present for `bitcoin` and `bsv`. */
  addressP2PKH?: string;
  /** Present for `bitcoin` only. BIP-173 v0 witness program. */
  addressBech32?: string;
}

export interface EcdsaSignature {
  hash: EcdsaHash;
  signatureCompact: Uint8Array;
  signatureDer: Uint8Array;
  signatureCompactBase64: string;
  signatureDerBase64: string;
}

export interface WifKey {
  version: number;
  compressed: boolean;
  privateKey: Uint8Array;
  privateKeyHex: string;
}

export interface RolePaths {
  identityPath: string;
  financePath: string;
  tokenPath: string;
  governancePath: string;
  rewardsPath: string;
  referralAttestPath: string;
  claimAuthPath: string;
  riskReviewPath: string;
}

export type RoleKeys = EcdsaKeys & {
  role: RoleName;
  /** Base58Check WIF of `privateKey` (Bitcoin mainnet version byte). */
  wif: string;
};

export interface RoleDerivation {
  chain: Chain;
  account: number;
  index: number;
  purpose: number;
  roles: Record<RoleName, RoleKeys>;
  pq: MlDsaKeys & { role: RoleName; level: MlDsaLevel; path: string };
}

export interface IdentityId {
  bytes: Uint8Array;
  hex: string;
  base64: string;
  base64url: string;
}

export declare const ROLE: Readonly<{
  IDENTITY: 'identity';
  FINANCE: 'finance';
  TOKEN: 'token';
  GOVERNANCE: 'governance';
  REWARDS: 'rewards';
  REFERRAL_ATTEST: 'referralAttest';
  CLAIM_AUTH: 'claimAuth';
  RISK_REVIEW: 'riskReview';
}>;

export declare function generateMnemonic(options?: {
  /** Ignored when `entropy` is supplied. */
  words?: 12 | 15 | 18 | 21 | 24;
  /** 16, 20, 24, 28, or 32 bytes, for deterministic generation. */
  entropy?: BytesLike;
}): string;

export declare function isValidMnemonic(mnemonic: string): boolean;

export declare function keygen(options?: {
  level?: MlDsaLevel;
  /** Exactly 32 bytes; omit for a randomly generated key. */
  seed?: BytesLike;
}): MlDsaKeys;

export declare function sign(
  message: MessageLike,
  secretKey: BytesLike,
  options?: { level?: MlDsaLevel }
): MlDsaSignature;

export declare function verify(
  signature: BytesLike,
  message: MessageLike,
  publicKey: BytesLike,
  options?: { level?: MlDsaLevel }
): boolean;

export declare function keygenFromMnemonic(options: {
  mnemonic: string;
  passphrase?: string;
  level?: MlDsaLevel;
  path?: string;
}): MlDsaKeys & { path: string };

export declare function ecdsaKeygenFromMnemonic(options: {
  mnemonic: string;
  passphrase?: string;
  chain?: Chain;
  /** `p2wpkh` is bitcoin-only; bsv accepts `p2pkh` only. */
  addressFormat?: AddressFormat;
  account?: number;
  change?: number;
  index?: number;
  path?: string;
}): EcdsaKeys;

export declare function ecdsaPrivateKeyToWif(
  privateKey: BytesLike,
  options?: { compressed?: boolean; version?: number }
): string;

export declare function ecdsaPrivateKeyFromWif(wif: string): WifKey;

export declare function ecdsaSign(
  message: MessageLike,
  privateKey: BytesLike,
  options?: { hash?: EcdsaHash }
): EcdsaSignature;

export declare function ecdsaVerify(
  /** 64-byte compact, or DER. */
  signature: BytesLike,
  message: MessageLike,
  publicKey: BytesLike,
  options?: { hash?: EcdsaHash }
): boolean;

export declare function deriveDualStackFromMnemonic(options: {
  mnemonic: string;
  passphrase?: string;
  chain?: Chain;
  pqLevel?: MlDsaLevel;
  ecdsaPath?: string;
  pqPath?: string;
}): { ecdsa: EcdsaKeys; pq: MlDsaKeys & { path: string } };

export declare function defaultRolePaths(options?: {
  chain?: Chain;
  account?: number;
  index?: number;
  purpose?: number;
}): RolePaths;

export declare function deriveRoleKeysFromMnemonic(options: {
  mnemonic: string;
  passphrase?: string;
  chain?: Chain;
  account?: number;
  index?: number;
  purpose?: number;
  level?: MlDsaLevel;
  pqRole?: RoleName;
  addressFormat?: AddressFormat;
  addressFormatByRole?: Partial<Record<RoleName, AddressFormat>>;
  /** Override by path key (`identityPath`) or by role name (`identity`); `pqPath` overrides the PQ leaf. */
  paths?: Partial<RolePaths> & Partial<Record<RoleName, string>> & { pqPath?: string };
}): RoleDerivation;

export declare function buildIdentityId(options: {
  ecdsaIdentityPubKey: BytesLike;
  pqPublicKey: BytesLike;
  version?: string;
  domain?: string;
}): IdentityId;

export declare function defaultEcdsaPath(
  chain: Chain,
  account?: number,
  change?: number,
  index?: number
): string;

export declare function defaultPqPath(
  level?: MlDsaLevel,
  account?: number,
  change?: number,
  index?: number
): string;

export declare function toEip55Address(lowerHexAddress: string): string;
export declare function toBase64(bytes: Uint8Array): string;
export declare function fromBase64(b64: string): Uint8Array;

/** Internal helpers, exposed for advanced/interop use. Not covered by semver. */
export declare function utils(): {
  toBase64: typeof toBase64;
  fromBase64: typeof fromBase64;
  normalizeMessage: (message: MessageLike) => Uint8Array;
  defaultEcdsaPath: typeof defaultEcdsaPath;
  defaultPqPath: typeof defaultPqPath;
  defaultRolePaths: typeof defaultRolePaths;
  toEip55Address: typeof toEip55Address;
  wordsToStrength: (words: number) => number;
  ROLE: typeof ROLE;
  roleIndices: Readonly<Record<RoleName, number>>;
};

declare const MLDSA: {
  generateMnemonic: typeof generateMnemonic;
  isValidMnemonic: typeof isValidMnemonic;
  keygen: typeof keygen;
  sign: typeof sign;
  verify: typeof verify;
  keygenFromMnemonic: typeof keygenFromMnemonic;
  ecdsaKeygenFromMnemonic: typeof ecdsaKeygenFromMnemonic;
  ecdsaSign: typeof ecdsaSign;
  ecdsaVerify: typeof ecdsaVerify;
  ecdsaPrivateKeyToWif: typeof ecdsaPrivateKeyToWif;
  ecdsaPrivateKeyFromWif: typeof ecdsaPrivateKeyFromWif;
  deriveDualStackFromMnemonic: typeof deriveDualStackFromMnemonic;
  deriveRoleKeysFromMnemonic: typeof deriveRoleKeysFromMnemonic;
  buildIdentityId: typeof buildIdentityId;
  toBase64: typeof toBase64;
  fromBase64: typeof fromBase64;
  defaultEcdsaPath: typeof defaultEcdsaPath;
  defaultPqPath: typeof defaultPqPath;
  defaultRolePaths: typeof defaultRolePaths;
  toEip55Address: typeof toEip55Address;
  ROLE: typeof ROLE;
};

export default MLDSA;

export as namespace MLDSA;
