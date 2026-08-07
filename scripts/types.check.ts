/**
 * Compile-time check that `src/index.d.ts` matches how the library is actually
 * used. Never executed — `npm run check:types` type-checks it with `tsc --noEmit`.
 * It lives outside `test/` so the `node --test` runner does not try to run it.
 */
import MLDSA, {
  buildIdentityId,
  deriveRoleKeysFromMnemonic,
  ecdsaKeygenFromMnemonic,
  ecdsaSign,
  ecdsaVerify,
  generateMnemonic,
  keygen,
  sign,
  verify,
  ROLE,
  type EcdsaKeys,
  type MlDsaLevel,
  type RoleName,
} from '../src/index.js';

const level: MlDsaLevel = 65;

const mnemonic: string = generateMnemonic({ words: 24 });
const keys = keygen({ level });
const signature = sign('hello', keys.secretKey, { level });
const ok: boolean = verify(signature.signature, 'hello', keys.publicKey, { level });

// Messages accept strings and bytes; options are optional throughout.
sign(new Uint8Array([1, 2, 3]), keys.secretKey);
verify(signature.signature, new Uint8Array([1, 2, 3]), keys.publicKey);

const btc: EcdsaKeys = ecdsaKeygenFromMnemonic({
  mnemonic,
  chain: 'bitcoin',
  addressFormat: 'p2wpkh',
});
// `addressBech32` is bitcoin-only, so it is optional on the shared shape.
const bech32Address: string | undefined = btc.addressBech32;

const ecdsaSig = ecdsaSign('payload', btc.privateKey, { hash: 'keccak256' });
const ecdsaOk: boolean = ecdsaVerify(ecdsaSig.signatureDer, 'payload', btc.publicKeyCompressed, {
  hash: 'keccak256',
});

const derived = deriveRoleKeysFromMnemonic({
  mnemonic,
  chain: 'bsv',
  level: 87,
  pqRole: ROLE.FINANCE,
  paths: { identityPath: "m/44'/236'/7'/0/3", pqPath: "m/44'/9007'/0'/0/0" },
});

const role: RoleName = derived.roles.identity.role;
const wif: string = derived.roles.governance.wif;
const pqPath: string = derived.pq.path;

const id = buildIdentityId({
  ecdsaIdentityPubKey: derived.roles.identity.publicKeyCompressed,
  pqPublicKey: derived.pq.publicKey,
});

// The default export carries the same surface as the named exports.
const viaDefault: string = MLDSA.toEip55Address('0x0000000000000000000000000000000000000000');
const roundTripped: Uint8Array = MLDSA.fromBase64(MLDSA.toBase64(keys.publicKey));
const paths = MLDSA.defaultRolePaths({ chain: 'bitcoin', account: 1 });

export type Checked = [
  typeof ok,
  typeof ecdsaOk,
  typeof bech32Address,
  typeof role,
  typeof wif,
  typeof pqPath,
  typeof id.hex,
  typeof viaDefault,
  typeof roundTripped,
  typeof paths.identityPath,
];
