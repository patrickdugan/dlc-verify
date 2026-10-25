/**
 * Research-only BIP341 two-leaf proposal for an opt-in Ducat vault.
 *
 * Composes the existing canonical Ducat 2-of-2 cosign leaf with the proposed
 * three-signer option leaf. Reconstructs the entire two-leaf Merkle tree,
 * P2TR scriptPubKey, both control blocks, and output-key parity.
 *
 * Security boundary: this verifies a COMPLETE PROPOSED TWO-LEAF TREE.
 * It cannot prove that the Taproot internal key has no known private key,
 * that there are no key-path signers, or that an actual UTXO uses this tree.
 * A CET and all option claims remain unauthenticated by this module.
 */
import { createHash } from 'node:crypto';
import { matchOptionLeaf } from './ducat-option';

type Secp256k1 = {
  publicKeyVerify: (pubkey: Uint8Array) => boolean;
  publicKeyTweakAdd: (pubkey: Uint8Array, tweak: Uint8Array, compressed?: boolean) => Uint8Array;
};
// Existing dlc-verify dependency. This is used only for PUBLIC elliptic-curve
// arithmetic; no secret keys or signing are handled.
const secp = require('secp256k1') as Secp256k1;

const XONLY = /^[0-9a-f]{64}$/u;
const CANONICAL_DUCAT_COSIGN = /^20([0-9a-f]{64})ad20([0-9a-f]{64})ac$/u;
const CURVE_ORDER = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const TAPROOT_LEAF_VERSION = 0xc0;
/** BIP341's publicly specified Nothing-Up-My-Sleeve x-coordinate. */
export const BIP341_NUMS_XONLY = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0';


export type OptionVaultProposal = {
  /** x-only key used to derive the tweaked Taproot output. */
  internalKeyXOnly: string;
  /** Reveal a BIP341 NUMS blinding scalar r; the internal key must equal x(H+rG). */
  numsBlindingScalarHex?: string;
  /** Exact current Ducat cosign shape without the optional Ord envelope. */
  ducatCosignScriptHex: string;
  /** Exact option leaf exported by constructOptionLeaf. */
  optionScriptHex: string;
  /** Borrower key from a separately authenticated wallet account. */
  expectedBorrowerXOnly: string;
  /** Guardian x-only key from a separately authenticated allowlist. */
  expectedGuardianXOnly: string;
};
export type FullTwoLeafManifest = {
  treeKind: 'ducat-cosign+candidate-option/v1';
  status: 'review-only';
  scriptPubKeyHex: string;
  outputKeyXOnly: string;
  outputParity: 0 | 1;
  merkleRootHex: string;
  cosignLeafHash: string;
  optionLeafHash: string;
  cosignControlBlockHex: string;
  optionControlBlockHex: string;
  // x-only internal key ownership cannot be derived from its 32-byte value.
  keyPathSpendability: 'unproven' | 'nums-derived';
  // Taproot alone does not enforce the contingent outputs of a DLC.
  cetEnforcement: 'unimplemented';
};

/** Tagged hash as specified by BIP340 and BIP341. */
function taggedHash(tag: string, bytes: Uint8Array): Buffer {
  const t = createHash('sha256').update(Buffer.from(tag, 'ascii')).digest();
  return createHash('sha256').update(Buffer.concat([t, t, Buffer.from(bytes)])).digest();
}
function pubkey(hex: string, label: string): Buffer {
  if (!XONLY.test(hex)) throw Error(label + ': expected 32-byte lowercase x-only key');
  const out = Buffer.from('02' + hex, 'hex');
  if (!secp.publicKeyVerify(out)) throw Error(label + ': invalid curve x-coordinate');
  return Buffer.from(hex, 'hex');
}
function leafHash(scriptHex: string): Buffer {
  if (!/^(?:[0-9a-f]{2})+$/u.test(scriptHex)) throw Error('non-canonical leaf script');
  const bytes = Buffer.from(scriptHex, 'hex');
  if (bytes.length >= 253) throw Error('leaf too long for compactSize(1) in this verifier');
  return taggedHash('TapLeaf', Buffer.concat([Buffer.from([TAPROOT_LEAF_VERSION, bytes.length]), bytes]));
}
function branch(a: Buffer, b: Buffer): Buffer {
  const parts = Buffer.compare(a, b) <= 0 ? [a, b] : [b, a];
  return taggedHash('TapBranch', Buffer.concat(parts));
}

/**
 * Verify a NUMS witness against the BIP341 construction x(H+rG).
 * This establishes a publicly reviewable derivation from the documented
 * NUMS point under the elliptic-curve discrete-log assumption. It does not
 * constitute an absolute mathematical proof of unknown discrete log.
 */
export function verifyNumsDerivation(internalKeyXOnly: string, scalarHex: string): boolean {
  if (!XONLY.test(internalKeyXOnly) || !XONLY.test(scalarHex)) return false;
  const scalar = BigInt('0x' + scalarHex);
  if (scalar === 0n || scalar >= CURVE_ORDER) return false;
  try {
    const blinded = Buffer.from(secp.publicKeyTweakAdd(
      Buffer.from('02' + BIP341_NUMS_XONLY, 'hex'),
      Buffer.from(scalarHex, 'hex'), true,
    ));
    return blinded.length === 33 && blinded.subarray(1).toString('hex') === internalKeyXOnly;
  } catch {
    return false;
  }
}

/** Rebuild a proposed output with exactly the explicitly listed two scripts. */
export function constructTwoLeafOptionVault(p: OptionVaultProposal): FullTwoLeafManifest {
  const inner = pubkey(p.internalKeyXOnly, 'internal key');
  if (p.numsBlindingScalarHex !== undefined &&
      !verifyNumsDerivation(p.internalKeyXOnly, p.numsBlindingScalarHex)) {
    throw Error('internal key fails the claimed BIP341 NUMS derivation');
  }
  const borrower = pubkey(p.expectedBorrowerXOnly, 'borrower');
  const guardian = pubkey(p.expectedGuardianXOnly, 'guardian');
  const existing = CANONICAL_DUCAT_COSIGN.exec(p.ducatCosignScriptHex);
  if (!existing) throw Error('existing leaf is not the canonical two-key Ducat cosign leaf');
  const proposed = matchOptionLeaf(p.optionScriptHex);
  if (!proposed) throw Error('option leaf is not the canonical three-key proposal');
  if (existing[1] !== borrower.toString('hex') || proposed.borrower !== borrower.toString('hex')) {
    throw Error('borrower differs between the two leaves or approved wallet key');
  }
  if (existing[2] !== guardian.toString('hex') || proposed.guardian !== guardian.toString('hex')) {
    throw Error('guardian differs between the two leaves or the approved guardian key');
  }
  pubkey(proposed.putWriter, 'writer');
  if (proposed.putWriter === p.internalKeyXOnly) {
    throw Error('option writer cannot be vault internal key in this proposal');
  }

  const a = leafHash(p.ducatCosignScriptHex);
  const b = leafHash(p.optionScriptHex);
  if (a.equals(b)) throw Error('same leaf committed twice');
  const root = branch(a, b);
  const tweak = taggedHash('TapTweak', Buffer.concat([inner, root]));
  if (BigInt('0x' + tweak.toString('hex')) >= CURVE_ORDER) {
    throw Error('BIP341 invalid tap tweak scalar');
  }
  let output: Buffer;
  try {
    output = Buffer.from(secp.publicKeyTweakAdd(Buffer.concat([Buffer.from([0x02]), inner]), tweak, true));
  } catch {
    throw Error('BIP341 output key tweak failed');
  }
  if (output.length !== 33 || (output[0] !== 0x02 && output[0] !== 0x03)) {
    throw Error('BIP341 output key is invalid');
  }
  const parity = (output[0] & 1) as 0 | 1;
  const prefix = Buffer.concat([Buffer.from([TAPROOT_LEAF_VERSION | parity]), inner]);
  return {
    treeKind: 'ducat-cosign+candidate-option/v1',
    status: 'review-only',
    scriptPubKeyHex: '5120' + output.subarray(1).toString('hex'),
    outputKeyXOnly: output.subarray(1).toString('hex'),
    outputParity: parity,
    merkleRootHex: root.toString('hex'),
    cosignLeafHash: a.toString('hex'),
    optionLeafHash: b.toString('hex'),
    cosignControlBlockHex: Buffer.concat([prefix, b]).toString('hex'),
    optionControlBlockHex: Buffer.concat([prefix, a]).toString('hex'),
    keyPathSpendability: p.numsBlindingScalarHex === undefined ? 'unproven' : 'nums-derived',
    cetEnforcement: 'unimplemented',
  };
}

export type ObservedOptionVault = {
  scriptPubKeyHex: string;
  cosignControlBlockHex: string;
  optionControlBlockHex: string;
};
export type TwoLeafVerdict = {
  status: 'matches-proposed-tree' | 'mismatch';
  reasons: string[];
  manifest: FullTwoLeafManifest | null;
};
/**
 * Checks an observer's output script and BOTH control blocks against exactly
 * the tree reconstructed from explicit inputs. A successful result is NOT
 * a signing authorization because key path and DLC settlement remain open.
 */
export function verifyTwoLeafOptionVault(
  p: OptionVaultProposal,
  observed: ObservedOptionVault,
): TwoLeafVerdict {
  let manifest: FullTwoLeafManifest;
  try {
    manifest = constructTwoLeafOptionVault(p);
  } catch (error) {
    return {
      status: 'mismatch',
      reasons: [error instanceof Error ? error.message : 'malformed vault proposal'],
      manifest: null,
    };
  }
  const reasons: string[] = [];
  if (observed.scriptPubKeyHex !== manifest.scriptPubKeyHex) reasons.push('SCRIPT_PUBKEY_MISMATCH');
  if (observed.cosignControlBlockHex !== manifest.cosignControlBlockHex) {
    reasons.push('COSIGN_CONTROL_BLOCK_MISMATCH');
  }
  if (observed.optionControlBlockHex !== manifest.optionControlBlockHex) {
    reasons.push('OPTION_CONTROL_BLOCK_MISMATCH');
  }
  return {
    status: reasons.length === 0 ? 'matches-proposed-tree' : 'mismatch',
    reasons,
    manifest,
  };
}
