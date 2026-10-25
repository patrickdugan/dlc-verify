import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { constructOptionLeaf } from '../src/ducat-option';
import {
  BIP341_NUMS_XONLY, constructTwoLeafOptionVault, verifyTwoLeafOptionVault, verifyNumsDerivation,
  type OptionVaultProposal,
} from '../src/ducat-option-vault-tree';

// secp256k1 is an existing dependency of dlc-verify.
// KNOWN TEST PRIVATE KEYS: must NEVER be deployed or funded.
const secp = require('secp256k1') as {
  publicKeyCreate: (secret: Uint8Array, compressed?: boolean) => Uint8Array;
};
function x(i: number): string {
  const secret = Buffer.alloc(32);
  secret[31] = i;
  return Buffer.from(secp.publicKeyCreate(secret, true)).subarray(1).toString('hex');
}
const borrower = x(1);
const guardian = x(2);
const writer = x(3);
const internalKeyXOnly = x(4);

function proposal(): OptionVaultProposal {
  return {
    internalKeyXOnly,
    ducatCosignScriptHex: '20' + borrower + 'ad20' + guardian + 'ac',
    optionScriptHex: constructOptionLeaf(borrower, guardian, writer).scriptHex,
    expectedBorrowerXOnly: borrower,
    expectedGuardianXOnly: guardian,
  };
}

describe('Ducat Taproot two-leaf option vault preflight (read only)', () => {
  it('produces a real P2TR output and exact 65-byte BIP341 control blocks', () => {
    const m = constructTwoLeafOptionVault(proposal());
    expect(m.scriptPubKeyHex).toMatch(/^5120[0-9a-f]{64}$/u);
    expect(m.outputKeyXOnly).toHaveLength(64);
    expect(m.merkleRootHex).toHaveLength(64);
    expect(m.cosignControlBlockHex).toHaveLength(130);
    expect(m.optionControlBlockHex).toHaveLength(130);
    expect(parseInt(m.optionControlBlockHex.slice(0, 2), 16) & 1).toBe(m.outputParity);
    expect(m.cosignControlBlockHex.slice(2,66)).toBe(internalKeyXOnly);
    expect(m.cosignControlBlockHex.slice(66)).toBe(m.optionLeafHash);
    expect(m.optionControlBlockHex.slice(66)).toBe(m.cosignLeafHash);
    expect(m.keyPathSpendability).toBe('unproven');
    expect(m.cetEnforcement).toBe('unimplemented');
  });

  it('matches the entire proposed output and both control blocks', () => {
    const p = proposal();
    const m = constructTwoLeafOptionVault(p);
    const result = verifyTwoLeafOptionVault(p, {
      scriptPubKeyHex: m.scriptPubKeyHex,
      cosignControlBlockHex: m.cosignControlBlockHex,
      optionControlBlockHex: m.optionControlBlockHex,
    });
    expect(result.status).toBe('matches-proposed-tree');
    expect(result.reasons).toEqual([]);
  });

  it('detects an output not committed to the exact two-leaf tree', () => {
    const p = proposal();
    const m = constructTwoLeafOptionVault(p);
    const result = verifyTwoLeafOptionVault(p, {
      scriptPubKeyHex: '5120' + '0'.repeat(64),
      cosignControlBlockHex: m.cosignControlBlockHex,
      optionControlBlockHex: m.optionControlBlockHex,
    });
    expect(result).toMatchObject({ status: 'mismatch', reasons: ['SCRIPT_PUBKEY_MISMATCH'] });
  });

  it('rejects a forged control branch even when the prevout output matches', () => {
    const p = proposal();
    const m = constructTwoLeafOptionVault(p);
    const corrupted = m.optionControlBlockHex.slice(0, -2) +
      (m.optionControlBlockHex.endsWith('00') ? '01' : '00');
    const result = verifyTwoLeafOptionVault(p, {
      scriptPubKeyHex: m.scriptPubKeyHex,
      cosignControlBlockHex: m.cosignControlBlockHex,
      optionControlBlockHex: corrupted,
    });
    expect(result.status).toBe('mismatch');
    expect(result.reasons).toContain('OPTION_CONTROL_BLOCK_MISMATCH');
  });

  it('refuses a guardian different from the authenticated allowlist input', () => {
    expect(() => constructTwoLeafOptionVault({
      ...proposal(), expectedGuardianXOnly: writer,
    })).toThrow(/guardian differs/u);
  });

  it('refuses a borrower different from the independently approved wallet', () => {
    expect(() => constructTwoLeafOptionVault({
      ...proposal(), expectedBorrowerXOnly: writer,
    })).toThrow(/borrower differs/u);
  });

  it('rejects hidden custom opcodes in a Ducat cosign leaf', () => {
    expect(() => constructTwoLeafOptionVault({
      ...proposal(), ducatCosignScriptHex: proposal().ducatCosignScriptHex + '51',
    })).toThrow(/canonical two-key/u);
  });

  it('rejects noncurve points and mismatched option scripts', () => {
    expect(verifyTwoLeafOptionVault({
      ...proposal(), internalKeyXOnly: 'f'.repeat(64),
    }, {scriptPubKeyHex:'',optionControlBlockHex:'',cosignControlBlockHex:''}).status).toBe('mismatch');
    expect(() => constructTwoLeafOptionVault({
      ...proposal(), optionScriptHex: constructOptionLeaf(guardian, borrower, writer).scriptHex,
    })).toThrow(/borrower differs/u);
  });


  it('pins the BIP341 NUMS construction to SHA256(uncompressed G)', () => {
    const sec = Buffer.alloc(32);
    sec[31] = 1;
    const point = Buffer.from(secp.publicKeyCreate(sec, false));
    expect(createHash('sha256').update(point).digest('hex')).toBe(BIP341_NUMS_XONLY);
  });

  it('verifies a blinded NUMS internal key with a revealed scalar', () => {
    const native = require('secp256k1') as {
      publicKeyTweakAdd: (point: Uint8Array, tweak: Uint8Array, compressed?: boolean) => Uint8Array;
    };
    const r = '0'.repeat(63) + '5'; // public test scalar, never use for funds
    const internal = Buffer.from(native.publicKeyTweakAdd(
      Buffer.from('02' + BIP341_NUMS_XONLY, 'hex'),
      Buffer.from(r, 'hex'), true,
    )).subarray(1).toString('hex');
    expect(verifyNumsDerivation(internal, r)).toBe(true);
    const manifest = constructTwoLeafOptionVault({
      ...proposal(), internalKeyXOnly: internal, numsBlindingScalarHex: r,
    });
    expect(manifest.keyPathSpendability).toBe('nums-derived');
    expect(manifest.scriptPubKeyHex).toMatch(/^5120[0-9a-f]{64}$/u);
    expect(verifyNumsDerivation(internal, '0'.repeat(64))).toBe(false);
    expect(verifyNumsDerivation(internal, 'f'.repeat(64))).toBe(false);
    expect(verifyNumsDerivation(internal, '0'.repeat(63) + '6')).toBe(false);
  });

  it('fails closed if the asserted NUMS witness cannot produce the internal key', () => {
    expect(() => constructTwoLeafOptionVault({
      ...proposal(), numsBlindingScalarHex: '0'.repeat(63) + '5',
    })).toThrow(/fails the claimed BIP341 NUMS derivation/u);
  });

  it('rejects unknown internal key-path safety even after a valid tree match', () => {
    const m = constructTwoLeafOptionVault(proposal());
    expect(m.status).toBe('review-only');
    expect(m.keyPathSpendability).toBe('unproven');
    // Because x(4) has a known secret scalar, this fixture is unsafe to fund.
  });
});
