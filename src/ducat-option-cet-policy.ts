/**
 * Read-only Bitcoin CET preflight for a Ducat option collar.
 * Checks transaction byte structure and exact economic payout allocations
 * but does NOT verify any adaptor/Schnorr signatures, oracle attestations,
 * writer-bond encumbrance, or UNIT debt-extinguishment rules.
 */
import { createHash } from 'node:crypto';
import { Transaction } from 'bitcoinjs-lib';
import { analyzeOptions, payoutAt, type OptionTerms } from './ducat-option';
import {
  verifyTwoLeafOptionVault, type OptionVaultProposal, type ObservedOptionVault,
} from './ducat-option-vault-tree';

const P2TR = /^5120[0-9a-f]{64}$/u;
const TX_HEX = /^(?:[0-9a-f]{2})+$/u;
const OUTPOINT = /^([0-9a-f]{64}):((?:0|[1-9][0-9]*))$/u;
const NONFINAL_LOCKTIME_SEQUENCE = 0xfffffffe;
const MIN_RELAY_OUTPUT = 546n;
const secp = require('secp256k1') as { publicKeyVerify: (point: Uint8Array) => boolean };

type Role = 'lender' | 'borrower' | 'putWriter' | 'callHolder';
const ROLES: readonly Role[] = ['lender', 'borrower', 'putWriter', 'callHolder'];

export type OptionCetCandidate = {
  outcomeUsdCents: string;
  unsignedTransactionHex: string;
};
export type OptionCetBundle = {
  terms: OptionTerms;
  writerBondOutpoint: string;
  /** Full proposed tree with an independently reviewable BIP341 NUMS witness. */
  proposedTree: OptionVaultProposal;
  /** Actual candidate scriptPubKey and both control blocks to be verified. */
  observedTree: ObservedOptionVault;
  /** Must be checked against the actual chain independently. */
  vaultPrevoutScriptPubKeyHex: string;
  /** Must be checked against the actual chain independently. */
  writerBondPrevoutScriptPubKeyHex: string;
  payoutScripts: Record<Role, string>;
  candidates: OptionCetCandidate[];
};
export type CetPreflightResult = {
  status: 'preflight-pass' | 'reject';
  authorization: 'not-authorized';
  problems: string[];
  cetTxids: string[];
  /** A deterministic request hash for independent off-chain review, not a signature. */
  reviewDigest: string | null;
  unsatisfied: string[];
};

function splitOutpoint(raw: string): { txid: string; vout: number } {
  const match = OUTPOINT.exec(raw);
  if (!match) throw Error('invalid funding outpoint format');
  const vout = Number(match[2]);
  if (!Number.isSafeInteger(vout) || vout > 0xffffffff) throw Error('funding vout out of range');
  return { txid: match[1], vout };
}
function txOutpoint(input: Transaction['ins'][number]): string {
  return Buffer.from(input.hash).reverse().toString('hex') + ':' + input.index;
}
function assertScript(raw: string, name: string): void {
  if (!P2TR.test(raw)) throw Error(name + ': only canonical P2TR scripts accepted');
  if (!secp.publicKeyVerify(Buffer.from('02' + raw.slice(4), 'hex'))) {
    throw Error(name + ': invalid x-only secp256k1 public key');
  }
}
function validateCandidates(b: OptionCetBundle): { txids: string[] } {
  const check = analyzeOptions(b.terms);
  if (!check.arithmeticReady) throw Error('financial allocation: ' + check.errors.join('; '));
  const tree = verifyTwoLeafOptionVault(b.proposedTree, b.observedTree);
  if (tree.status !== 'matches-proposed-tree' || !tree.manifest) {
    throw Error('vault Taproot tree commitment mismatch: ' + tree.reasons.join('; '));
  }
  if (tree.manifest.keyPathSpendability !== 'nums-derived') {
    throw Error('missing independently verifiable BIP341 NUMS internal-key witness');
  }
  if (tree.manifest.scriptPubKeyHex !== b.vaultPrevoutScriptPubKeyHex) {
    throw Error('CET vault funding script differs from reviewed option tree');
  }
  const vault = splitOutpoint(b.terms.vaultOutpoint);
  const writer = splitOutpoint(b.writerBondOutpoint);
  if (b.terms.vaultOutpoint === b.writerBondOutpoint) {
    throw Error('vault and writer bond cannot share the same outpoint');
  }
  assertScript(b.vaultPrevoutScriptPubKeyHex, 'vault prevout');
  assertScript(b.writerBondPrevoutScriptPubKeyHex, 'writer prevout');
  for (const role of ROLES) assertScript(b.payoutScripts[role], role);
  if (new Set(ROLES.map(role => b.payoutScripts[role])).size !== ROLES.length) {
    throw Error('payout roles require distinct Bitcoin scripts');
  }
  if (!Array.isArray(b.candidates) ||
      b.candidates.length !== b.terms.oracleOutcomesUsdCents.length) {
    throw Error('missing or extra oracle CET outcomes');
  }
  if (b.terms.expiryHeight >= 500_000_000 || b.terms.refundHeight >= 500_000_000) {
    throw Error('this policy requires block-height-based CLTV');
  }
  const txids:string[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < b.candidates.length; i += 1) {
    const c = b.candidates[i];
    const expectedOutcome = b.terms.oracleOutcomesUsdCents[i];
    if (c.outcomeUsdCents !== expectedOutcome) throw Error('CET oracle outcome ordering mismatch');
    if (seen.has(c.outcomeUsdCents)) throw Error('duplicate CET oracle outcome');
    seen.add(c.outcomeUsdCents);
    if (!TX_HEX.test(c.unsignedTransactionHex)) throw Error('malformed unsigned CET hex');
    let tx: Transaction;
    try {
      tx = Transaction.fromHex(c.unsignedTransactionHex);
    } catch {
      throw Error('invalid Bitcoin transaction encoding for CET');
    }
    if (tx.toHex() !== c.unsignedTransactionHex) throw Error('noncanonical CET encoding');
    if (tx.version !== 2 || tx.locktime !== b.terms.expiryHeight) {
      throw Error('CET must use version 2 and exactly the agreed maturity locktime');
    }
    if (tx.hasWitnesses() || tx.ins.some(input => input.script.length !== 0)) {
      throw Error('CET policy requires an unsigned witness-free transaction');
    }
    if (tx.ins.length !== 2 ||
        tx.ins[0].sequence !== NONFINAL_LOCKTIME_SEQUENCE ||
        tx.ins[1].sequence !== NONFINAL_LOCKTIME_SEQUENCE ||
        txOutpoint(tx.ins[0]) !== vault.txid + ':' + vault.vout ||
        txOutpoint(tx.ins[1]) !== writer.txid + ':' + writer.vout) {
      throw Error('CET funding inputs or BIP65 locktime sequences differ');
    }
    const pay = payoutAt(b.terms, c.outcomeUsdCents);
    const expected: {script: string; value: bigint}[] = [];
    const values: Record<Role, string> = {
      lender: pay.lenderSats,
      borrower: pay.borrowerEquitySats,
      putWriter: pay.writerRefundSats,
      callHolder: pay.callHolderSats,
    };
    for (const role of ROLES) {
      const value = BigInt(values[role]);
      if (value !== 0n) {
        if (value < MIN_RELAY_OUTPUT) {
          throw Error('dust payout for ' + role + ' at outcome ' + c.outcomeUsdCents);
        }
        expected.push({script:b.payoutScripts[role],value});
      }
    }
    if (tx.outs.length !== expected.length) throw Error('CET output count mismatch');
    tx.outs.forEach((output, n) => {
      if (Buffer.from(output.script).toString('hex') !== expected[n].script ||
          output.value !== expected[n].value) {
        throw Error('CET payout mismatch at outcome ' + c.outcomeUsdCents + ', index ' + n);
      }
    });
    const spentSats = BigInt(b.terms.borrowerCollateralSats) + BigInt(b.terms.writerBondSats);
    const paidSats = tx.outs.reduce((a, o) => a + o.value, 0n);
    if (paidSats + BigInt(b.terms.minerFeeSats) !== spentSats) {
      throw Error('CET violates satoshi conservation');
    }
    txids.push(tx.getId());
  }
  return {txids};
}

/**
 * Incomplete by design. The review digest commits to actual candidate CET
 * transaction IDs and terms but is NOT authorization for signing or broadcast.
 */
export function preflightOptionCets(bundle: OptionCetBundle): CetPreflightResult {
  const unsatisfied = [
    'independently prove both funding outpoints unspent with specified BTC values and scripts',
    'prove the writer bond is encumbered until valid CET or refund settlement',
    'obtain signed oracle announcement binding every allowed outcome and expiry',
    'verify all Schnorr/adaptor signatures on each actual Taproot CET and refund',
    'authenticate confirmed on-chain vault output against reviewed NUMS tree and forbid any legacy liquidation path',
    'bind UNIT burn/debt discharge and the lender claim to the same settlement',
    'review option-premium settlement and qard/murabaha legal characterization',
  ];
  try {
    const {txids} = validateCandidates(bundle);
    // Field order is fixed by this implementation, all values originate from
    // canonical validated integer strings / lowercase hex values.
    const committed = {
      domain: 'ducat-research-cet-policy/v1',
      terms: bundle.terms,
      approvedTree: {
        scriptPubKeyHex: bundle.observedTree.scriptPubKeyHex,
        internalKeyXOnly: bundle.proposedTree.internalKeyXOnly,
        numsBlindingScalarHex: bundle.proposedTree.numsBlindingScalarHex,
        cosignControlBlockHex: bundle.observedTree.cosignControlBlockHex,
        optionControlBlockHex: bundle.observedTree.optionControlBlockHex,
      },
      writerBondOutpoint: bundle.writerBondOutpoint,
      vaultPrevoutScriptPubKeyHex: bundle.vaultPrevoutScriptPubKeyHex,
      writerBondPrevoutScriptPubKeyHex: bundle.writerBondPrevoutScriptPubKeyHex,
      payoutScripts: ROLES.map(role => [role, bundle.payoutScripts[role]]),
      cets: bundle.candidates.map((c, i) => [c.outcomeUsdCents, txids[i]]),
    };
    const digest = createHash('sha256').update(
      Buffer.from('Ducat/CETPolicy/v1\u0000' + JSON.stringify(committed), 'utf8'),
    ).digest('hex');
    return {
      status:'preflight-pass', authorization:'not-authorized',
      problems:[], cetTxids:txids, reviewDigest:digest, unsatisfied,
    };
  } catch (error) {
    return {
      status:'reject', authorization:'not-authorized',
      problems:[error instanceof Error?error.message:'invalid CET bundle'],
      cetTxids:[], reviewDigest:null, unsatisfied,
    };
  }
}
