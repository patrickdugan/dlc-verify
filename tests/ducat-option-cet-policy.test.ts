import { describe, expect, it } from 'vitest';
import { Transaction } from 'bitcoinjs-lib';
import { constructOptionLeaf, payoutAt, type OptionTerms } from '../src/ducat-option';
import { BIP341_NUMS_XONLY, constructTwoLeafOptionVault } from '../src/ducat-option-vault-tree';
import { preflightOptionCets, type OptionCetBundle } from '../src/ducat-option-cet-policy';

const terms:OptionTerms = {
  network:'mutinynet',vaultOutpoint:'a'.repeat(64)+':0',
  borrowerCollateralSats:'100000000',writerBondSats:'80000000',
  debtUsdCents:'5000000',putStrikeUsdCents:'7000000',callStrikeUsdCents:'16600000',
  oracleOutcomesUsdCents:['4000000','7000000','10000000','20000000'],
  minerFeeSats:'1000',eventId:'ducat-collar-maturity-100000',
  oracleXOnlyPubkey:'d'.repeat(64),expiryHeight:100000,refundHeight:100010,
};
// Deterministic known-secret test keys. NEVER use as funded Bitcoin keys.
const secp = require('secp256k1') as {
  publicKeyCreate: (privateKey: Uint8Array, compressed?: boolean) => Uint8Array;
  publicKeyTweakAdd: (point: Uint8Array, scalar: Uint8Array, compressed?: boolean) => Uint8Array;
};
function spk(lastByte: number): string {
  const key = Buffer.alloc(32);
  key[31] = lastByte;
  return '5120' + Buffer.from(secp.publicKeyCreate(key, true)).subarray(1).toString('hex');
}
const payoutScripts = {
  lender: spk(1),
  borrower: spk(2),
  putWriter: spk(3),
  callHolder: spk(4),
};
const bondOutpoint = 'b'.repeat(64)+':1';
const witness = '0'.repeat(63) + '5'; // Public deterministic witness, test-only
const internalKey = Buffer.from(secp.publicKeyTweakAdd(
  Buffer.from('02'+BIP341_NUMS_XONLY, 'hex'),
  Buffer.from(witness, 'hex'), true,
)).subarray(1).toString('hex');
const borrowerKey = spk(10).slice(4);
const guardianKey = spk(11).slice(4);
const writerKey = spk(12).slice(4);
const proposedTree = {
  internalKeyXOnly: internalKey,
  numsBlindingScalarHex: witness,
  ducatCosignScriptHex:'20'+borrowerKey+'ad20'+guardianKey+'ac',
  optionScriptHex:constructOptionLeaf(borrowerKey,guardianKey,writerKey).scriptHex,
  expectedBorrowerXOnly:borrowerKey,
  expectedGuardianXOnly:guardianKey,
};
const tree = constructTwoLeafOptionVault(proposedTree);
const observedTree = {
  scriptPubKeyHex:tree.scriptPubKeyHex,
  cosignControlBlockHex:tree.cosignControlBlockHex,
  optionControlBlockHex:tree.optionControlBlockHex,
};
function buildOne(price:string, mods?:{
  changeRecipient?:boolean;swapInputs?:boolean;locktime?:number;
  overpay?:boolean;addOutput?:boolean;badSequence?:boolean;
}) {
  const tx = new Transaction();
  tx.version = 2;
  tx.locktime = mods?.locktime ?? terms.expiryHeight;
  const inputVault: [Buffer,number,number]=[Buffer.from('a'.repeat(64),'hex').reverse(),0,0xfffffffe];
  const inputWriter: [Buffer,number,number]=[Buffer.from('b'.repeat(64),'hex').reverse(),1,mods?.badSequence?0xffffffff:0xfffffffe];
  if(mods?.swapInputs) {
    tx.addInput(...inputWriter);tx.addInput(...inputVault);
  } else {
    tx.addInput(...inputVault);tx.addInput(...inputWriter);
  }
  const pay = payoutAt(terms,price);
  const out = {
    lender:BigInt(pay.lenderSats),borrower:BigInt(pay.borrowerEquitySats),
    putWriter:BigInt(pay.writerRefundSats),callHolder:BigInt(pay.callHolderSats)
  };
  (['lender','borrower','putWriter','callHolder'] as const).forEach(role=>{
    const v=out[role];
    if(v>0n)tx.addOutput(Buffer.from(
      mods?.changeRecipient&&role==='borrower'?spk(8):payoutScripts[role],'hex'
    ),v+(mods?.overpay&&role==='borrower'?1n:0n));
  });
  if(mods?.addOutput)tx.addOutput(Buffer.from(spk(9),'hex'),1000n);
  return {outcomeUsdCents:price,unsignedTransactionHex:tx.toHex()};
}
function bundle():OptionCetBundle {
  return {
    terms,writerBondOutpoint:bondOutpoint,
    proposedTree:{...proposedTree}, observedTree:{...observedTree},
    vaultPrevoutScriptPubKeyHex:tree.scriptPubKeyHex,
    writerBondPrevoutScriptPubKeyHex:spk(6),
    payoutScripts:{...payoutScripts},
    candidates:terms.oracleOutcomesUsdCents.map(price=>buildOne(price)),
  };
}
describe('Ducat option CET output allocation preflight',()=>{
  it('checks every unsigned Bitcoin transaction and produces reproducible digest',()=>{
    const b=bundle();
    const r=preflightOptionCets(b);
    expect(r.status).toBe('preflight-pass');
    expect(r.authorization).toBe('not-authorized');
    expect(r.cetTxids).toHaveLength(4);
    expect(r.reviewDigest).toMatch(/^[0-9a-f]{64}$/u);
    expect(preflightOptionCets(b).reviewDigest).toBe(r.reviewDigest);
    expect(r.unsatisfied.join(' ')).toMatch(/oracle announcement/u);
  });
  it('rejects a substituted borrower payout address',()=>{
    const b=bundle();
    b.candidates[1]=buildOne(b.candidates[1].outcomeUsdCents,{changeRecipient:true});
    expect(preflightOptionCets(b).problems).toContain('CET payout mismatch at outcome 7000000, index 1');
  });
  it('rejects a single satoshi overpayment',()=>{
    const b=bundle();b.candidates[0]=buildOne('4000000',{overpay:true});
    expect(preflightOptionCets(b).status).toBe('reject');
  });
  it('rejects change of input spending priority and nSequence',()=>{
    const b=bundle();b.candidates[0]=buildOne('4000000',{swapInputs:true});
    expect(preflightOptionCets(b).problems.join(' ')).toMatch(/CET funding inputs/u);
    const c=bundle();c.candidates[0]=buildOne('4000000',{badSequence:true});
    expect(preflightOptionCets(c).status).toBe('reject');
  });
  it('rejects early/late locktimes',()=>{
    const b=bundle();b.candidates[0]=buildOne('4000000',{locktime:terms.expiryHeight+1});
    expect(preflightOptionCets(b).problems.join(' ')).toMatch(/maturity locktime/u);
  });
  it('rejects extra outputs and reused recipient scripts',()=>{
    const b=bundle();b.candidates[0]=buildOne('4000000',{addOutput:true});
    expect(preflightOptionCets(b).status).toBe('reject');
    const c=bundle();c.payoutScripts.borrower=c.payoutScripts.lender;
    expect(preflightOptionCets(c).problems.join(' ')).toMatch(/distinct Bitcoin scripts/u);
  });
  it('rejects omitted or duplicate oracle outcomes',()=>{
    const b=bundle();b.candidates.pop();
    expect(preflightOptionCets(b).problems.join(' ')).toMatch(/missing or extra/u);
    const c=bundle();c.candidates[1].outcomeUsdCents='4000000';
    expect(preflightOptionCets(c).status).toBe('reject');
  });
  it('rejects unbound or duplicate collateral UTXOs',()=>{
    const b=bundle();b.writerBondOutpoint=terms.vaultOutpoint;
    expect(preflightOptionCets(b).problems.join(' ')).toMatch(/cannot share/u);
    const c=bundle();c.vaultPrevoutScriptPubKeyHex='0014'+'f'.repeat(40);
    expect(preflightOptionCets(c).problems.join(' ')).toMatch(/differs from reviewed option tree/u);
  });
  it('rejects unsigned CETs without an independently derived NUMS key',()=>{
    const b=bundle();
    b.proposedTree.numsBlindingScalarHex=undefined;
    expect(preflightOptionCets(b).problems.join(' ')).toMatch(/NUMS internal-key witness/u);
  });
  it('rejects an added unauthorized leaf or altered tree commitment',()=>{
    const b=bundle();
    b.observedTree.optionControlBlockHex='c0'+'a'.repeat(128);
    expect(preflightOptionCets(b).problems.join(' ')).toMatch(/tree commitment mismatch/u);
    const c=bundle();
    c.vaultPrevoutScriptPubKeyHex=spk(5);
    expect(preflightOptionCets(c).problems.join(' ')).toMatch(/differs from reviewed option tree/u);
  });
  it('rejects a non-curve Taproot destination',()=>{
    const b=bundle(); b.payoutScripts.lender='5120'+'1'.repeat(64);
    expect(preflightOptionCets(b).problems.join(' ')).toMatch(/invalid x-only secp256k1/u);
  });
  it('updates the review digest when a legitimate recipient changes',()=>{
    const b=bundle();
    const a=preflightOptionCets(b).reviewDigest;
    b.payoutScripts.borrower=spk(7);
    b.candidates=terms.oracleOutcomesUsdCents.map(p=>{
      const tx=Transaction.fromHex(buildOne(p).unsignedTransactionHex);
      const paid = payoutAt(terms,p);
      // Role order lender, borrower, writer, holder. Borrower is always positive here.
      expect(paid.borrowerEquitySats).not.toBe('0');
      tx.outs[1].script=Buffer.from(b.payoutScripts.borrower,'hex');
      return {outcomeUsdCents:p,unsignedTransactionHex:tx.toHex()};
    });
    const after=preflightOptionCets(b);
    expect(after.status).toBe('preflight-pass');
    expect(after.reviewDigest).not.toBe(a);
  });
});
