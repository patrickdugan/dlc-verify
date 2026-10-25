import { describe, expect, it } from 'vitest';
import {
  analyzeOptions, constructOptionLeaf, firstRightsDifference,
  matchOptionLeaf, payoutAt, screenFiqh, type OptionTerms,
  type RightsObservation,
} from '../src/ducat-option';

const t: OptionTerms = {
  network:'mutinynet',vaultOutpoint:'a'.repeat(64)+':0',
  borrowerCollateralSats:'100000000',writerBondSats:'80000000',
  debtUsdCents:'5000000',putStrikeUsdCents:'7000000',
  callStrikeUsdCents:'16600000',
  oracleOutcomesUsdCents:['4000000','7000000','10000000','20000000'],
  minerFeeSats:'1000',eventId:'ducat-option-btcusd-4000000',
  oracleXOnlyPubkey:'d'.repeat(64),expiryHeight:100000,refundHeight:100012,
};
const facts = {
  creditClassification:'qard' as const,
  mandatoryBorrowingFeeCents:'0',
  provenActualAdminCostCents:'0',
  borrowerConsentAndDisclosures:true,
  enforceableResidualEquityReturn:true,
  fundedOptionWriter:true,
  coveredCallIndependentOfLenderBenefit:true,
  promisedOutcomesFunded:true,
  optionsPremiumExternallyDocumented:true,
};
describe('Ducat research-only DLC collar adapter',()=>{
  it('creates canonical 3-of-3 Tapscript without accidentally accepting extra opcodes',()=>{
    const a='1'.repeat(64),b='2'.repeat(64),c='3'.repeat(64);
    const leaf=constructOptionLeaf(a,b,c);
    expect(leaf.scriptHex).toHaveLength(204);
    expect(leaf.leafHash).toMatch(/^[0-9a-f]{64}$/u);
    expect(matchOptionLeaf(leaf.scriptHex)).toEqual({borrower:a,guardian:b,putWriter:c});
    expect(matchOptionLeaf(leaf.scriptHex+'ac')).toBeNull();
    expect(()=>constructOptionLeaf(a,a,c)).toThrow();
  });
  it('enforces per-outcome satoshi conservation',()=>{
    const result=analyzeOptions(t);
    expect(result.status).toBe('research-only');
    expect(result.arithmeticReady).toBe(true);
    expect(result.outcomes).toHaveLength(4);
    for(const o of result.outcomes){
      const sats=BigInt(o.lenderSats)+BigInt(o.borrowerEquitySats)+
        BigInt(o.writerRefundSats)+BigInt(o.callHolderSats)+BigInt(o.minerFeeSats);
      expect(sats).toBe(180000000n);
      expect(o.lenderShortfallSats).toBe('0');
    }
    expect(payoutAt(t,'4000000').borrowerEquitySats).toBe('50000000');
  });
  it('rejects the unfunded low-price tail',()=>{
    const r=analyzeOptions({...t,oracleOutcomesUsdCents:['1000000','4000000']});
    expect(r.arithmeticReady).toBe(false);
    expect(r.errors.join(' ')).toMatch(/underfunded put/u);
  });
  it('detects lender shortfall separately from option underfunding',()=>{
    const r=analyzeOptions({...t,debtUsdCents:'10000000'});
    expect(r.arithmeticReady).toBe(false);
    expect(r.errors.join(' ')).toMatch(/debt not fully protected/u);
  });
  it('rejects invalid oracle domain, timelock, and funding identity',()=>{
    for(const changed of [
      {oracleOutcomesUsdCents:['4000000','4000000']},
      {oracleOutcomesUsdCents:['0','4000000']},
      {refundHeight:100003},
      {oracleXOnlyPubkey:'xyz'},
      {vaultOutpoint:'invalid'},
    ]){
      expect(analyzeOptions({...t,...changed}).arithmeticReady).toBe(false);
    }
  });
  it('caps the call by borrower-owned BTC',()=>{
    const r=payoutAt(t,'20000000');
    expect(BigInt(r.callExerciseSats)).toBeLessThanOrEqual(100000000n);
    expect(r.putPayoutSats).toBe('0');
  });
  it('flags a qard fee surplus and a call option to the lender',()=>{
    const r=screenFiqh({...facts,mandatoryBorrowingFeeCents:'700',
      coveredCallIndependentOfLenderBenefit:false});
    expect(r.status).toBe('review-only');
    expect(r.blockers).toContain('QARD_STIPULATED_BENEFIT_CONCERN');
    expect(r.blockers).toContain('COVERED_CALL_AS_LENDER_BENEFIT');
  });
  it('flags absent cost evidence and unreturned borrower equity',()=>{
    const r=screenFiqh({...facts,provenActualAdminCostCents:null,
      enforceableResidualEquityReturn:false});
    expect(r.blockers).toContain('ADMIN_COST_EVIDENCE_ABSENT');
    expect(r.blockers).toContain('BORROWER_EQUITY_AT_RISK');
  });
  it('finds the first property-rights barzakh witness',()=>{
    const a:RightsObservation={step:'open',owner:'borrower',cash:'50000',
      debt:'50000',collateralPriority:'lender',contingentClaims:'put',consent:'yes'};
    expect(firstRightsDifference([a],[a])).toBeNull();
    expect(firstRightsDifference([a,a],[a,{...a,owner:'liquidator'}])).toEqual({
      index:1,field:'owner',a:'borrower',b:'liquidator',
    });
  });
});
