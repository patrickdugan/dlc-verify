/* Node 22+ --experimental-strip-types; independently runnable without node_modules. */
const test = require('node:test');
const assert = require('node:assert/strict');
const o = require('../src/ducat-option.mts');
const t = {
 network:'mutinynet',vaultOutpoint:'a'.repeat(64)+':0',
 borrowerCollateralSats:'100000000',writerBondSats:'80000000',
 debtUsdCents:'5000000',putStrikeUsdCents:'7000000',
 callStrikeUsdCents:'16600000',oracleOutcomesUsdCents:['4000000','7000000','10000000','20000000'],
 minerFeeSats:'1000',eventId:'collar',oracleXOnlyPubkey:'d'.repeat(64),
 expiryHeight:100000,refundHeight:100012
};
test('candidate leaf exact shape',()=>{
 const leaf=o.constructOptionLeaf('1'.repeat(64),'2'.repeat(64),'3'.repeat(64));
 assert.equal(leaf.scriptHex.length,204);
 assert.deepEqual(o.matchOptionLeaf(leaf.scriptHex),{
  borrower:'1'.repeat(64),guardian:'2'.repeat(64),putWriter:'3'.repeat(64)});
 assert.equal(o.matchOptionLeaf(leaf.scriptHex+'ac'),null);
});
test('conserved sats and repaid lender',()=>{
 const a=o.analyzeOptions(t); assert.equal(a.arithmeticReady,true,JSON.stringify(a.errors));
 for(const p of a.outcomes){
  assert.equal(BigInt(p.lenderSats)+BigInt(p.borrowerEquitySats)+
   BigInt(p.writerRefundSats)+BigInt(p.callHolderSats)+BigInt(p.minerFeeSats),180000000n);
  assert.equal(p.lenderShortfallSats,'0');
 }
 assert.equal(o.payoutAt(t,'4000000').borrowerEquitySats,'50000000');
});
test('finite BTC bond cannot pay an unbounded USD put',()=>{
 const p=o.analyzeOptions({...t,oracleOutcomesUsdCents:['1000000','4000000']});
 assert.equal(p.arithmeticReady,false);assert.match(p.errors.join(' '),/underfunded put/);
});
test('unrecovered lender principal and malformed oracle event fail',()=>{
 assert.equal(o.analyzeOptions({...t,debtUsdCents:'10000000'}).arithmeticReady,false);
 assert.equal(o.analyzeOptions({...t,oracleOutcomesUsdCents:['4000000','4000000']}).arithmeticReady,false);
 assert.equal(o.analyzeOptions({...t,refundHeight:100003}).arithmeticReady,false);
});
test('fiqh screen is human-review only and flags financial benefit',()=>{
 const p=o.screenFiqh({
  creditClassification:'qard',mandatoryBorrowingFeeCents:'700',provenActualAdminCostCents:'0',
  borrowerConsentAndDisclosures:true,enforceableResidualEquityReturn:true,
  fundedOptionWriter:true,coveredCallIndependentOfLenderBenefit:false,
  promisedOutcomesFunded:true,optionsPremiumExternallyDocumented:true
 });
 assert.equal(p.status,'review-only');
 assert.ok(p.blockers.includes('QARD_STIPULATED_BENEFIT_CONCERN'));
 assert.ok(p.blockers.includes('COVERED_CALL_AS_LENDER_BENEFIT'));
});
test('barzakh pinpoints ownership transfer',()=>{
 const a={step:'open',owner:'borrower',cash:'50000',debt:'50000',
  collateralPriority:'lender',contingentClaims:'put',consent:'yes'};
 assert.deepEqual(o.firstRightsDifference([a,a],[a,{...a,owner:'liquidator'}]),{
  index:1,field:'owner',a:'borrower',b:'liquidator'
 });
});
