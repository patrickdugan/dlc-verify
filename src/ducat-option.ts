/** Research-only Ducat DLC option settlement and ʿilmī uṣūl evidence screen.
 * Intended upstream Snap commit 34392b3c3d67979596bd8e5be07d98fde06496c4.
 * NO signing, broadcast, approval, or live collateral integration.
 */
import { createHash } from 'node:crypto';

const HEX32 = /^[0-9a-f]{64}$/u;
const UINT = /^(0|[1-9][0-9]*)$/u;
const SATS = 100000000n;
const MAX_SATS = 21000000n * SATS;

export type OptionTerms = {
  network: 'mutinynet' | 'regtest' | 'mainnet';
  vaultOutpoint: string;
  borrowerCollateralSats: string;
  writerBondSats: string;
  debtUsdCents: string;
  putStrikeUsdCents: string;
  callStrikeUsdCents: string;
  oracleOutcomesUsdCents: string[];
  minerFeeSats: string;
  eventId: string;
  oracleXOnlyPubkey: string;
  expiryHeight: number;
  refundHeight: number;
};
export type OutcomeAllocation = {
  btcUsdCents: string;
  putPayoutSats: string;
  callExerciseSats: string;
  lenderSats: string;
  borrowerEquitySats: string;
  writerRefundSats: string;
  callHolderSats: string;
  minerFeeSats: string;
  lenderShortfallSats: string;
};
export type Analysis = {
  status: 'research-only';
  errors: string[];
  outcomes: OutcomeAllocation[];
  arithmeticReady: boolean;
  unresolvedPrerequisites: string[];
};

export function uint(v: unknown, field: string, allowZero = false): bigint {
  if (typeof v !== 'string' || !UINT.test(v)) throw Error(field + ': expected a canonical integer string');
  const n = BigInt(v);
  if ((!allowZero && n === 0n) || n > MAX_SATS * SATS) throw Error(field + ': out of range');
  return n;
}
function ceilDiv(a: bigint, b: bigint): bigint {
  if (a < 0n || b <= 0n) throw Error('invalid division');
  return (a + b - 1n) / b;
}
function maximum(a: bigint, b: bigint): bigint { return a > b ? a : b; }

/** USD-cent price outcomes are converted to Bitcoin satoshi obligations. */
export function payoutAt(t: OptionTerms, price: string): OutcomeAllocation {
  const s = uint(price, 'btcUsdCents');
  const q = uint(t.borrowerCollateralSats, 'borrowerCollateralSats');
  const b = uint(t.writerBondSats, 'writerBondSats');
  const d = uint(t.debtUsdCents, 'debtUsdCents');
  const kPut = uint(t.putStrikeUsdCents, 'putStrikeUsdCents');
  const kCall = uint(t.callStrikeUsdCents, 'callStrikeUsdCents');
  const fee = uint(t.minerFeeSats, 'minerFeeSats', true);
  if (kPut >= kCall) throw Error('put strike must precede call strike');
  if (q > MAX_SATS || b > MAX_SATS || fee > b) throw Error('invalid collateral or writer fee reserve');
  // This put requires unbounded BTC as price approaches zero; reject unfunded states.
  const put = s < kPut ? ceilDiv((kPut - s) * q, s) : 0n;
  const call = s > kCall ? ceilDiv((s - kCall) * q, s) : 0n;
  if (call > q) throw Error('uncovered call');
  if (put + fee > b) throw Error('underfunded put at ' + price + ': required ' + (put + fee) + ', bonded ' + b);
  const debtSats = ceilDiv(d * SATS, s);
  const afterOptions = q + put - call;
  const lender = debtSats < afterOptions ? debtSats : afterOptions;
  const shortfall = maximum(debtSats - lender, 0n);
  const borrower = afterOptions - lender;
  const refund = b - put - fee;
  if (lender + borrower + refund + call + fee !== q + b) throw Error('settlement conservation failure');
  return {
    btcUsdCents: s.toString(), putPayoutSats: put.toString(),
    callExerciseSats: call.toString(), lenderSats: lender.toString(),
    borrowerEquitySats: borrower.toString(), writerRefundSats: refund.toString(),
    callHolderSats: call.toString(), minerFeeSats: fee.toString(),
    lenderShortfallSats: shortfall.toString(),
  };
}

/** Enumeration is only a financial arithmetic check: NOT an oracle domain proof. */
export function analyzeOptions(t: OptionTerms): Analysis {
  const errors: string[] = [];
  const outcomes: OutcomeAllocation[] = [];
  if (!/^[0-9a-fA-F]{64}:[0-9]+$/u.test(t.vaultOutpoint)) errors.push('invalid vault outpoint');
  if (!HEX32.test(t.oracleXOnlyPubkey)) errors.push('invalid oracle key');
  if (!t.eventId || t.eventId.length > 160 || !/^[A-Za-z0-9._:/-]+$/u.test(t.eventId)) errors.push('invalid oracle event');
  if (!['mutinynet','regtest','mainnet'].includes(t.network)) errors.push('unknown network');
  if (!Number.isSafeInteger(t.expiryHeight) || t.expiryHeight < 1 ||
      !Number.isSafeInteger(t.refundHeight) || t.refundHeight <= t.expiryHeight + 6) {
    errors.push('refund must follow expiry by more than six blocks');
  }
  if (!Array.isArray(t.oracleOutcomesUsdCents) || t.oracleOutcomesUsdCents.length < 2 ||
      t.oracleOutcomesUsdCents.length > 4096) {
    errors.push('explicit bounded oracle outcomes required');
  } else {
    const seen = new Set<string>();
    for (const price of t.oracleOutcomesUsdCents) {
      if (seen.has(price)) { errors.push('duplicate oracle outcome: ' + price); continue; }
      seen.add(price);
      try {
        const outcome = payoutAt(t, price);
        outcomes.push(outcome);
        if (outcome.lenderShortfallSats !== '0') errors.push('debt not fully protected at price ' + price);
      } catch(e) { errors.push(e instanceof Error ? e.message : String(e)); }
    }
  }
  return {
    status:'research-only', errors, outcomes, arithmeticReady: errors.length === 0,
    unresolvedPrerequisites: [
      'Ducat guardian and validator recognize funded option transitions',
      'Complete signed oracle event descriptor and announcement',
      'Taproot output-key and control-block proof for every leaf',
      'Exact CET and refund bytes with valid Taproot adaptor signatures',
      'Both actual outpoints bonded and every settlement outcome fully covered',
      'Runes/UNIT accounting and live debt extinguishment',
      'Independent option premium, qard-benefit and scholar review',
      'Reorg, outage, signer-loss and fee-bumping enforcement',
    ],
  };
}

function sha256(x: Uint8Array): Buffer { return createHash('sha256').update(x).digest(); }
function taggedHash(tag: string, value: Uint8Array): Buffer {
  const t = sha256(Buffer.from(tag, 'ascii'));
  return sha256(Buffer.concat([t, t, Buffer.from(value)]));
}
function pubkey(x: string, label: string): Buffer {
  if (!HEX32.test(x)) throw Error(label + ': expected lowercase x-only key');
  // Curve-point validation is an independent Bitcoin script verifier obligation.
  return Buffer.from(x, 'hex');
}
export type OptionLeaf = {
  scriptHex:string; leafHash:string; leafVersion:192;
  signers: readonly ['borrower','guardian','putWriter'];
};
/**
 * A candidate, opt-in 3-of-3 Tapscript leaf. A standalone leaf does not
 * constrain transaction outputs or implement DLC exercise. All CETs, oracle
 * adaptor proofs and refund must be independently verified before funding.
 */
export function constructOptionLeaf(borrower:string,guardian:string,putWriter:string):OptionLeaf {
  const a=pubkey(borrower,'borrower');
  const b=pubkey(guardian,'guardian');
  const c=pubkey(putWriter,'put writer');
  if(new Set([borrower,guardian,putWriter]).size!==3) throw Error('duplicate signer');
  const script=Buffer.concat([
    Buffer.from([0x20]),a,Buffer.from([0xad,0x20]),b,Buffer.from([0xad,0x20]),c,Buffer.from([0xac]),
  ]);
  if(script.length>=253) throw Error('unsupported script length');
  const hash=taggedHash('TapLeaf',Buffer.concat([Buffer.from([0xc0,script.length]),script]));
  return {scriptHex:script.toString('hex'),leafHash:hash.toString('hex'),
    leafVersion:0xc0,signers:['borrower','guardian','putWriter']};
}
export function matchOptionLeaf(hex:string):{borrower:string;guardian:string;putWriter:string}|null{
  if(!/^20[0-9a-f]{64}ad20[0-9a-f]{64}ad20[0-9a-f]{64}ac$/u.test(hex))return null;
  const borrower=hex.slice(2,66),guardian=hex.slice(70,134),putWriter=hex.slice(138,202);
  return new Set([borrower,guardian,putWriter]).size===3?{borrower,guardian,putWriter}:null;
}

export type RightsObservation = {
  step:string; owner:string; cash:string; debt:string;
  collateralPriority:string; contingentClaims:string; consent:string;
};
/** First independently material property-right difference; no fatwa is inferred. */
export function firstRightsDifference(a:RightsObservation[],b:RightsObservation[]):{
  index:number;field:string;a:string;b:string
}|null{
  const fields=['step','owner','cash','debt','collateralPriority','contingentClaims','consent'] as const;
  if(a.length!==b.length)return{index:Math.min(a.length,b.length),field:'trace-length',a:String(a.length),b:String(b.length)};
  for(let i=0;i<a.length;i++)for(const field of fields){
    if(a[i][field]!==b[i][field])return{index:i,field,a:a[i][field],b:b[i][field]};
  }
  return null;
}

/** Sources concern different instruments. They do not certify this BTC option. */
export const FIQH_REFERENCES = Object.freeze([
  {id:'iifa-63',stance:'prohibits',scope:'conventional financial options',url:'https://iifa-aifi.org/en/1845.html'},
  {id:'iifa-72',stance:'permits-conditionally',scope:'earnest-money sale',url:'https://iifa-aifi.org/en/32466.html'},
  {id:'malaysia-warrants',stance:'recognizes-property-rights',scope:'eligible equity warrants',url:'https://www.sc.com.my/api/documentms/download.ashx?id=511180c4-b0f1-49e3-9f92-46efe55457bc'},
  {id:'iifa-179',stance:'prohibits',scope:'organized bank tawarruq',url:'https://iifa-aifi.org/en/33707.html'},
]);
export type FiqhFacts = {
  creditClassification:'qard'|'partnership'|'unresolved';
  mandatoryBorrowingFeeCents:string;
  provenActualAdminCostCents:string|null;
  borrowerConsentAndDisclosures:boolean;
  enforceableResidualEquityReturn:boolean;
  fundedOptionWriter:boolean;
  coveredCallIndependentOfLenderBenefit:boolean;
  promisedOutcomesFunded:boolean;
  optionsPremiumExternallyDocumented:boolean;
};
export type FiqhScreen={status:'review-only';blockers:string[];sources:typeof FIQH_REFERENCES};
/** A human-auditable disagreement and property-rights screen, NEVER a halal verdict. */
export function screenFiqh(f:FiqhFacts):FiqhScreen{
  const blockers:string[]=[];
  let fee:bigint|null=null,cost:bigint|null=null;
  try {fee=uint(f.mandatoryBorrowingFeeCents,'fee',true)} catch {blockers.push('FEE_NOT_VERIFIABLE')}
  if(f.provenActualAdminCostCents===null)blockers.push('ADMIN_COST_EVIDENCE_ABSENT');
  else try{cost=uint(f.provenActualAdminCostCents,'cost',true)}catch{blockers.push('ADMIN_COST_EVIDENCE_INVALID')}
  if(f.creditClassification==='qard'&&fee!==null&&cost!==null&&fee>cost)blockers.push('QARD_STIPULATED_BENEFIT_CONCERN');
  if(f.creditClassification==='unresolved')blockers.push('LEGAL_CHARACTERIZATION_UNRESOLVED');
  if(!f.borrowerConsentAndDisclosures)blockers.push('CONSENT_NOT_ESTABLISHED');
  if(!f.enforceableResidualEquityReturn)blockers.push('BORROWER_EQUITY_AT_RISK');
  if(!f.fundedOptionWriter)blockers.push('PUT_WRITER_UNFUNDED');
  if(!f.coveredCallIndependentOfLenderBenefit)blockers.push('COVERED_CALL_AS_LENDER_BENEFIT');
  if(!f.promisedOutcomesFunded)blockers.push('ORACLE_OUTCOMES_NOT_FULLY_FUNDED');
  if(!f.optionsPremiumExternallyDocumented)blockers.push('PREMIUM_TRANSFER_UNPROVEN');
  return {status:'review-only',blockers,sources:FIQH_REFERENCES};
}
