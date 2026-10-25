# Ducat DLC option leaf and ʿilmī uṣūl adapter

Research-only prototype, 25 October 2026. **No authority to sign or broadcast Bitcoin transactions.**

## Pinned upstream sources

| Repository | Commit | Integration surface |
|---|---|---|
| [DUCAT-UNIT/ducat-snap](https://github.com/DUCAT-UNIT/ducat-snap) | 34392b3c3d67979596bd8e5be07d98fde06496c4 | src/psbt.ts, src/cosign-leaf.ts, src/timeout-leaf.ts, src/__tests__/psbt.test.ts |
| [DUCAT-UNIT/app](https://github.com/DUCAT-UNIT/app) | a7a7b98f9caddc2b549c5c28f760856e1f043728 | services/vault, services/liquidation, services/signing |
| [patrickdugan/dlc-verify](https://github.com/patrickdugan/dlc-verify) | 8a9211d6dca9d9a85c4e3ca6c3ba64e7874bdc67 | The current verifier accepts enumerated P2WSH/ECDSA DLCs, not Taproot Schnorr CETs |

This branch stages the proof of concept in an existing writable repo. No fork of Ducat has been created because the connected GitHub interface does not offer a fork operation. Ducat guardian, validator, and production vault-tree construction are not available in these public repositories.

## Economic contract and finite coverage

The borrower pledges BTC and retains all residual property after debt and enforceable option claims. The put writer separately locks a funded BTC bond. The call writer is the borrower, with the call claim covered by existing BTC; genuine payment of the option premiums needs independent evidence.

Each enumerated BTC/USD outcome has a lender, borrower, put-writer, call-holder and miner-fee allocation. Integer arithmetic verifies conservation of satoshis and rejects an insufficient put bond or unpaid loan principal.

For underlying q satoshis, put strike K and oracle price S in equal monetary units:

  putPayoutSats = ceil(q * max(K - S, 0) / S)

The BTC obligation becomes unbounded as S approaches zero. A finite BTC-only bond cannot guarantee all price outcomes. The prototype checks a supplied outcome list; that list is not authenticated against an actual oracle event descriptor.

## Candidate Taproot leaf

The exported leaf builder produces a BIP341 TapLeaf hash for this three-signature script:

  PUSH32(borrower_xonly) OP_CHECKSIGVERIFY
  PUSH32(approved_guardian_xonly) OP_CHECKSIGVERIFY
  PUSH32(funded_put_writer_xonly) OP_CHECKSIG

The leaf alone enforces only signer concurrence. It does not enforce output amounts, authorize an oracle, or provide unilateral option exercise. A secure DLC requires pre-committed Contract Execution Transactions (CETs), Taproot-compatible adaptor signatures, a verified oracle event and time-locked refund. The template remains excluded from Ducat Snap's current signing allowlist. It must never be enabled based only on a supplied frontend context.

A Taproot output key commits the complete script tree. New leaves require an opt-in new/refinanced vault UTXO; confirmed vaults cannot acquire extra spending leaves in place.

## Porting checkpoints

1. Acquire the private Ducat guardian, validator, tree-construction and transaction-acceptance sources. Pin their actual revisions and work on regtest or Mutinynet.
2. Add a new vault type with explicit debt, borrower collateral, separate put-writer bond, known guardian, price event and full rights-priority ledger.
3. Implement Taproot-compatible Schnorr adaptor signing, exact CET and refund byte construction, signatures and refund timelocks. The existing DLC Verify P2WSH/ECDSA path is a different cryptosystem and provides none of these signatures.
4. Independently bind both real funding outpoints, every CET output and complete signed outcome descriptor. Prove BIP341 control-block inclusion against the Taproot output key. Reject unknown guardians, malformed scripts, extra paths and unverified attestations.
5. Extend Ducat Snap's src/psbt.ts checkOwnedTaprootScriptPathInput, action types and confirmation only after the required CET and funding evidence is independently checked. Preserve complete-input/output sighash policy and Snap-owned prevout verification.
6. Add app services/vault and services/liquidation integration with a fixed-term DLC. Remove or atomically supersede the previous spot-liquidation key path before the protection starts; otherwise a legacy oracle may liquidate a hedged vault.
7. Adversarial-test missed or equivocating oracles, reorgs, bond exhaustion, fee-bumping, transaction replacement, signer refusal and refund under UTXO contention.

## Fiqh decision evidence

The screen records concerns about stipulated benefits on qard, missing fee-cost evidence, a lender receiving a call as compensation, failed surplus-equity recovery, incomplete borrower consent or unfunded contingent claims. It always returns review-only. Distinct legal rulings are cross-referenced with their actual instrument scopes:

- [IIFA Resolution 63, 1992](https://iifa-aifi.org/en/1845.html), conventional traded options, prohibition.
- [IIFA Resolution 72, 1993](https://iifa-aifi.org/en/32466.html), conditional permission of specified earnest-money sales.
- [Malaysian Sharia Advisory Council, 1995](https://www.sc.com.my/api/documentms/download.ashx?id=511180c4-b0f1-49e3-9f92-46efe55457bc), qualified equity warrants and transferable subscription rights recognized as property interests.
- [IIFA Resolution 179, 2009](https://iifa-aifi.org/en/33707.html), prohibition of bank-arranged organized tawarruq.

The barzakh comparator uses a predefined trace projection of ownership, debts, claims, priorities and consent to locate the first rights difference between two contracts. It does not issue legal rulings.

## Verification and exclusions

    npm ci
    npm run build
    npm test -- --run tests/ducat-option.test.ts

The source adds no runtime package dependency. Passing tests verifies arithmetic and a candidate script encoding only. Oracle authenticity, adaptor cryptography, option premium payment, collateral recovery on actual Bitcoin, Runes/UNIT burn, production integration and juristic approval remain open.
