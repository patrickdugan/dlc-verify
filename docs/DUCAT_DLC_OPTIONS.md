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


## Offline acceptance layer (added after the initial prototype)

### Exact proposed vault tree

The file src/ducat-option-vault-tree.ts builds a **new**, opt-in two-leaf BIP341 output:

- Existing Ducat borrower + Guardian CHECKSIGVERIFY/CHECKSIG leaf, in its strict canonical shape.
- Candidate three-signature borrower + Guardian + option-writer leaf.

The code derives their TapLeaf hashes, lexicographically sorted TapBranch root, BIP341 TapTweak output key, and both 65-byte control blocks. It compares that **entire** proposed tree to a candidate funding P2TR scriptPubKey and both witnesses. Unlisted unilateral liquidation leaves change the root and fail this comparison.

Key-path bypass matters. BIP341 specifies an independently constructed NUMS point H whose x coordinate is SHA256(uncompressed secp256k1 generator G), namely:

    50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0

The reviewer supplies the scalar r and the claimed internal key x(H+rG). The adapter verifies this derivation with the project's existing secp256k1 package. This supports a claim of unknown discrete log under the hardness assumption, without mathematically proving it. A plain internal key without a valid witness retains an explicit unproven key-path status.

### Exact unsigned CET payout preflight

The file src/ducat-option-cet-policy.ts parses Bitcoin transaction bytes with bitcoinjs-lib and enforces:

- The complete two-leaf NUMS tree matches the pledged BTC output script.
- Both funding outpoints have the exact pinned txid/vout and spend order.
- Every outcome in the finite enumerated domain has one version-2 unsigned CET with exact mature nLockTime and nonfinal input sequences.
- Each output uses a valid P2TR x-only curve key and pays precisely the model's satoshi amount to its unique declared recipient, in role order. A zero payout omits its output, and any nonzero payout must meet the conservative 546-sat dust floor.
- The four recipients' outputs and miner fee exactly conserve the specified BTC collateral and writer bond, with no extra outputs.
- The returned review digest binds the terms, claimed funding scripts, published tree, and the actual CET txids. It is merely a review commitment and requires an independent signature/authentication layer.

The model enforces USD-linked debt using BTC amounts computed at oracle outcomes. If underlying stablecoins lose their peg, the economic interpretation changes. Every signed oracle outcome must be independently authenticated against its signed event announcement before accepting this enumeration as complete.

**Critical omissions even after preflight passes:** actual on-chain unspent proofs, valid Schnorr adaptor signatures and refund signatures, a full writer-bond spending policy, oracle authenticity, a synchronization/atomicity proof between BTC settlement and UNIT debt burn, and the collateral right to reclaim any residual equity. The existing Ducat validator may reject the proposed transaction flow. The existing Snap correctly refuses this new leaf until a separately reviewed feature is implemented.

To test:

    npm ci
    npm run build
    npm test -- --run tests/ducat-option.test.ts tests/ducat-option-vault-tree.test.ts tests/ducat-option-cet-policy.test.ts
    node --experimental-strip-types --test tests/ducat-option.offline.cjs

The Node-only check requires a temporary ES module copy of src/ducat-option.ts into src/ducat-option.mts; this is created by the GitHub Actions workflow.

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
    npm test -- --run tests/ducat-option.test.ts tests/ducat-option-vault-tree.test.ts tests/ducat-option-cet-policy.test.ts

The source adds no runtime package dependency. Passing tests verifies exact arithmetic, a proposed Taproot script tree, and unsigned CET output preflight. Oracle authenticity, adaptor cryptography, option premium payment, collateral recovery on actual Bitcoin, Runes/UNIT burn, production integration and juristic approval remain open.
