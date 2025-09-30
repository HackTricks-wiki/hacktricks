# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα τεκμηριώνει μια κατηγορία τεχνικών εκμετάλλευσης DeFi/AMM εναντίον DEXes τύπου Uniswap v4 που επεκτείνουν τα βασικά μαθηματικά με προσαρμοσμένα hooks. Ένα πρόσφατο περιστατικό στο Bunni V2 εκμεταλλεύτηκε ένα σφάλμα στρογγυλοποίησης/ακρίβειας σε μια Liquidity Distribution Function (LDF) που εκτελούνταν σε κάθε swap, επιτρέποντας στον επιτιθέμενο να συσσωρεύσει θετικό πιστωτικό υπόλοιπο και να εξαντλήσει τη ρευστότητα.

Κύρια ιδέα: εάν ένα hook υλοποιεί πρόσθετη λογιστική που εξαρτάται από fixed‑point math, tick rounding και threshold logic, ένας επιτιθέμενος μπορεί να κατασκευάσει exact‑input swaps που διασχίζουν συγκεκριμένα όρια ώστε οι αποκλίσεις στρογγυλοποίησης να συσσωρεύονται υπέρ του. Επαναλαμβάνοντας το μοτίβο και στη συνέχεια κάνοντας ανάληψη του διογκωμένου υπολοίπου πραγματοποιείται κέρδος, συχνά χρηματοδοτούμενο με flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks είναι συμβόλαια που καλεί ο PoolManager σε συγκεκριμένα σημεία του lifecycle (π.χ., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Οι Pools αρχικοποιούνται με ένα PoolKey που περιλαμβάνει τη διεύθυνση hooks. Αν δεν είναι μηδενική, ο PoolManager εκτελεί callbacks σε κάθε σχετική λειτουργία.
- Τα core math χρησιμοποιούν fixed‑point formats όπως Q64.96 για το sqrtPriceX96 και tick arithmetic με 1.0001^tick. Οποιαδήποτε custom math πάνω από αυτά πρέπει να ταιριάζει προσεκτικά τα rounding semantics για να αποφευχθεί απόκλιση των invariants.
- Τα swaps μπορούν να είναι exactInput ή exactOutput. Σε v3/v4, η τιμή κινείται κατά μήκος των ticks· το πέρασμα ενός tick boundary μπορεί να ενεργοποιήσει/απενεργοποιήσει range liquidity. Τα hooks μπορεί να υλοποιούν επιπλέον λογική κατά τα threshold/tick crossings.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Ένα τυπικό ευάλωτο μοτίβο σε custom hooks:

1. Το hook υπολογίζει ανά‑swap deltas ρευστότητας ή υπολοίπων χρησιμοποιώντας integer division, mulDiv, ή fixed‑point conversions (π.χ., token ↔ liquidity με χρήση sqrtPrice και tick ranges).
2. Η threshold logic (π.χ., rebalancing, stepwise redistribution ή per‑range activation) ενεργοποιείται όταν το μέγεθος ενός swap ή μια μετακίνηση τιμής διασχίζει ένα εσωτερικό όριο.
3. Η στρογγυλοποίηση εφαρμόζεται ασυνεπώς (π.χ., truncation προς το μηδέν, floor έναντι ceil) μεταξύ του forward calculation και της settlement path. Μικρές αποκλίσεις δεν ακυρώνονται και αντίθετα πιστώνονται στον καλούντα.
4. Exact‑input swaps, ακριβούς μεγέθους ώστε να στραγγαλίζουν αυτά τα όρια, επανειλημμένα θερίζουν το θετικό υπόλοιπο στρογγυλοποίησης. Ο επιτιθέμενος αργότερα αποσύρει το συσσωρευμένο πιστωτικό υπόλοιπο.

Προϋποθέσεις επίθεσης
- Ένα pool που χρησιμοποιεί custom v4 hook που εκτελεί πρόσθετα μαθηματικά σε κάθε swap (π.χ., ένα LDF/rebalancer).
- Τουλάχιστον ένα execution path όπου η στρογγυλοποίηση ωφελεί τον initiator του swap κατά τα threshold crossings.
- Ικανότητα επανάληψης πολλαπλών swaps ατομικά (flash loans είναι ιδανικά για παροχή προσωρινού float και απόσβεση των gas).

## Practical attack methodology

1) Identify candidate pools with hooks
- Καταγράψτε v4 pools και ελέγξτε PoolKey.hooks != address(0).
- Επιθεωρήστε hook bytecode/ABI για callbacks: beforeSwap/afterSwap και οποιεσδήποτε custom rebalancing μεθόδους.
- Ψάξτε για math που: διαιρεί με liquidity, μετατρέπει μεταξύ token amounts και liquidity, ή αθροίζει BalanceDelta με στρογγυλοποίηση.

2) Model the hook’s math and thresholds
- Αναπαράγετε τον τύπο liquidity/redistribution του hook: inputs συνήθως περιλαμβάνουν sqrtPriceX96, tickLower/Upper, currentTick, fee tier και net liquidity.
- Χαρτογραφήστε threshold/step functions: ticks, όρια buckets ή LDF breakpoints. Προσδιορίστε σε ποια πλευρά κάθε ορίου στρογγυλοποιείται το delta.
- Εντοπίστε πού γίνονται conversions μεταξύ uint256/int256, χρησιμοποιείται SafeCast, ή βασίζονται σε mulDiv με implicit floor.

3) Calibrate exact‑input swaps to cross boundaries
- Χρησιμοποιήστε Foundry/Hardhat simulations για να υπολογίσετε το ελάχιστο Δin που χρειάζεται για να μετακινήσει την τιμή ακριβώς πέρα από ένα όριο και να ενεργοποιήσει το branch του hook.
- Επαληθεύστε ότι το afterSwap settlement πιστώνει τον καλούντα περισσότερο από το κόστος, αφήνοντας ένα θετικό BalanceDelta ή πιστωτικό υπόλοιπο στην accounting του hook.
- Επαναλάβετε swaps για να συσσωρεύσετε credit· στη συνέχεια καλέστε το withdrawal/settlement path του hook.

Example Foundry‑style test harness (pseudocode)
```solidity
function test_precision_rounding_abuse() public {
// 1) Arrange: set up pool with hook
PoolKey memory key = PoolKey({
currency0: USDC,
currency1: USDT,
fee: 500, // 0.05%
tickSpacing: 10,
hooks: address(bunniHook)
});
pm.initialize(key, initialSqrtPriceX96);

// 2) Determine a boundary‑crossing exactInput
uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

// 3) Loop swaps to accrue rounding credit
for (uint i; i < N; ++i) {
pm.swap(
key,
IPoolManager.SwapParams({
zeroForOne: true,
amountSpecified: int256(exactIn), // exactInput
sqrtPriceLimitX96: 0 // allow tick crossing
}),
""
);
}

// 4) Realize inflated credit via hook‑exposed withdrawal
bunniHook.withdrawCredits(msg.sender);
}
```
Καλιμπράρισμα του exactInput
- Υπολόγισε το ΔsqrtP για ένα tick step: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Προσέγγισε το Δin χρησιμοποιώντας τις φόρμουλες v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Βεβαιώσου ότι η κατεύθυνση στρογγυλοποίησης ταιριάζει με τα βασικά μαθηματικά.
- Ρύθμισε το Δin κατά ±1 wei γύρω από το όριο για να βρεις τον κλάδο όπου το hook στρογγυλοποιεί υπέρ σου.

4) Ενίσχυση με flash loans
- Δανείσου ένα μεγάλο notional (π.χ., 3M USDT ή 2000 WETH) για να τρέξεις πολλές επαναλήψεις ατομικά.
- Εκτέλεσε τον καλιμπραρισμένο swap loop, έπειτα απόσυρε και αποπλήρωσε εντός του flash loan callback.

Aave V3 flash loan skeleton
```solidity
function executeOperation(
address[] calldata assets,
uint256[] calldata amounts,
uint256[] calldata premiums,
address initiator,
bytes calldata params
) external returns (bool) {
// run threshold‑crossing swap loop here
for (uint i; i < N; ++i) {
_exactInBoundaryCrossingSwap();
}
// realize credits / withdraw inflated balances
bunniHook.withdrawCredits(address(this));
// repay
for (uint j; j < assets.length; ++j) {
IERC20(assets[j]).approve(address(POOL), amounts[j] + premiums[j]);
}
return true;
}
```
5) Έξοδος και αναπαραγωγή μεταξύ αλυσίδων
- Αν τα hooks είναι αναπτυγμένα σε πολλαπλές αλυσίδες, επαναλάβετε την ίδια βαθμονόμηση ανά αλυσίδα.
- Η γέφυρα επιστρέφει στη target chain και προαιρετικά κυκλώνει μέσω lending protocols για να συγκαλύψει τις ροές.

## Συνηθισμένες ριζικές αιτίες στα μαθηματικά των hook

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between token/liquidity apply different rounding.
- Tick alignment errors: using unrounded ticks in one path and tick‑spaced rounding in another.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping.
- Accumulation pathways: per‑swap remainders tracked as credits that are withdrawable by the caller instead of being burned/zero‑sum.

## Αμυντικές οδηγίες

- Differential testing: mirror the hook’s math vs a reference implementation using high‑precision rational arithmetic and assert equality or bounded error that is always adversarial (never favorable to caller).
- Invariant/property tests:
- Sum of deltas (tokens, liquidity) across swap paths and hook adjustments must conserve value modulo fees.
- No path should create positive net credit for the swap initiator over repeated exactInput iterations.
- Threshold/tick boundary tests around ±1 wei inputs for both exactInput/exactOutput.
- Rounding policy: centralize rounding helpers that always round against the user; eliminate inconsistent casts and implicit floors.
- Settlement sinks: accumulate unavoidable rounding residue to protocol treasury or burn it; never attribute to msg.sender.
- Rate‑limits/guardrails: minimum swap sizes for rebalancing triggers; disable rebalances if deltas are sub‑wei; sanity‑check deltas against expected ranges.
- Review hook callbacks holistically: beforeSwap/afterSwap and before/after liquidity changes should agree on tick alignment and delta rounding.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) with an LDF applied per swap to rebalance.
- Root cause: rounding/precision error in LDF liquidity accounting during threshold‑crossing swaps; per‑swap discrepancies accrued as positive credits for the caller.
- Ethereum leg: attacker took a ~3M USDT flash loan, performed calibrated exact‑input swaps on USDC/USDT to build credits, withdrew inflated balances, repaid, and routed funds via Aave.
- UniChain leg: repeated the exploit with a 2000 WETH flash loan, siphoning ~1366 WETH and bridging to Ethereum.
- Impact: ~USD 8.3M drained across chains. No user interaction required; entirely on‑chain.

## Hunting checklist

- Does the pool use a non‑zero hooks address? Which callbacks are enabled?
- Are there per‑swap redistributions/rebalances using custom math? Any tick/threshold logic?
- Where are divisions/mulDiv, Q64.96 conversions, or SafeCast used? Are rounding semantics globally consistent?
- Can you construct Δin that barely crosses a boundary and yields a favorable rounding branch? Test both directions and both exactInput and exactOutput.
- Does the hook track per‑caller credits or deltas that can be withdrawn later? Ensure residue is neutralized.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
