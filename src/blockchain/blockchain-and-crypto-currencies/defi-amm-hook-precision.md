# DeFi/AMM Εκμετάλλευση: Uniswap v4 Hook — Κατάχρηση Ακρίβειας/Στρογγυλοποίησης

{{#include ../../banners/hacktricks-training.md}}



Αυτή η σελίδα τεκμηριώνει μια κατηγορία τεχνικών εκμετάλλευσης DeFi/AMM εναντίον DEXes τύπου Uniswap v4 που επεκτείνουν τον βασικό μαθηματικό πυρήνα με custom hooks. Ένα πρόσφατο περιστατικό στο Bunni V2 εκμεταλλεύτηκε ένα σφάλμα στρογγυλοποίησης/ακρίβειας σε ένα Liquidity Distribution Function (LDF) που εκτελούνταν σε κάθε swap, επιτρέποντας στον επιτιθέμενο να συγκεντρώσει θετικές πιστώσεις και να αποστραγγίσει ρευστότητα.

Κύρια ιδέα: εάν ένα hook υλοποιεί επιπλέον λογιστική που εξαρτάται από fixed‑point math, tick rounding και threshold logic, ένας επιτιθέμενος μπορεί να δημιουργήσει exact‑input swaps που διασχίζουν συγκεκριμένα όρια, ώστε οι διαφορές στρογγυλοποίησης να συσσωρεύονται υπέρ του. Επαναλαμβάνοντας το μοτίβο και στη συνέχεια αποσύροντας το διογκωμένο υπόλοιπο πραγματοποιείται κέρδος, συχνά χρηματοδοτούμενο με flash loan.

## Υπόβαθρο: Uniswap v4 hooks και ροή swap

- Τα hooks είναι συμβόλαια που καλεί ο PoolManager σε συγκεκριμένα σημεία του lifecycle (π.χ., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Τα Pools αρχικοποιούνται με PoolKey που περιλαμβάνει τη διεύθυνση του hooks. Αν είναι μη‑μηδενική, ο PoolManager εκτελεί callbacks σε κάθε σχετική λειτουργία.
- Τα hooks μπορούν να επιστρέψουν **custom deltas** που τροποποιούν τις τελικές αλλαγές υπολοίπων ενός swap ή ενέργειας ρευστότητας (custom accounting). Αυτά τα deltas διακανονίζονται ως καθαρά υπόλοιπα στο τέλος της κλήσης, οπότε οποιοδήποτε σφάλμα στρογγυλοποίησης μέσα στα μαθηματικά του hook συσσωρεύεται πριν τον διακανονισμό.
- Ο βασικός μαθηματικός πυρήνας χρησιμοποιεί fixed‑point formats όπως Q64.96 για sqrtPriceX96 και tick arithmetic με 1.0001^tick. Οποιαδήποτε custom math που στρώνεται από πάνω πρέπει να ταιριάζει προσεκτικά τα rounding semantics για να αποφευχθεί drift στα invariants.
- Τα swaps μπορεί να είναι exactInput ή exactOutput. Στα v3/v4, η τιμή κινείται κατά μήκος των ticks· η διάσχιση ορίου tick μπορεί να ενεργοποιήσει/απενεργοποιήσει range liquidity. Τα hooks μπορεί να υλοποιούν επιπλέον λογική σε threshold/tick crossings.

## Αρχέτυπο ευπάθειας: παρέκκλιση ακρίβειας/στρογγυλοποίησης σε διάσχιση ορίου

Ένα τυπικό ευάλωτο μοτίβο σε custom hooks:

1. Το hook υπολογίζει ανά‑swap deltas ρευστότητας ή υπολοίπων χρησιμοποιώντας integer division, mulDiv, ή μετατροπές fixed‑point (π.χ., token ↔ liquidity χρησιμοποιώντας sqrtPrice και tick ranges).
2. Η threshold logic (π.χ., rebalancing, stepwise redistribution ή per‑range activation) ενεργοποιείται όταν το μέγεθος swap ή η μετακίνηση τιμής διασχίζει ένα εσωτερικό όριο.
3. Η στρογγυλοποίηση εφαρμόζεται ασυνεπώς (π.χ., truncation προς το μηδέν, floor έναντι ceil) μεταξύ του αρχικού υπολογισμού και του μονοπατιού διακανονισμού. Μικρές διαφορές δεν ακυρώνονται αλλά αντίθετα πιστώνονται στον caller.
4. Exact‑input swaps, με ακριβή μεγέθη ώστε να καλύπτουν αυτά τα όρια, συγκομίζουν επανειλημμένα το θετικό υπόλοιπο στρογγυλοποίησης. Ο επιτιθέμενος αργότερα αποσύρει την συσσωρευμένη πίστωση.

Προϋποθέσεις επίθεσης
- Ένα pool που χρησιμοποιεί custom v4 hook που εκτελεί επιπλέον μαθηματικά σε κάθε swap (π.χ., ένα LDF/rebalancer).
- Τουλάχιστον ένα execution path όπου η στρογγυλοποίηση ωφελεί τον swap initiator κατά τις διάσχισης ορίων.
- Δυνατότητα να επαναλαμβάνει πολλά swaps ατομικά (flash loans είναι ιδανικά για παροχή προσωρινής ρευστότητας και να αμοιβοποιήσουν το gas).

## Πρακτική μεθοδολογία επίθεσης

1) Εντοπισμός υποψήφιων pools με hooks
- Καταγραφή των v4 pools και έλεγχος PoolKey.hooks != address(0).
- Εξέταση του hook bytecode/ABI για callbacks: beforeSwap/afterSwap και οποιεσδήποτε custom rebalancing μεθόδους.
- Ψάξτε για μαθηματικά που: διαιρούν με liquidity, μετατρέπουν μεταξύ ποσών token και liquidity, ή αθροίζουν BalanceDelta με στρογγυλοποίηση.

2) Μοντελοποίηση των μαθηματικών του hook και των ορίων
- Ανακατασκευή του liquidity/redistribution τύπου του hook: τα inputs συνήθως περιλαμβάνουν sqrtPriceX96, tickLower/Upper, currentTick, fee tier, και net liquidity.
- Χαρτογράφηση των threshold/step functions: ticks, bucket boundaries, ή LDF breakpoints. Προσδιορίστε σε ποια πλευρά κάθε ορίου γίνεται rounding του delta.
- Εντοπίστε πού γίνονται conversions μεταξύ uint256/int256, χρησιμοποιείται SafeCast, ή στηρίζονται σε mulDiv με implicit floor.

3) Βαθμονόμηση exact‑input swaps για να διασχίζουν όρια
- Χρησιμοποιήστε Foundry/Hardhat simulations για να υπολογίσετε το ελάχιστο Δin απαραίτητο για να μετακινήσει την τιμή ακριβώς πέρα από ένα όριο και να ενεργοποιήσει το branch του hook.
- Επαληθεύστε ότι ο afterSwap διακανονισμός πιστώνει τον caller περισσότερο από το κόστος, αφήνοντας ένα θετικό BalanceDelta ή πίστωση στην λογιστική του hook.
- Επαναλάβετε swaps για να συσσωρεύσετε πίστωση· στη συνέχεια καλέστε το withdrawal/settlement path του hook.

Παράδειγμα Foundry‑style test harness (pseudocode)
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
Calibrating the exactInput
- Υπολογίστε το ΔsqrtP για ένα tick step: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Προσεγγίστε το Δin χρησιμοποιώντας τους τύπους v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Βεβαιωθείτε ότι η κατεύθυνση στρογγυλοποίησης ταιριάζει με τα θεμελιώδη μαθηματικά.
- Προσαρμόστε το Δin κατά ±1 wei γύρω από το όριο για να βρείτε το branch όπου το hook στρογγυλοποιεί υπέρ σας.

4) Amplify with flash loans
- Δανειστείτε ένα μεγάλο notional (π.χ., 3M USDT ή 2000 WETH) για να εκτελέσετε πολλές επαναλήψεις ατομικά.
- Εκτελέστε το calibrated swap loop, μετά αποσύρετε και αποπληρώστε εντός του flash loan callback.

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
5) Έξοδος και διασταυρούμενη αναπαραγωγή σε αλυσίδες
- If hooks are deployed on multiple chains, repeat the same calibration per chain.
- Το bridge επιστρέφει στην target chain και προαιρετικά κάνει κύκλους μέσω lending protocols για να θολώσει τις ροές.

## Κοινές ρίζες προβλημάτων στη μαθηματική των hooks

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between token/liquidity apply different rounding.
- Tick alignment errors: using unrounded ticks in one path and tick‑spaced rounding in another.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping.
- Accumulation pathways: per‑swap remainders tracked as credits that are withdrawable by the caller instead of being burned/zero‑sum.

## Προσαρμοσμένη λογιστική & ενίσχυση delta

- Uniswap v4 custom accounting lets hooks return deltas that directly adjust what the caller owes/receives. If the hook tracks credits internally, rounding residue can accumulate across many small operations **before** the final settlement happens.
- This makes boundary/threshold abuse stronger: the attacker can alternate `swap → withdraw → swap` in the same tx, forcing the hook to recompute deltas on slightly different state while all balances are still pending.
- When reviewing hooks, always trace how BalanceDelta/HookDelta is produced and settled. A single biased rounding in one branch can become a compounding credit when deltas are repeatedly re‑computed.

## Οδηγίες άμυνας

- Differential testing: mirror the hook’s math vs a reference implementation using high‑precision rational arithmetic and assert equality or bounded error that is always adversarial (never favorable to caller).
- Invariant/property tests:
- Sum of deltas (tokens, liquidity) across swap paths and hook adjustments must conserve value modulo fees.
- No path should create positive net credit for the swap initiator over repeated exactInput iterations.
- Threshold/tick boundary tests around ±1 wei inputs for both exactInput/exactOutput.
- Rounding policy: centralize rounding helpers that always round against the user; eliminate inconsistent casts and implicit floors.
- Settlement sinks: accumulate unavoidable rounding residue to protocol treasury or burn it; never attribute to msg.sender.
- Rate‑limits/guardrails: minimum swap sizes for rebalancing triggers; disable rebalances if deltas are sub‑wei; sanity‑check deltas against expected ranges.
- Review hook callbacks holistically: beforeSwap/afterSwap and before/after liquidity changes should agree on tick alignment and delta rounding.

## Μελέτη περίπτωσης: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) with an LDF applied per swap to rebalance.
- Affected pools: USDC/USDT on Ethereum and weETH/ETH on Unichain, totaling about $8.4M.
- Step 1 (price push): the attacker flash‑borrowed ~3M USDT and swapped to push the tick to ~5000, shrinking the **ενεργό** USDC υπόλοιπο down to ~28 wei.
- Step 2 (rounding drain): 44 tiny αναλήψεις exploited floor rounding in `BunniHubLogic::withdraw()` to reduce the active USDC balance from 28 wei to 4 wei (‑85.7%) while only a tiny fraction of LP shares was burned. Total liquidity was underestimated by ~84.4%.
- Step 3 (liquidity rebound sandwich): a large swap moved the tick to ~839,189 (1 USDC ≈ 2.77e36 USDT). Liquidity estimates flipped and increased by ~16.8%, enabling a sandwich where the attacker swapped back at the inflated price and exited with profit.
- Fix identified in the post‑mortem: change the idle‑balance update to round **επάνω** so repeated micro‑withdrawals can’t ratchet the pool’s active balance downward.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Λίστα ελέγχου ανίχνευσης

- Χρησιμοποιεί το pool διεύθυνση hooks διαφορετική του μηδενός; Ποια callbacks είναι ενεργοποιημένα;
- Υπάρχουν per‑swap ανακατανομές/rebalances που χρησιμοποιούν custom math; Υπάρχει κάποια tick/threshold λογική;
- Πού γίνονται divisions/mulDiv, μετατροπές Q64.96, ή χρήση SafeCast; Είναι οι κανόνες στρογγυλοποίησης συνεπείς σε όλο το σύστημα;
- Μπορείς να κατασκευάσεις Δin που μόλις διασχίζει ένα όριο και παράγει ευνοϊκό branch στρογγυλοποίησης; Δοκίμασε και τις δύο κατευθύνσεις και τόσο exactInput όσο και exactOutput.
- Το hook παρακολουθεί per‑caller credits ή deltas που μπορούν να αναληφθούν αργότερα; Βεβαιώσου ότι το υπόλοιπο εξουδετερώνεται.

## Αναφορές

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
