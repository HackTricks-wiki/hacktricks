# Εκμετάλλευση DeFi/AMM: Κατάχρηση Precision/Rounding σε Uniswap v4 Hooks

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα τεκμηριώνει μια κατηγορία τεχνικών εκμετάλλευσης DeFi/AMM εναντίον DEXes τύπου Uniswap v4, τα οποία επεκτείνουν τα core math με custom hooks. Ένα πρόσφατο περιστατικό στο Bunni V2 εκμεταλλεύτηκε ένα rounding/precision flaw σε μια Liquidity Distribution Function (LDF) που εκτελείται σε κάθε swap, επιτρέποντας στον attacker να συσσωρεύσει positive credits και να αποστραγγίσει liquidity.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

Η βασική ιδέα: αν ένα hook υλοποιεί πρόσθετο accounting που εξαρτάται από fixed-point math, tick rounding και threshold logic, ένας attacker μπορεί να δημιουργήσει exact-input swaps που διασχίζουν συγκεκριμένα thresholds, ώστε οι rounding discrepancies να συσσωρεύονται προς όφελός του. Με την επανάληψη του pattern και στη συνέχεια την ανάληψη του inflated balance, πραγματοποιείται profit, συχνά με χρηματοδότηση μέσω flash loan.

## Background: Uniswap v4 hooks και swap flow

- Τα hooks είναι contracts που καλούνται από το PoolManager σε συγκεκριμένα lifecycle points (π.χ. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[3]](#references)[[6]](#references)</sup>
- Τα pools αρχικοποιούνται με ένα PoolKey που περιλαμβάνει τη διεύθυνση των hooks. Αν δεν είναι μηδενική, το PoolManager εκτελεί callbacks σε κάθε σχετική operation.<sup>[[6]](#references)</sup>
- Τα hooks μπορούν να επιστρέφουν **custom deltas** που τροποποιούν τις τελικές balance changes ενός swap ή μιας liquidity action (custom accounting). Αυτά τα deltas διακανονίζονται ως net balances στο τέλος της κλήσης, επομένως οποιοδήποτε rounding error μέσα στο hook συσσωρεύεται πριν από το settlement.<sup>[[5]](#references)</sup>
- Το core math χρησιμοποιεί fixed-point formats όπως Q64.96 για sqrtPriceX96 και tick arithmetic με 1.0001^tick. Οποιοδήποτε custom math που προστίθεται από πάνω πρέπει να αντιστοιχίζει προσεκτικά τα rounding semantics, ώστε να αποφεύγεται invariant drift.<sup>[[4]](#references)[[8]](#references)</sup>
- Τα swaps μπορεί να είναι exactInput ή exactOutput. Στα v3/v4, η τιμή κινείται κατά μήκος των ticks· η διάσχιση ενός tick boundary μπορεί να ενεργοποιήσει/απενεργοποιήσει range liquidity. Τα hooks μπορεί να υλοποιούν πρόσθετη logic κατά τις threshold/tick crossings.<sup>[[5]](#references)</sup>

## Vulnerability archetype: threshold-crossing precision/rounding drift

Ένα τυπικό vulnerable pattern σε custom hooks:

1. Το hook υπολογίζει per-swap liquidity ή balance deltas χρησιμοποιώντας integer division, mulDiv ή fixed-point conversions (π.χ. token ↔ liquidity με χρήση sqrtPrice και tick ranges).
2. Η threshold logic (π.χ. rebalancing, stepwise redistribution ή per-range activation) ενεργοποιείται όταν το μέγεθος ενός swap ή η price movement διασχίζει ένα internal boundary.
3. Το rounding εφαρμόζεται ασυνεπώς (π.χ. truncation προς το μηδέν, floor αντί για ceil) μεταξύ του forward calculation και του settlement path. Οι μικρές discrepancies δεν αλληλοαναιρούνται και αντίθετα πιστώνουν τον caller.
4. Exact-input swaps, με ακριβές μέγεθος ώστε να διασχίζουν αυτά τα boundaries, συλλέγουν επανειλημμένα το positive rounding remainder. Ο attacker πραγματοποιεί αργότερα withdrawal του συσσωρευμένου credit.

Προϋποθέσεις επίθεσης
- Ένα pool που χρησιμοποιεί custom v4 hook και εκτελεί πρόσθετο math σε κάθε swap (π.χ. LDF/rebalancer).
- Τουλάχιστον ένα execution path όπου το rounding ωφελεί τον swap initiator κατά τις threshold crossings.
- Δυνατότητα επανάληψης πολλών swaps atomically (τα flash loans είναι ιδανικά για την παροχή προσωρινού float και την απόσβεση του gas).

## Practical attack methodology

1) Εντοπισμός candidate pools με hooks
- Κάντε enumerate τα v4 pools και ελέγξτε αν το PoolKey.hooks != address(0).
- Επιθεωρήστε το hook bytecode/ABI για callbacks: beforeSwap/afterSwap και τυχόν custom rebalancing methods.
- Αναζητήστε math που: διαιρεί με liquidity, μετατρέπει token amounts σε liquidity ή συγκεντρώνει BalanceDelta με rounding.

2) Μοντελοποίηση του math και των thresholds του hook
- Αναδημιουργήστε τον τύπο liquidity/redistribution του hook: τα inputs συνήθως περιλαμβάνουν sqrtPriceX96, tickLower/Upper, currentTick, fee tier και net liquidity.
- Χαρτογραφήστε τις threshold/step functions: ticks, bucket boundaries ή LDF breakpoints. Καθορίστε σε ποια πλευρά κάθε boundary εφαρμόζεται το rounding.
- Εντοπίστε τα σημεία όπου γίνονται casts μεταξύ uint256/int256, χρησιμοποιείται SafeCast ή γίνεται reliance σε mulDiv με implicit floor.

3) Calibration των exact-input swaps για διάσχιση boundaries
- Χρησιμοποιήστε Foundry/Hardhat simulations για να υπολογίσετε το ελάχιστο Δin που απαιτείται ώστε να μετακινηθεί η τιμή μόλις πέρα από ένα boundary και να ενεργοποιηθεί το branch του hook.
- Επαληθεύστε ότι το afterSwap settlement πιστώνει στον caller περισσότερα από το κόστος, αφήνοντας positive BalanceDelta ή credit στο accounting του hook.
- Επαναλάβετε τα swaps για να συσσωρεύσετε credit· στη συνέχεια καλέστε το withdrawal/settlement path του hook.

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
Calibrating το exactInput
- Υπολόγισε το ΔsqrtP για ένα tick step: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Προσέγγισε το Δin χρησιμοποιώντας τους τύπους v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Βεβαιώσου ότι η κατεύθυνση του rounding ταιριάζει με τα core math.
- Προσάρμοσε το Δin κατά ±1 wei γύρω από το boundary, για να βρεις το branch όπου το hook κάνει rounding υπέρ σου.

4) Ενίσχυση με flash loans
- Δανείσου ένα μεγάλο notional (π.χ. 3M USDT ή 2000 WETH) για να εκτελέσεις πολλές iterations atomically.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Εκτέλεσε το calibrated swap loop και, στη συνέχεια, κάνε withdraw και repay μέσα στο flash loan callback.

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
5) Έξοδος και cross-chain replication
- Αν τα hooks έχουν αναπτυχθεί σε πολλές chains, επαναλάβετε την ίδια calibration ανά chain.
- Επιστρέψτε τα proceeds στη target chain και προαιρετικά πραγματοποιήστε κύκλους μέσω lending protocols για να obfuscate τις ροές.<sup>[[2]](#references)</sup>

## Συνήθεις βασικές αιτίες στα μαθηματικά των hooks

- Μεικτή σημασιολογία στρογγυλοποίησης: το mulDiv κάνει floor, ενώ μεταγενέστερες διαδρομές ουσιαστικά κάνουν round up· ή οι μετατροπές μεταξύ token/liquidity εφαρμόζουν διαφορετική στρογγυλοποίηση.
- Σφάλματα ευθυγράμμισης tick: χρήση μη στρογγυλοποιημένων ticks σε μία διαδρομή και στρογγυλοποίηση βάσει tick spacing σε άλλη.
- Ζητήματα προσήμου/υπερχείλισης του BalanceDelta κατά τη μετατροπή μεταξύ int256 και uint256 στο settlement.
- Απώλεια precision στις μετατροπές Q64.96 (sqrtPriceX96), η οποία δεν αντισταθμίζεται στην αντίστροφη αντιστοίχιση.
- Διαδρομές συσσώρευσης: τα υπόλοιπα ανά swap καταγράφονται ως credits που μπορούν να γίνουν withdraw από τον caller αντί να καίγονται/μηδενίζονται.

## Custom accounting και delta amplification

- Το Uniswap v4 custom accounting επιτρέπει στα hooks να επιστρέφουν deltas που προσαρμόζουν άμεσα όσα ο caller οφείλει/λαμβάνει. Αν το hook παρακολουθεί εσωτερικά credits, το υπόλοιπο από τη στρογγυλοποίηση μπορεί να συσσωρεύεται σε πολλές μικρές operations **πριν** πραγματοποιηθεί το τελικό settlement.<sup>[[5]](#references)</sup>
- Αυτό ενισχύει την abuse boundary/threshold: ο attacker μπορεί να εναλλάσσει `swap → withdraw → swap` στο ίδιο tx, αναγκάζοντας το hook να επανυπολογίζει τα deltas πάνω σε ελαφρώς διαφορετικό state, ενώ όλα τα balances παραμένουν pending.
- Κατά τον έλεγχο hooks, να ανιχνεύετε πάντα πώς παράγεται και γίνεται settle το BalanceDelta/HookDelta. Μία μόνο biased στρογγυλοποίηση σε έναν κλάδο μπορεί να μετατραπεί σε compounding credit όταν τα deltas επανυπολογίζονται επανειλημμένα.

## Αμυντικές οδηγίες

- Differential testing: συγκρίνετε τα μαθηματικά του hook με μια reference implementation χρησιμοποιώντας arithmetic rational υψηλής ακρίβειας και επιβεβαιώστε ισότητα ή bounded error που είναι πάντα adversarial (ποτέ ευνοϊκό για τον caller).
- Invariant/property tests:
- Το άθροισμα των deltas (tokens, liquidity) σε όλες τις διαδρομές swap και τις προσαρμογές του hook πρέπει να διατηρεί την αξία modulo fees.
- Καμία διαδρομή δεν πρέπει να δημιουργεί θετικό net credit για τον initiator του swap σε επαναλαμβανόμενες iterations exactInput.
- Tests στα όρια threshold/tick γύρω από inputs ±1 wei, τόσο για exactInput όσο και για exactOutput.
- Πολιτική στρογγυλοποίησης: συγκεντρώστε τα rounding helpers ώστε να κάνουν πάντα round against the user· εξαλείψτε τα ασυνεπή casts και τα implicit floors.
- Settlement sinks: συσσωρεύστε το αναπόφευκτο rounding residue στο protocol treasury ή κάψτε το· ποτέ μην το αποδίδετε στο msg.sender.
- Rate-limits/guardrails: ελάχιστα μεγέθη swap για rebalancing triggers· απενεργοποιήστε τα rebalances όταν τα deltas είναι μικρότερα από ένα wei· κάντε sanity-check στα deltas σε σχέση με τα αναμενόμενα ranges.
- Ελέγξτε ολιστικά τα hook callbacks: τα beforeSwap/afterSwap και οι before/after αλλαγές liquidity πρέπει να συμφωνούν ως προς το tick alignment και το delta rounding.

## Μελέτη περίπτωσης: Bunni V2 (2025-09-02)

- Protocol: Bunni V2 (Uniswap v4 hook) με LDF που εφαρμόζεται ανά swap για rebalance.<sup>[[7]](#references)</sup>
- Επηρεαζόμενα pools: USDC/USDT στο Ethereum και weETH/ETH στο Unichain, συνολικής αξίας περίπου $8.4M.<sup>[[1]](#references)[[2]](#references)</sup>
- Βήμα 1 (price push): ο attacker έκανε flash-borrow περίπου 3M USDT και εκτέλεσε swap για να μετακινήσει το tick περίπου στο 5000, μειώνοντας το **ενεργό** balance USDC σε περίπου 28 wei.<sup>[[7]](#references)</sup>
- Βήμα 2 (rounding drain): 44 μικροσκοπικά withdrawals εκμεταλλεύτηκαν το floor rounding στο `BunniHubLogic::withdraw()` για να μειώσουν το ενεργό balance USDC από 28 wei σε 4 wei (-85.7%), ενώ κάηκε μόνο ένα μικροσκοπικό κλάσμα των LP shares. Η συνολική liquidity υποτιμήθηκε κατά περίπου 84.4%.<sup>[[2]](#references)[[7]](#references)</sup>
- Βήμα 3 (liquidity rebound sandwich): ένα μεγάλο swap μετακίνησε το tick περίπου στο 839,189 (1 USDC ≈ 2.77e36 USDT). Οι εκτιμήσεις liquidity αντιστράφηκαν και αυξήθηκαν κατά περίπου 16.8%, επιτρέποντας ένα sandwich όπου ο attacker έκανε swap προς την αντίθετη κατεύθυνση στην διογκωμένη τιμή και αποχώρησε με κέρδος.<sup>[[7]](#references)</sup>
- Fix που εντοπίστηκε στο post-mortem: τροποποίηση της ενημέρωσης του idle-balance ώστε να κάνει round **up**, έτσι ώστε τα επαναλαμβανόμενα micro-withdrawals να μην μπορούν να μειώνουν σταδιακά το active balance του pool.<sup>[[7]](#references)</sup>

Απλοποιημένη ευάλωτη γραμμή (και fix του post-mortem)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Λίστα ελέγχου αναζήτησης

- Χρησιμοποιεί το pool διεύθυνση hooks με μη μηδενική τιμή; Ποια callbacks είναι ενεργοποιημένα;
- Υπάρχουν per-swap αναδιανομές/rebalances με custom math; Υπάρχει λογική tick/threshold;
- Πού χρησιμοποιούνται divisions/mulDiv, μετατροπές Q64.96 ή SafeCast; Είναι οι semantics του rounding συνεπείς σε όλο το σύστημα;
- Μπορείς να κατασκευάσεις Δin που περνά οριακά ένα boundary και οδηγεί σε ευνοϊκό rounding branch; Δοκίμασε και τις δύο κατευθύνσεις και τόσο exactInput όσο και exactOutput.
- Παρακολουθεί το hook credits ή deltas ανά caller που μπορούν να γίνουν withdraw αργότερα; Βεβαιώσου ότι το residue neutralized.

## Αναφορές

- [1] [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (περίληψη)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: Πλήρης ανάλυση του Hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Υπόβαθρο του Uniswap v4 (έρευνα της QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Μηχανισμοί liquidity στο Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Μηχανισμοί swap στο Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Uniswap v4 Hooks και ζητήματα Security](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Bunni Exploit Post Mortem (Σεπ. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
