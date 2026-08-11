# Εκμετάλλευση DeFi/AMM: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα τεκμηριώνει μια κατηγορία τεχνικών εκμετάλλευσης DeFi/AMM εναντίον DEXes τύπου Uniswap v4, τα οποία επεκτείνουν τα βασικά μαθηματικά με custom hooks. Ένα περιστατικό στο Bunni V2 κατέδειξε μια σχετική αστοχία: ένα bug στην κατεύθυνση του rounding κατά το withdrawal accounting υποεκτιμούσε το active liquidity, και ένα μεταγενέστερο swap αποκάλυψε αυτή την υποεκτίμηση μέσω ενός επικερδούς sandwich.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Βασική ιδέα: αν ένα hook υλοποιεί πρόσθετο accounting που εξαρτάται από fixed‑point math, tick rounding και threshold logic, ένας attacker μπορεί να κατασκευάσει exact‑input swaps που διασχίζουν συγκεκριμένα thresholds, ώστε οι discrepancies του rounding να συσσωρεύονται προς όφελός του. Με την επανάληψη του pattern και στη συνέχεια την ανάληψη του inflated balance, πραγματοποιείται profit, συχνά χρηματοδοτούμενο με flash loan.

## Background: Uniswap v4 hooks και flow των swaps

- Τα hooks είναι contracts που καλούνται από το PoolManager σε συγκεκριμένα lifecycle points (π.χ. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Τα pools αρχικοποιούνται με ένα PoolKey που περιλαμβάνει το hook contract. Μια non-zero hook address ενεργοποιεί τα callbacks που έχουν επιλεγεί για το συγκεκριμένο pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Τα hooks μπορούν να επιστρέφουν **custom deltas** που τροποποιούν τις τελικές balance changes ενός swap ή μιας ενέργειας liquidity (custom accounting). Αυτά τα deltas διακανονίζονται ως net balances στο τέλος του call, επομένως κάθε rounding error μέσα στα hook math συσσωρεύεται πριν από το settlement.<sup>[[4]](#references)</sup>
- Τα core math χρησιμοποιούν fixed-point formats όπως το Q64.96 για το sqrtPriceX96 και tick arithmetic με 1.0001^tick. Κάθε custom math που προστίθεται από πάνω πρέπει να ταιριάζει προσεκτικά με τα rounding semantics, ώστε να αποφεύγεται invariant drift.<sup>[[12]](#references)[[13]](#references)</sup>
- Τα swaps μπορούν να είναι exactInput ή exactOutput. Στα v3/v4, η τιμή κινείται κατά μήκος των ticks· η διέλευση ενός tick boundary μπορεί να ενεργοποιήσει ή να απενεργοποιήσει range liquidity. Τα hooks μπορεί να υλοποιούν πρόσθετη λογική κατά τις threshold/tick crossings.<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Ένα τυπικό ευάλωτο pattern σε custom hooks:

1. Το hook υπολογίζει per‑swap liquidity ή balance deltas χρησιμοποιώντας integer division, mulDiv ή fixed‑point conversions (π.χ. token ↔ liquidity με χρήση sqrtPrice και tick ranges).
2. Η threshold logic (π.χ. rebalancing, stepwise redistribution ή per‑range activation) ενεργοποιείται όταν το μέγεθος ενός swap ή η price movement διασχίζει ένα internal boundary.
3. Το rounding εφαρμόζεται με inconsistent τρόπο (π.χ. truncation προς το μηδέν, floor αντί για ceil) μεταξύ του forward calculation και του settlement path. Οι μικρές discrepancies δεν αλληλοαναιρούνται και, αντίθετα, πιστώνονται στον caller.
4. Exact‑input swaps, με ακριβές μέγεθος ώστε να διασχίζουν αυτά τα boundaries, πραγματοποιούν επανειλημμένα harvest του positive rounding remainder. Ο attacker στη συνέχεια αποσύρει το accumulated credit.

Προϋποθέσεις επίθεσης
- Ένα pool που χρησιμοποιεί custom v4 hook το οποίο εκτελεί πρόσθετα math σε κάθε swap (π.χ. ένα LDF/rebalancer).
- Τουλάχιστον ένα execution path όπου το rounding ωφελεί τον initiator του swap κατά τη διέλευση των thresholds.
- Δυνατότητα επανάληψης πολλών swaps atomically (τα flash loans είναι ιδανικά για την παροχή προσωρινού float και την απόσβεση του gas).

## Practical attack methodology

1) Εντοπισμός candidate pools με hooks
- Κάντε enumerate τα v4 pools και ελέγξτε αν `PoolKey.hooks != address(0)`.
- Επιθεωρήστε το hook bytecode/ABI για callbacks: beforeSwap/afterSwap και τυχόν custom rebalancing methods.
- Αναζητήστε math που: διαιρεί με liquidity, μετατρέπει μεταξύ token amounts και liquidity ή κάνει aggregate τα BalanceDelta με rounding.

2) Μοντελοποίηση των math και thresholds του hook
- Αναπαραγάγετε τον liquidity/redistribution formula του hook: τα inputs συνήθως περιλαμβάνουν sqrtPriceX96, tickLower/Upper, currentTick, fee tier και net liquidity.
- Χαρτογραφήστε τις threshold/step functions: ticks, bucket boundaries ή LDF breakpoints. Προσδιορίστε προς ποια πλευρά κάθε boundary γίνεται το rounding του delta.
- Εντοπίστε τα σημεία όπου οι conversions κάνουν cast μεταξύ uint256/int256, χρησιμοποιούν SafeCast ή βασίζονται σε mulDiv με implicit floor.

3) Calibration των exact‑input swaps για τη διέλευση boundaries
- Χρησιμοποιήστε Foundry/Hardhat simulations για να υπολογίσετε το ελάχιστο Δin που απαιτείται ώστε η τιμή να περάσει οριακά ένα boundary και να ενεργοποιήσει το branch του hook.
- Επαληθεύστε ότι το afterSwap settlement πιστώνει στον caller περισσότερα από το κόστος, αφήνοντας ένα positive BalanceDelta ή credit στο accounting του hook.
- Επαναλάβετε τα swaps για να συσσωρεύσετε credit· στη συνέχεια καλέστε το withdrawal/settlement path του hook.

Στο v4, ο swap loop πρέπει να εκτελείται από ένα PoolManager unlock callback· το negative `amountSpecified` δηλώνει exact input και το `sqrtPriceLimitX96` πρέπει να βρίσκεται αυστηρά εντός του valid range. Ένα zero price limit προκαλεί revert, επομένως το παρακάτω pseudocode χρησιμοποιεί το lower bound για ένα zero-for-one swap.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Παράδειγμα test harness σε στυλ Foundry (pseudocode)
```solidity
function test_precision_rounding_abuse() public {
// 1) Arrange: set up pool with hook
PoolKey memory key = PoolKey({
currency0: USDC,
currency1: USDT,
fee: 500, // 0.05%
tickSpacing: 10,
hooks: IHooks(address(bunniHook))
});
pm.initialize(key, initialSqrtPriceX96);

// 2) Determine a boundary‑crossing exactInput
uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

// 3) Loop swaps to accrue rounding credit
// This loop runs inside the PoolManager unlockCallback.
for (uint i; i < N; ++i) {
pm.swap(
key,
SwapParams({
zeroForOne: true,
amountSpecified: -int256(exactIn), // exactInput
sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1 // allow movement to the lower bound
}),
""
);
}

// 4) Realize inflated credit via hook‑exposed withdrawal
bunniHook.withdrawCredits(msg.sender);
}
```
Calibrating το exactInput
- Υπολόγισε τον στόχο με το core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) σε όρους πραγματικών τιμών· το αποτέλεσμα Q64.96 στρογγυλοποιείται από το TickMath.<sup>[[13]](#references)</sup>
- Προσέγγισε ένα input token0 (zero-for-one) χρησιμοποιώντας τον τύπο που λαμβάνει υπόψη το Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Ταίριαξε το direction-specific rounding της core routine.<sup>[[12]](#references)</sup>
- Προσάρμοσε το Δin κατά ±1 wei γύρω από το boundary, για να εντοπίσεις το branch όπου το hook στρογγυλοποιεί υπέρ σου.

4) Ενίσχυση με flash loans
- Δανείσου ένα μεγάλο notional (π.χ. 3M USDT ή 2000 WETH) για να εκτελέσεις πολλές iterations ατομικά.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
- Αν τα hooks έχουν deployed σε πολλαπλά chains, επαναλάβετε το ίδιο calibration ανά chain.
- Στο περιστατικό Bunni, η flash-loan liquidity και οι bridge routes διέφεραν ανά chain, επομένως λάβετε υπόψη αυτούς τους chain-specific περιορισμούς κατά την αναπαραγωγή της ανάλυσης.<sup>[[1]](#references)[[2]](#references)</sup>

## Συνήθεις βασικές αιτίες στα μαθηματικά των hooks

- Μικτές semantics στρογγυλοποίησης: το mulDiv κάνει floor, ενώ μεταγενέστερα paths ουσιαστικά κάνουν round up· ή οι μετατροπές μεταξύ token/liquidity εφαρμόζουν διαφορετική στρογγυλοποίηση.
- Σφάλματα ευθυγράμμισης tick: χρήση μη στρογγυλοποιημένων ticks σε ένα path και στρογγυλοποίηση με βάση το tick spacing σε άλλο.
- Προβλήματα πρόσημου/overflow του BalanceDelta κατά τη μετατροπή μεταξύ int256 και uint256 κατά το settlement.
- Απώλεια precision στις μετατροπές Q64.96 (sqrtPriceX96), η οποία δεν αντικατοπτρίζεται στο reverse mapping.
- Pathways συσσώρευσης: τα remainders ανά swap καταγράφονται ως credits που μπορούν να γίνουν withdraw από τον caller, αντί να καίγονται ή να διατηρούν zero-sum ισορροπία.

## Custom accounting και delta amplification

- Το Uniswap v4 custom accounting επιτρέπει στα hooks να επιστρέφουν deltas που προσαρμόζουν άμεσα όσα οφείλει ή λαμβάνει ο caller. Αν το hook παρακολουθεί εσωτερικά credits, το residue από τη στρογγυλοποίηση μπορεί να συσσωρευτεί σε πολλές μικρές operations **πριν** πραγματοποιηθεί το τελικό settlement.<sup>[[4]](#references)</sup>
- Αν το hook εκθέτει ένα συμβατό withdrawal path, ένας attacker μπορεί να εναλλάσσει `swap → withdraw → swap` μέσα στο ίδιο PoolManager unlock callback, αναγκάζοντας το hook να επανυπολογίζει τα deltas σε ελαφρώς διαφορετικό state, ενώ τα balances παραμένουν pending μέχρι να ολοκληρωθεί το unlock settlement.<sup>[[4]](#references)[[10]](#references)</sup>
- Κατά το review των hooks, να ανιχνεύετε πάντα τον τρόπο με τον οποίο παράγεται και γίνεται settle το BalanceDelta/HookDelta. Μία μόνο μεροληπτική στρογγυλοποίηση σε ένα branch μπορεί να μετατραπεί σε compounding credit όταν τα deltas επανυπολογίζονται επανειλημμένα.

## Αμυντικές οδηγίες

- Differential testing: συγκρίνετε τα μαθηματικά του hook με μια reference implementation που χρησιμοποιεί arithmetic ρητών αριθμών υψηλής ακρίβειας και απαιτήστε equality ή bounded error που είναι πάντα adversarial (ποτέ ευνοϊκό για τον caller).
- Invariant/property tests:
- Το άθροισμα των deltas (tokens, liquidity) σε όλα τα swap paths και τις hook adjustments πρέπει να διατηρεί την αξία, εκτός από τα fees.
- Κανένα path δεν πρέπει να δημιουργεί θετικό net credit για τον swap initiator σε επαναλαμβανόμενες iterations exactInput.
- Tests για thresholds/tick boundaries γύρω από inputs ±1 wei, τόσο για exactInput όσο και για exactOutput.
- Πολιτική στρογγυλοποίησης: συγκεντρώστε τους rounding helpers, ώστε να κάνουν πάντα round against the user· εξαλείψτε τα inconsistent casts και τα implicit floors.
- Settlement sinks: συσσωρεύστε το αναπόφευκτο rounding residue στο protocol treasury ή κάψτε το· μην το αποδίδετε ποτέ στο msg.sender.
- Rate-limits/guardrails: ελάχιστα μεγέθη swap για rebalancing triggers· απενεργοποιήστε τα rebalances όταν τα deltas είναι sub-wei· κάντε sanity-check στα deltas σε σχέση με τα αναμενόμενα ranges.
- Εξετάστε τα hook callbacks συνολικά: τα beforeSwap/afterSwap και οι before/after αλλαγές liquidity πρέπει να συμφωνούν ως προς το tick alignment και τη delta rounding.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2, ένα Uniswap v4 hook που χρησιμοποιεί Liquidity Density Function (LDF) για τον υπολογισμό της token density και εκτιμήσεων total-liquidity.<sup>[[1]](#references)[[2]](#references)</sup>
- Affected pools: USDC/USDT στο Ethereum και weETH/ETH στο Unichain, συνολικού ύψους περίπου $8.4M.<sup>[[1]](#references)</sup>
- Step 1 (price push): ο attacker έκανε flash-borrow περίπου 3M USDT και έκανε swap για να μετακινήσει το tick περίπου στο 5000, μειώνοντας το **ενεργό** USDC balance σε περίπου 28 wei.<sup>[[1]](#references)</sup>
- Step 2 (rounding drain): 44 μικροσκοπικά withdrawals εκμεταλλεύτηκαν το floor rounding στο `BunniHubLogic::withdraw()` για να μειώσουν το ενεργό USDC balance από 28 wei σε 4 wei (-85.7%), ενώ κάηκε μόνο ένα μικροσκοπικό κλάσμα των LP shares. Η συνολική liquidity μειώθηκε περίπου κατά 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3 (liquidity rebound sandwich): ένα μεγάλο swap μετακίνησε το tick περίπου στο 839,189 (1 USDC ≈ 2.77e36 USDT). Οι εκτιμήσεις liquidity αντιστράφηκαν και αυξήθηκαν περίπου κατά 16.8%, επιτρέποντας ένα sandwich όπου ο attacker έκανε swap back στην inflated price και εξήλθε με κέρδος.<sup>[[1]](#references)</sup>
- Fix που εντοπίστηκε στο post-mortem: αλλάξτε το idle-balance update ώστε να κάνει round **up**, έτσι ώστε τα επαναλαμβανόμενα micro-withdrawals να μην μειώνουν σταδιακά το active balance του pool.<sup>[[1]](#references)</sup>

Απλοποιημένη ευάλωτη γραμμή (και fix του post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Checklist hunting

- Χρησιμοποιεί το pool non-zero hooks address; Ποια callbacks είναι ενεργοποιημένα;
- Υπάρχουν per-swap redistributions/rebalances με custom math; Υπάρχει λογική tick/threshold;
- Πού χρησιμοποιούνται divisions/mulDiv, μετατροπές Q64.96 ή SafeCast; Είναι οι semantics του rounding συνεπείς σε όλο το σύστημα;
- Μπορείς να κατασκευάσεις ένα Δin που μόλις περνά ένα boundary και ενεργοποιεί favorable rounding branch; Έλεγξε και τις δύο κατευθύνσεις, καθώς και τα exactInput και exactOutput.
- Παρακολουθεί το hook credits ή deltas ανά caller, τα οποία μπορούν να αποσυρθούν αργότερα; Βεβαιώσου ότι το residue εξουδετερώνεται.

## References

- [1] [Bunni Exploit Post Mortem (Σεπ. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: Πλήρης ανάλυση του hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: $8.3M drained μέσω flaw στη ρευστότητα (περίληψη)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 background (έρευνα της QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Μηχανισμοί ρευστότητας στο Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Μηχανισμοί swap στο Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks και ζητήματα ασφάλειας](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
