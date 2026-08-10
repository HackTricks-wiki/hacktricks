# Εκμετάλλευση DeFi/AMM: Abuse Ακρίβειας/Στρογγυλοποίησης Hook στο Uniswap v4

Αυτή η σελίδα τεκμηριώνει μια κατηγορία τεχνικών εκμετάλλευσης DeFi/AMM εναντίον DEXes τύπου Uniswap v4, τα οποία επεκτείνουν τα core μαθηματικά με custom hooks. Ένα περιστατικό στο Bunni V2 ανέδειξε μια σχετική αστοχία: ένα bug στην κατεύθυνση στρογγυλοποίησης κατά το accounting των αναλήψεων υποεκτιμούσε το ενεργό liquidity, και ένα μεταγενέστερο swap αποκάλυψε αυτή την υποεκτίμηση μέσω ενός κερδοφόρου sandwich.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Βασική ιδέα: αν ένα hook υλοποιεί επιπλέον accounting που εξαρτάται από fixed-point math, στρογγυλοποίηση ticks και λογική thresholds, ένας attacker μπορεί να κατασκευάσει exact-input swaps που διασχίζουν συγκεκριμένα thresholds, ώστε οι αποκλίσεις στρογγυλοποίησης να συσσωρεύονται υπέρ του. Με την επανάληψη του μοτίβου και στη συνέχεια την ανάληψη του διογκωμένου balance, πραγματοποιείται κέρδος, συχνά χρηματοδοτούμενο με flash loan.

## Background: Uniswap v4 hooks και ροή swap

- Τα hooks είναι contracts που καλούνται από το PoolManager σε συγκεκριμένα lifecycle points (π.χ. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Τα pools αρχικοποιούνται με ένα PoolKey που περιλαμβάνει το hook contract. Μια διεύθυνση hook διαφορετική από το zero ενεργοποιεί τα callbacks που έχουν επιλεγεί για το συγκεκριμένο pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Τα hooks μπορούν να επιστρέφουν **custom deltas** που τροποποιούν τις τελικές μεταβολές balance ενός swap ή μιας ενέργειας liquidity (custom accounting). Αυτά τα deltas διακανονίζονται ως net balances στο τέλος του call, επομένως οποιοδήποτε rounding error μέσα στα μαθηματικά του hook συσσωρεύεται πριν από το settlement.<sup>[[4]](#references)</sup>
- Τα core μαθηματικά χρησιμοποιούν fixed-point formats όπως το Q64.96 για το sqrtPriceX96 και arithmetic ticks με 1.0001^tick. Οποιοδήποτε custom math που βασίζεται σε αυτά πρέπει να αντιστοιχίζει προσεκτικά τα semantics στρογγυλοποίησης, ώστε να αποφεύγεται invariant drift.<sup>[[12]](#references)[[13]](#references)</sup>
- Τα swaps μπορούν να είναι exactInput ή exactOutput. Στα v3/v4, η τιμή μετακινείται κατά μήκος των ticks· η διάσχιση ενός ορίου tick μπορεί να ενεργοποιήσει/απενεργοποιήσει liquidity ενός range. Τα hooks μπορεί να υλοποιούν πρόσθετη λογική κατά τις διελεύσεις από thresholds/ticks.<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: drift ακρίβειας/στρογγυλοποίησης κατά τη διάσχιση threshold

Ένα τυπικό ευάλωτο pattern σε custom hooks:

1. Το hook υπολογίζει liquidity ή balance deltas ανά swap χρησιμοποιώντας integer division, mulDiv ή fixed-point conversions (π.χ. token ↔ liquidity με χρήση sqrtPrice και tick ranges).
2. Η λογική threshold (π.χ. rebalancing, stepwise redistribution ή per-range activation) ενεργοποιείται όταν το μέγεθος ενός swap ή η μεταβολή της τιμής διασχίζει ένα εσωτερικό boundary.
3. Η στρογγυλοποίηση εφαρμόζεται ασυνεπώς (π.χ. truncation προς το μηδέν, floor έναντι ceil) μεταξύ του forward calculation και του settlement path. Μικρές αποκλίσεις δεν αλληλοαναιρούνται, αλλά αντίθετα πιστώνουν τον caller.
4. Exact-input swaps, με ακριβές μέγεθος ώστε να διασχίζουν αυτά τα boundaries, συλλέγουν επανειλημμένα το θετικό remainder της στρογγυλοποίησης. Ο attacker αργότερα αποσύρει το συσσωρευμένο credit.

Attack preconditions
- Ένα pool που χρησιμοποιεί custom v4 hook και εκτελεί επιπλέον math σε κάθε swap (π.χ. ένα LDF/rebalancer).
- Τουλάχιστον ένα execution path όπου η στρογγυλοποίηση ωφελεί τον initiator του swap κατά τη διάσχιση thresholds.
- Δυνατότητα επανάληψης πολλών swaps atomically (τα flash loans είναι ιδανικά για την παροχή προσωρινού float και την απόσβεση του gas).

## Practical attack methodology

1) Εντοπισμός candidate pools με hooks
- Enumerate τα v4 pools και έλεγξε αν `PoolKey.hooks != address(0)`.
- Επιθεώρησε το bytecode/ABI του hook για callbacks: beforeSwap/afterSwap και τυχόν custom rebalancing methods.
- Αναζήτησε math που: διαιρεί με liquidity, μετατρέπει μεταξύ token amounts και liquidity ή συγκεντρώνει BalanceDelta με rounding.

2) Μοντελοποίηση των μαθηματικών και των thresholds του hook
- Αναδημιούργησε τον τύπο liquidity/redistribution του hook: οι είσοδοι συνήθως περιλαμβάνουν sqrtPriceX96, tickLower/Upper, currentTick, fee tier και net liquidity.
- Χαρτογράφησε τις threshold/step functions: ticks, bucket boundaries ή LDF breakpoints. Καθόρισε σε ποια πλευρά κάθε boundary εφαρμόζεται η στρογγυλοποίηση.
- Εντόπισε τα σημεία όπου γίνεται cast μεταξύ uint256/int256, χρησιμοποιείται SafeCast ή γίνεται reliance σε mulDiv με implicit floor.

3) Calibration exact-input swaps για τη διάσχιση boundaries
- Χρησιμοποίησε Foundry/Hardhat simulations για να υπολογίσεις το ελάχιστο Δin που απαιτείται ώστε η τιμή να μετακινηθεί μόλις πέρα από ένα boundary και να ενεργοποιηθεί το branch του hook.
- Επαλήθευσε ότι το afterSwap settlement πιστώνει στον caller περισσότερα από το κόστος, αφήνοντας θετικό BalanceDelta ή credit στο accounting του hook.
- Επανάλαβε τα swaps για να συσσωρεύσεις credit και στη συνέχεια κάλεσε το withdrawal/settlement path του hook.

Στο v4, ο βρόχος του swap πρέπει να εκτελείται από ένα PoolManager unlock callback· το αρνητικό `amountSpecified` δηλώνει exact input και το `sqrtPriceLimitX96` πρέπει να βρίσκεται αυστηρά εντός του valid range. Ένα zero price limit προκαλεί revert, επομένως το παρακάτω pseudocode χρησιμοποιεί το lower bound για ένα zero-for-one swap.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Example Foundry‑style test harness (pseudocode)
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
Βαθμονόμηση του exactInput
- Υπολογίστε τον στόχο με το core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) σε όρους πραγματικών τιμών· το αποτέλεσμα Q64.96 στρογγυλοποιείται από το TickMath.<sup>[[13]](#references)</sup>
- Προσεγγίστε ένα input token0 (zero-for-one) χρησιμοποιώντας τον τύπο που λαμβάνει υπόψη το Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Ταιριάξτε τη στρογγυλοποίηση συγκεκριμένης κατεύθυνσης της core routine.<sup>[[12]](#references)</sup>
- Προσαρμόστε το Δin κατά ±1 wei γύρω από το boundary για να βρείτε το branch όπου το hook στρογγυλοποιεί υπέρ σας.

4) Ενίσχυση με flash loans
- Δανειστείτε ένα μεγάλο notional (π.χ. 3M USDT ή 2000 WETH) για να εκτελέσετε πολλές iterations ατομικά.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Εκτελέστε το calibrated swap loop και, στη συνέχεια, κάντε withdraw και repay μέσα στο flash loan callback.

Σκελετός flash loan του Aave V3
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
5) Έξοδος και cross‑chain replication
- Αν τα hooks έχουν αναπτυχθεί σε πολλαπλές chains, επαναλάβετε την ίδια calibration ανά chain.
- Στο περιστατικό του Bunni, η ρευστότητα flash-loan και οι bridge routes διέφεραν ανά chain, επομένως λάβετε υπόψη αυτούς τους chain-specific περιορισμούς κατά την αναπαραγωγή της ανάλυσης.<sup>[[1]](#references)[[2]](#references)</sup>

## Συνήθεις root causes στα μαθηματικά των hooks

- Μικτές σημασιολογίες στρογγυλοποίησης: το mulDiv κάνει floor, ενώ μεταγενέστερα paths ουσιαστικά κάνουν round up· ή οι μετατροπές μεταξύ token/liquidity εφαρμόζουν διαφορετική στρογγυλοποίηση.
- Σφάλματα ευθυγράμμισης tick: χρήση μη στρογγυλοποιημένων ticks σε ένα path και tick‑spaced rounding σε άλλο.
- Προβλήματα προσήμου/overflow του BalanceDelta κατά τη μετατροπή μεταξύ int256 και uint256 στο settlement.
- Απώλεια precision στις μετατροπές Q64.96 (sqrtPriceX96), η οποία δεν αντιστοιχίζεται αντίστροφα.
- Pathways συσσώρευσης: τα υπόλοιπα ανά swap καταγράφονται ως credits που μπορούν να γίνουν withdraw από τον caller, αντί να καίγονται ή να μηδενίζονται.

## Custom accounting και delta amplification

- Το Uniswap v4 custom accounting επιτρέπει στα hooks να επιστρέφουν deltas που προσαρμόζουν άμεσα όσα ο caller οφείλει ή λαμβάνει. Αν το hook καταγράφει εσωτερικά credits, το residue της στρογγυλοποίησης μπορεί να συσσωρευτεί σε πολλές μικρές operations **πριν** πραγματοποιηθεί το τελικό settlement.<sup>[[4]](#references)</sup>
- Αν το hook εκθέτει συμβατό withdrawal path, ένας attacker μπορεί να εναλλάσσει `swap → withdraw → swap` μέσα στο ίδιο PoolManager unlock callback, αναγκάζοντας το hook να επανυπολογίζει τα deltas σε ελαφρώς διαφορετικό state, ενώ τα balances παραμένουν pending μέχρι να ολοκληρωθεί το unlock settlement.<sup>[[4]](#references)[[10]](#references)</sup>
- Κατά το review των hooks, να ανιχνεύετε πάντα τον τρόπο με τον οποίο παράγεται και γίνεται settle το BalanceDelta/HookDelta. Μία biased rounding σε ένα branch μπορεί να μετατραπεί σε compounding credit όταν τα deltas επανυπολογίζονται επανειλημμένα.

## Αμυντικές οδηγίες

- Differential testing: συγκρίνετε τα μαθηματικά του hook με μια reference implementation χρησιμοποιώντας high-precision rational arithmetic και απαιτήστε equality ή bounded error που είναι πάντα adversarial (ποτέ ευνοϊκό για τον caller).
- Invariant/property tests:
- Το άθροισμα των deltas (tokens, liquidity) σε όλα τα swap paths και τις hook adjustments πρέπει να διατηρεί την αξία, modulo fees.
- Κανένα path δεν πρέπει να δημιουργεί θετικό net credit για τον swap initiator σε επαναλαμβανόμενες iterations exactInput.
- Threshold/tick boundary tests γύρω από inputs ±1 wei, τόσο για exactInput όσο και για exactOutput.
- Πολιτική στρογγυλοποίησης: συγκεντρώστε τα rounding helpers σε ένα σημείο, ώστε να κάνουν πάντα round against the user· εξαλείψτε τα inconsistent casts και τα implicit floors.
- Settlement sinks: συσσωρεύστε το αναπόφευκτο rounding residue στο protocol treasury ή κάψτε το· ποτέ μην το αποδίδετε στον msg.sender.
- Rate-limits/guardrails: minimum swap sizes για rebalancing triggers· απενεργοποιήστε τα rebalances αν τα deltas είναι sub-wei· κάντε sanity-check στα deltas σε σχέση με τα αναμενόμενα ranges.
- Εξετάστε τα hook callbacks ολιστικά: τα beforeSwap/afterSwap και οι before/after liquidity changes πρέπει να συμφωνούν ως προς το tick alignment και το delta rounding.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2, ένα Uniswap v4 hook που χρησιμοποιεί Liquidity Density Function (LDF) για τον υπολογισμό της token density και estimates της συνολικής liquidity.<sup>[[1]](#references)[[2]](#references)</sup>
- Affected pools: USDC/USDT στο Ethereum και weETH/ETH στο Unichain, συνολικού ύψους περίπου $8.4M.<sup>[[1]](#references)</sup>
- Step 1 (price push): ο attacker έκανε flash-borrow περίπου 3M USDT και έκανε swap ώστε να ωθήσει το tick περίπου στο 5000, μειώνοντας το **ενεργό** USDC balance σε περίπου 28 wei.<sup>[[1]](#references)</sup>
- Step 2 (rounding drain): 44 tiny withdrawals εκμεταλλεύτηκαν το floor rounding στο `BunniHubLogic::withdraw()` για να μειώσουν το ενεργό USDC balance από 28 wei σε 4 wei (-85.7%), ενώ κάηκε μόνο ένα tiny fraction των LP shares. Η συνολική liquidity μειώθηκε περίπου κατά 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3 (liquidity rebound sandwich): ένα large swap μετέφερε το tick περίπου στο 839,189 (1 USDC ≈ 2.77e36 USDT). Τα liquidity estimates αντιστράφηκαν και αυξήθηκαν περίπου κατά 16.8%, επιτρέποντας ένα sandwich όπου ο attacker έκανε swap back στην inflated price και αποχώρησε με profit.<sup>[[1]](#references)</sup>
- Fix identified in the post-mortem: αλλάξτε το idle-balance update ώστε να κάνει round **up**, έτσι ώστε τα repeated micro-withdrawals να μην μειώνουν πλέον σταδιακά το active balance του pool.<sup>[[1]](#references)</sup>

Simplified vulnerable line (and post‑mortem fix).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Λίστα ελέγχου hunting

- Χρησιμοποιεί το pool non-zero hooks address; Ποια callbacks είναι ενεργοποιημένα;
- Υπάρχουν per-swap αναδιανομές/επανα balancing με custom math; Υπάρχει λογική tick/threshold;
- Πού χρησιμοποιούνται divisions/mulDiv, μετατροπές Q64.96 ή SafeCast; Είναι οι semantics του rounding συνεπείς σε όλο το σύστημα;
- Μπορείς να κατασκευάσεις Δin που περνά οριακά ένα boundary και οδηγεί σε ευνοϊκό rounding branch; Δοκίμασε και τις δύο κατευθύνσεις, καθώς και exactInput και exactOutput.
- Παρακολουθεί το hook credits ή deltas ανά caller, τα οποία μπορούν να γίνουν withdraw αργότερα; Βεβαιώσου ότι το residue εξουδετερώνεται.

## References

- [1] [Post Mortem του Bunni Exploit (Σεπ. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: Πλήρης ανάλυση του Hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: $8.3M αποστραγγίστηκαν μέσω προβλήματος στο Liquidity (περίληψη)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper του Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Υπόβαθρο του Uniswap v4 (έρευνα της QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Μηχανισμοί Liquidity στο Uniswap v4 Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Μηχανισμοί Swap στο Uniswap v4 Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks και ζητήματα Security](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 Core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 Core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 Core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 Core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
