# Εκμετάλλευση DeFi/AMM: Κατάχρηση ακρίβειας/στρογγυλοποίησης σε Uniswap v4 Hook

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα τεκμηριώνει μια κατηγορία τεχνικών εκμετάλλευσης DeFi/AMM σε DEX τύπου Uniswap v4, τα οποία επεκτείνουν τα βασικά μαθηματικά με custom hooks. Ένα περιστατικό στο Bunni V2 παρουσιάζει μια σχετική αστοχία: ένα σφάλμα στην κατεύθυνση της στρογγυλοποίησης κατά τον υπολογισμό των αναλήψεων υπολόγισε την ενεργή ρευστότητα χαμηλότερη από την πραγματική, και μια μεταγενέστερη ανταλλαγή αποκάλυψε αυτή την υποεκτίμηση μέσω ενός κερδοφόρου sandwich.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Βασική ιδέα: αν ένα hook υλοποιεί πρόσθετους λογιστικούς υπολογισμούς που εξαρτώνται από fixed-point μαθηματικά, στρογγυλοποίηση tick και λογική κατωφλίων, ένας attacker μπορεί να κατασκευάσει exact-input swaps που περνούν συγκεκριμένα κατώφλια, ώστε οι αποκλίσεις στρογγυλοποίησης να συσσωρεύονται προς όφελός του. Η επανάληψη του μοτίβου και, στη συνέχεια, η ανάληψη του διογκωμένου υπολοίπου αποφέρει κέρδος, το οποίο συχνά χρηματοδοτείται με flash loan.

## Υπόβαθρο: Uniswap v4 hooks και ροή swap

- Τα hooks είναι συμβόλαια που καλεί το PoolManager σε συγκεκριμένα σημεία του κύκλου ζωής (π.χ. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Τα pools αρχικοποιούνται με ένα PoolKey που περιλαμβάνει το συμβόλαιο hook. Μια διεύθυνση hook διαφορετική από το μηδέν ενεργοποιεί τα callbacks που έχουν επιλεγεί για εκείνο το pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Τα hooks μπορούν να επιστρέφουν **custom deltas**, τα οποία τροποποιούν τις τελικές μεταβολές υπολοίπων ενός swap ή μιας ενέργειας ρευστότητας (custom accounting). Αυτά τα deltas εκκαθαρίζονται ως καθαρά υπόλοιπα στο τέλος της κλήσης, επομένως κάθε σφάλμα στρογγυλοποίησης στους υπολογισμούς του hook συσσωρεύεται πριν από την εκκαθάριση.<sup>[[4]](#references)</sup>
- Τα βασικά μαθηματικά χρησιμοποιούν μορφές fixed-point, όπως Q64.96 για το sqrtPriceX96, και αριθμητική tick με βάση το 1.0001^tick. Κάθε custom μαθηματικός υπολογισμός που προστίθεται από πάνω πρέπει να ακολουθεί προσεκτικά τους κανόνες στρογγυλοποίησης, ώστε να αποφεύγεται η απόκλιση του invariant.<sup>[[12]](#references)[[13]](#references)</sup>
- Τα swaps μπορούν να είναι exactInput ή exactOutput. Στα v3/v4, η τιμή κινείται κατά μήκος των ticks· η διέλευση ενός ορίου tick μπορεί να ενεργοποιήσει/απενεργοποιήσει ρευστότητα εύρους. Τα hooks μπορεί να υλοποιούν πρόσθετη λογική κατά τη διέλευση κατωφλίων/ticks.<sup>[[9]](#references)[[11]](#references)</sup>

## Τυπική ευπάθεια: απόκλιση ακρίβειας/στρογγυλοποίησης κατά τη διέλευση κατωφλίων

Ένα τυπικό ευάλωτο μοτίβο σε custom hooks:

1. Το hook υπολογίζει μεταβολές ρευστότητας ή υπολοίπων ανά swap χρησιμοποιώντας ακέραια διαίρεση, mulDiv ή μετατροπές fixed-point (π.χ. μετατροπή token ↔ ρευστότητας με χρήση sqrtPrice και εύρους tick).
2. Η λογική κατωφλίων (π.χ. ανακατανομή, σταδιακή ανακατανομή ή ενεργοποίηση ανά εύρος) ενεργοποιείται όταν το μέγεθος ενός swap ή η μεταβολή της τιμής περνά ένα εσωτερικό όριο.
3. Η στρογγυλοποίηση εφαρμόζεται με ασυνέπεια (π.χ. αποκοπή προς το μηδέν, floor έναντι ceil) μεταξύ του αρχικού υπολογισμού και της διαδρομής εκκαθάρισης. Οι μικρές αποκλίσεις δεν αλληλοαναιρούνται, αλλά πιστώνονται στον caller.
4. Τα exact-input swaps, με μέγεθος που επιλέγεται με ακρίβεια ώστε να περνούν αυτά τα όρια, αποσπούν επανειλημμένα το θετικό υπόλοιπο στρογγυλοποίησης. Αργότερα, ο attacker αποσύρει την πίστωση που έχει συσσωρευτεί.

Προϋποθέσεις επίθεσης
- Ένα pool που χρησιμοποιεί custom v4 hook, το οποίο εκτελεί πρόσθετους υπολογισμούς σε κάθε swap (π.χ. LDF/rebalancer).
- Τουλάχιστον μία διαδρομή εκτέλεσης όπου η στρογγυλοποίηση ωφελεί τον initiator του swap κατά τη διέλευση κατωφλίων.
- Δυνατότητα ατομικής επανάληψης πολλών swaps (τα flash loans είναι ιδανικά για την παροχή προσωρινής ρευστότητας και τον επιμερισμό του gas).

## Πρακτική μεθοδολογία επίθεσης

1) Εντοπισμός υποψήφιων pools με hooks
- Καταγράψτε τα v4 pools και ελέγξτε αν PoolKey.hooks != address(0).
- Εξετάστε το bytecode/ABI του hook για callbacks: beforeSwap/afterSwap και τυχόν custom μεθόδους ανακατανομής.
- Αναζητήστε μαθηματικούς υπολογισμούς που: διαιρούν με τη ρευστότητα, μετατρέπουν ποσά token σε ρευστότητα ή συγκεντρώνουν BalanceDelta με στρογγυλοποίηση.

2) Μοντελοποίηση των μαθηματικών υπολογισμών και των κατωφλίων του hook
- Αναπαραγάγετε τον τύπο ρευστότητας/ανακατανομής του hook: οι είσοδοι συνήθως περιλαμβάνουν sqrtPriceX96, tickLower/Upper, currentTick, fee tier και καθαρή ρευστότητα.
- Χαρτογραφήστε τις συναρτήσεις κατωφλίων/βημάτων: ticks, όρια bucket ή σημεία αλλαγής του LDF. Προσδιορίστε προς ποια πλευρά κάθε ορίου γίνεται η στρογγυλοποίηση του delta.
- Εντοπίστε πού οι μετατροπές κάνουν cast μεταξύ uint256/int256, χρησιμοποιούν SafeCast ή βασίζονται σε mulDiv με implicit floor.

3) Ρύθμιση exact-input swaps ώστε να περνούν τα όρια
- Χρησιμοποιήστε προσομοιώσεις Foundry/Hardhat για να υπολογίσετε το ελάχιστο Δin που χρειάζεται για να μετακινηθεί η τιμή μόλις πέρα από ένα όριο και να ενεργοποιηθεί ο κλάδος του hook.
- Επιβεβαιώστε ότι η εκκαθάριση afterSwap πιστώνει στον caller περισσότερα από το κόστος, αφήνοντας θετικό BalanceDelta ή πίστωση στους λογιστικούς υπολογισμούς του hook.
- Επαναλάβετε τα swaps για να συσσωρεύσετε πίστωση· έπειτα καλέστε τη διαδρομή ανάληψης/εκκαθάρισης του hook.

Στο v4, ο βρόχος swap πρέπει να εκτελείται από callback ξεκλειδώματος του PoolManager· αρνητικό `amountSpecified` δηλώνει exact input, ενώ το `sqrtPriceLimitX96` πρέπει να βρίσκεται αυστηρά εντός του έγκυρου εύρους. Ένα μηδενικό price limit προκαλεί revert, επομένως ο παρακάτω ψευδοκώδικας χρησιμοποιεί το κάτω όριο για swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Παράδειγμα test harness τύπου Foundry (ψευδοκώδικας)
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
- Υπολόγισε την τιμή-στόχο με το core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) σε όρους πραγματικών τιμών· το αποτέλεσμα Q64.96 στρογγυλοποιείται από το TickMath.<sup>[[13]](#references)</sup>
- Προσέγγισε την είσοδο token0 (zero-for-one) χρησιμοποιώντας τον τύπο που λαμβάνει υπόψη το Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Ακολούθησε τη στρογγυλοποίηση του core routine, ανάλογα με την κατεύθυνση.<sup>[[12]](#references)</sup>
- Ρύθμισε το Δin κατά ±1 wei κοντά στο όριο, για να βρεις τον κλάδο όπου το hook στρογγυλοποιεί προς όφελός σου.

4) Ενίσχυση με flash loans
- Δανείσου ένα μεγάλο ονομαστικό ποσό (π.χ. 3M USDT ή 2000 WETH), ώστε να εκτελέσεις πολλές επαναλήψεις ατομικά.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Εκτέλεσε τον βαθμονομημένο βρόχο swap και, στη συνέχεια, κάνε ανάληψη και αποπλήρωσε το δάνειο μέσα στο callback του flash loan.

Σκελετός flash loan στο Aave V3
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

5) Έξοδος και διασταυρούμενη αναπαραγωγή μεταξύ chain
- Αν τα hooks έχουν αναπτυχθεί σε πολλαπλά chain, επαναλάβετε την ίδια βαθμονόμηση σε κάθε chain.
- Στο περιστατικό Bunni, η ρευστότητα από flash loan και οι διαδρομές bridge διέφεραν ανά chain, οπότε λάβετε υπόψη αυτούς τους περιορισμούς ανά chain κατά την αναπαραγωγή της ανάλυσης.<sup>[[1]](#references)[[2]](#references)</sup>

## Συνήθεις βασικές αιτίες στα μαθηματικά των hook

- Μικτή σημασιολογία στρογγυλοποίησης: το mulDiv στρογγυλοποιεί προς τα κάτω, ενώ μεταγενέστερες διαδρομές ουσιαστικά στρογγυλοποιούν προς τα πάνω· ή οι μετατροπές μεταξύ token/ρευστότητας εφαρμόζουν διαφορετική στρογγυλοποίηση.
- Σφάλματα ευθυγράμμισης tick: χρήση μη στρογγυλοποιημένων tick σε μία διαδρομή και στρογγυλοποίησης βάσει tick spacing σε άλλη.
- Ζητήματα προσήμου/υπερχείλισης του BalanceDelta κατά τη μετατροπή μεταξύ int256 και uint256 κατά τον διακανονισμό.
- Απώλεια ακρίβειας στις μετατροπές Q64.96 (sqrtPriceX96), η οποία δεν αντισταθμίζεται στην αντίστροφη αντιστοίχιση.
- Διαδρομές συσσώρευσης: τα υπόλοιπα ανά swap καταγράφονται ως πιστώσεις, τις οποίες μπορεί να αποσύρει ο καλών, αντί να καίγονται ή να μηδενίζονται αμοιβαία.

## Προσαρμοσμένη λογιστική και ενίσχυση delta

- Η προσαρμοσμένη λογιστική του Uniswap v4 επιτρέπει στα hook να επιστρέφουν delta που προσαρμόζουν άμεσα όσα οφείλει ή λαμβάνει ο καλών. Αν το hook παρακολουθεί εσωτερικά πιστώσεις, τα υπόλοιπα στρογγυλοποίησης μπορούν να συσσωρευτούν σε πολλές μικρές πράξεις **πριν** γίνει ο τελικός διακανονισμός.<sup>[[4]](#references)</sup>
- Αν το hook εκθέτει συμβατή διαδρομή ανάληψης, ένας επιτιθέμενος μπορεί να εναλλάσσει `swap → withdraw → swap` μέσα στην ίδια callback ξεκλειδώματος του PoolManager, αναγκάζοντας το hook να επανυπολογίζει τα delta σε ελαφρώς διαφορετική κατάσταση, ενώ τα υπόλοιπα παραμένουν σε εκκρεμότητα μέχρι να ολοκληρωθεί ο διακανονισμός του unlock.<sup>[[4]](#references)[[10]](#references)</sup>
- Κατά την ανασκόπηση hook, να ανιχνεύετε πάντα πώς παράγονται και διακανονίζονται τα BalanceDelta/HookDelta. Μία μεροληπτική στρογγυλοποίηση σε έναν κλάδο μπορεί να μετατραπεί σε πίστωση που συσσωρεύεται, όταν τα delta επανυπολογίζονται επανειλημμένα.

## Οδηγίες άμυνας

- Διαφορικός έλεγχος: συγκρίνετε τα μαθηματικά του hook με μια υλοποίηση αναφοράς που χρησιμοποιεί ρητή αριθμητική υψηλής ακρίβειας και απαιτήστε ισότητα ή σφάλμα εντός ορίων, πάντα εις βάρος του επιτιθέμενου (ποτέ υπέρ του καλούντος).
- Έλεγχοι invariant/property:
  - Το άθροισμα των delta (token, ρευστότητα) στις διαδρομές swap και στις προσαρμογές hook πρέπει να διατηρεί την αξία, με εξαίρεση τις προμήθειες.
  - Καμία διαδρομή δεν πρέπει να δημιουργεί καθαρή θετική πίστωση για τον εκκινητή του swap μετά από επαναλαμβανόμενες επαναλήψεις exactInput.
  - Έλεγχοι ορίων γύρω από ±1 wei εισόδου για exactInput/exactOutput.
- Πολιτική στρογγυλοποίησης: συγκεντρώστε τις βοηθητικές συναρτήσεις στρογγυλοποίησης, ώστε να στρογγυλοποιούν πάντα εις βάρος του χρήστη· εξαλείψτε ασυνεπείς casts και έμμεσες στρογγυλοποιήσεις προς τα κάτω.
- Προορισμοί διακανονισμού: συσσωρεύστε τα αναπόφευκτα υπόλοιπα στρογγυλοποίησης στο ταμείο του πρωτοκόλλου ή κάψτε τα· μην τα αποδίδετε ποτέ στο msg.sender.
- Όρια/δικλείδες ασφαλείας: ελάχιστα μεγέθη swap για triggers επανεξισορρόπησης· απενεργοποιήστε τις επανεξισορροπήσεις αν τα delta είναι μικρότερα από wei· ελέγξτε ότι τα delta βρίσκονται εντός των αναμενόμενων ορίων.
- Εξετάστε συνολικά τα callback του hook: τα beforeSwap/afterSwap και οι before/after αλλαγές ρευστότητας πρέπει να συμφωνούν ως προς την ευθυγράμμιση tick και τη στρογγυλοποίηση delta.

## Μελέτη περίπτωσης: Bunni V2 (2025‑09‑02)

- Πρωτόκολλο: Bunni V2, ένα hook του Uniswap v4 που χρησιμοποιεί μια Liquidity Density Function (LDF) για τον υπολογισμό της πυκνότητας token και των εκτιμήσεων συνολικής ρευστότητας.<sup>[[1]](#references)[[2]](#references)</sup>
- Επηρεαζόμενα pools: USDC/USDT στο Ethereum και weETH/ETH στο Unichain, συνολικής αξίας περίπου $8.4M.<sup>[[1]](#references)</sup>
- Βήμα 1 (ώθηση τιμής): ο επιτιθέμενος δανείστηκε μέσω flash loan ~3M USDT και έκανε swap για να ωθήσει το tick περίπου στο 5000, μειώνοντας το **ενεργό** υπόλοιπο USDC σε περίπου 28 wei.<sup>[[1]](#references)</sup>
- Βήμα 2 (αποστράγγιση μέσω στρογγυλοποίησης): 44 μικρές αναλήψεις εκμεταλλεύτηκαν τη στρογγυλοποίηση προς τα κάτω στο `BunniHubLogic::withdraw()` για να μειώσουν το ενεργό υπόλοιπο USDC από 28 wei σε 4 wei (-85.7%), ενώ κάηκε μόνο ένα μικρό κλάσμα των μεριδίων LP. Η συνολική ρευστότητα μειώθηκε κατά ~84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Βήμα 3 (sandwich ανάκαμψης ρευστότητας): ένα μεγάλο swap μετέφερε το tick στο ~839,189 (1 USDC ≈ 2.77e36 USDT). Οι εκτιμήσεις ρευστότητας αντιστράφηκαν και αυξήθηκαν κατά ~16.8%, επιτρέποντας ένα sandwich όπου ο επιτιθέμενος έκανε swap προς την αντίθετη κατεύθυνση στην διογκωμένη τιμή και αποκόμισε κέρδος κατά την έξοδο.<sup>[[1]](#references)</sup>
- Η διόρθωση που εντοπίστηκε στην ανάλυση μετά το περιστατικό: αλλαγή της ενημέρωσης του αδρανούς υπολοίπου ώστε να γίνεται στρογγυλοποίηση **προς τα πάνω**, για να μην μειώνουν πλέον οι επαναλαμβανόμενες μικροαναλήψεις σταδιακά το ενεργό υπόλοιπο του pool.<sup>[[1]](#references)</sup>

Απλοποιημένη ευάλωτη γραμμή (και διόρθωση μετά το περιστατικό).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Λίστα ελέγχου για τον εντοπισμό ευπαθειών

- Χρησιμοποιεί το pool διεύθυνση hooks διαφορετική από το μηδέν; Ποια callbacks είναι ενεργοποιημένα;
- Γίνονται αναδιανομές/εξισορροπήσεις ανά swap με custom math; Υπάρχει λογική tick/threshold;
- Πού χρησιμοποιούνται διαιρέσεις/mulDiv, μετατροπές Q64.96 ή SafeCast; Είναι συνεπείς οι κανόνες στρογγυλοποίησης σε όλο το σύστημα;
- Μπορείς να κατασκευάσεις ένα Δin που μόλις περνά ένα όριο και οδηγεί σε ευνοϊκό κλάδο στρογγυλοποίησης; Δοκίμασε και τις δύο κατευθύνσεις, καθώς και exactInput και exactOutput.
- Παρακολουθεί το hook πιστώσεις ή deltas ανά caller που μπορούν να αποσυρθούν αργότερα; Βεβαιώσου ότι το υπόλοιπο εξουδετερώνεται.

## References

- [1] [Αναφορά μετά το περιστατικό του Bunni Exploit (Σεπ. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: Πλήρης ανάλυση του hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: $8.3M αφαιρέθηκαν μέσω ελαττώματος ρευστότητας (σύνοψη)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Λευκή βίβλος του Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Υπόβαθρο για το Uniswap v4 (έρευνα της QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Μηχανισμοί ρευστότητας στον πυρήνα του Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Μηχανισμοί swap στον πυρήνα του Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks του Uniswap v4 και ζητήματα ασφάλειας](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol του πυρήνα του Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol του πυρήνα του Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams του Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol του πυρήνα του Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol του πυρήνα του Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey του Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
