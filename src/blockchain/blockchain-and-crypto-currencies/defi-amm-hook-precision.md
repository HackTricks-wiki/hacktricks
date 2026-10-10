# Εκμετάλλευση DeFi/AMM: Κατάχρηση ακρίβειας/στρογγυλοποίησης σε Uniswap v4 Hook

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα παρουσιάζει μια κατηγορία τεχνικών εκμετάλλευσης DeFi/AMM εναντίον DEX τύπου Uniswap v4, τα οποία επεκτείνουν τα βασικά μαθηματικά με custom hooks. Ένα περιστατικό στο Bunni V2 αναδεικνύει μια σχετική αστοχία: ένα σφάλμα στην κατεύθυνση στρογγυλοποίησης κατά τη λογιστική των αναλήψεων υπολόγιζε την ενεργή ρευστότητα χαμηλότερη από την πραγματική, και μια μεταγενέστερη ανταλλαγή αποκάλυψε αυτήν την υποεκτίμηση μέσω ενός κερδοφόρου sandwich.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Βασική ιδέα: αν ένα hook υλοποιεί πρόσθετη λογιστική που εξαρτάται από fixed-point math, στρογγυλοποίηση tick και λογική κατωφλίων, ένας attacker μπορεί να διαμορφώσει exact-input swaps που περνούν συγκεκριμένα κατώφλια, ώστε οι αποκλίσεις στρογγυλοποίησης να συσσωρεύονται προς όφελός του. Επαναλαμβάνοντας το μοτίβο και στη συνέχεια αποσύροντας το διογκωμένο υπόλοιπο, πραγματοποιεί κέρδος, συχνά χρηματοδοτούμενος με flash loan.

## Υπόβαθρο: hooks του Uniswap v4 και ροή swap

- Τα hooks είναι contracts τα οποία το PoolManager καλεί σε συγκεκριμένα σημεία του κύκλου ζωής (π.χ. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Τα pools αρχικοποιούνται με ένα PoolKey που περιλαμβάνει το contract του hook. Μια μη μηδενική διεύθυνση hook ενεργοποιεί τα callbacks που έχουν επιλεγεί για αυτό το pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Τα hooks μπορούν να επιστρέφουν **custom deltas** που τροποποιούν τις τελικές μεταβολές υπολοίπου ενός swap ή μιας ενέργειας ρευστότητας (custom accounting). Αυτά τα deltas διακανονίζονται ως καθαρά υπόλοιπα στο τέλος της κλήσης, επομένως κάθε σφάλμα στρογγυλοποίησης μέσα στους υπολογισμούς του hook συσσωρεύεται πριν από τον διακανονισμό.<sup>[[4]](#references)</sup>
- Τα βασικά μαθηματικά χρησιμοποιούν fixed-point formats όπως το Q64.96 για το sqrtPriceX96 και αριθμητική tick με 1.0001^tick. Κάθε custom math που προστίθεται από πάνω πρέπει να αντιστοιχεί προσεκτικά στους κανόνες στρογγυλοποίησης, ώστε να αποφεύγεται η απόκλιση από το invariant.<sup>[[12]](#references)[[13]](#references)</sup>
- Τα swaps μπορούν να είναι exactInput ή exactOutput. Στα v3/v4, η τιμή κινείται κατά μήκος των ticks· η διέλευση ενός ορίου tick μπορεί να ενεργοποιήσει ή να απενεργοποιήσει ρευστότητα εύρους. Τα hooks μπορεί να υλοποιούν πρόσθετη λογική κατά τη διέλευση ορίων/ ticks.<sup>[[9]](#references)[[11]](#references)</sup>

## Τυπική ευπάθεια: απόκλιση ακρίβειας/στρογγυλοποίησης κατά τη διέλευση κατωφλίων

Ένα συνηθισμένο ευάλωτο μοτίβο σε custom hooks:

1. Το hook υπολογίζει μεταβολές ρευστότητας ή υπολοίπων ανά swap χρησιμοποιώντας ακέραια διαίρεση, mulDiv ή μετατροπές fixed-point (π.χ. token ↔ liquidity με χρήση sqrtPrice και εύρους tick).
2. Η λογική κατωφλίων (π.χ. αναπροσαρμογή ισορροπίας, σταδιακή ανακατανομή ή ενεργοποίηση ανά εύρος) ενεργοποιείται όταν το μέγεθος ενός swap ή η μεταβολή της τιμής περνά ένα εσωτερικό όριο.
3. Η στρογγυλοποίηση εφαρμόζεται με ασυνέπεια (π.χ. αποκοπή προς το μηδέν, floor έναντι ceil) μεταξύ του αρχικού υπολογισμού και της διαδικασίας διακανονισμού. Οι μικρές αποκλίσεις δεν αλληλοαναιρούνται, αλλά πιστώνονται στον caller.
4. Swaps exact-input, με ακριβές μέγεθος ώστε να περνούν αυτά τα όρια, αποφέρουν επανειλημμένα το θετικό υπόλοιπο στρογγυλοποίησης. Ο attacker αποσύρει αργότερα την πίστωση που συσσωρεύτηκε.

Προϋποθέσεις επίθεσης
- Ένα pool που χρησιμοποιεί custom v4 hook και εκτελεί πρόσθετους υπολογισμούς σε κάθε swap (π.χ. LDF/rebalancer).
- Τουλάχιστον μία διαδρομή εκτέλεσης στην οποία η στρογγυλοποίηση ωφελεί τον initiator του swap κατά τη διέλευση κατωφλίων.
- Δυνατότητα επανάληψης πολλών swaps ατομικά (τα flash loans είναι ιδανικά για την παροχή προσωρινής ρευστότητας και τον επιμερισμό του gas).

## Πρακτική μεθοδολογία επίθεσης

1) Εντοπισμός υποψήφιων pools με hooks
- Καταγράψτε τα v4 pools και ελέγξτε αν PoolKey.hooks != address(0).
- Εξετάστε το bytecode/ABI του hook για callbacks: beforeSwap/afterSwap και τυχόν μεθόδους custom rebalancing.
- Αναζητήστε μαθηματικούς υπολογισμούς που: διαιρούν με τη ρευστότητα, μετατρέπουν ποσά token σε ρευστότητα ή συγκεντρώνουν BalanceDelta με στρογγυλοποίηση.

2) Μοντελοποίηση των μαθηματικών και των κατωφλίων του hook
- Αναπαραγάγετε τον τύπο ρευστότητας/ανακατανομής του hook: οι είσοδοι συνήθως περιλαμβάνουν sqrtPriceX96, tickLower/Upper, currentTick, fee tier και καθαρή ρευστότητα.
- Χαρτογραφήστε τις συναρτήσεις κατωφλίων/βημάτων: ticks, όρια buckets ή σημεία διακοπής LDF. Καθορίστε προς ποια πλευρά κάθε ορίου γίνεται η στρογγυλοποίηση του delta.
- Εντοπίστε τα σημεία όπου οι μετατροπές κάνουν cast μεταξύ uint256/int256, χρησιμοποιούν SafeCast ή βασίζονται σε mulDiv με implicit floor.

3) Προσαρμογή swaps exact-input για τη διέλευση ορίων
- Χρησιμοποιήστε προσομοιώσεις Foundry/Hardhat για να υπολογίσετε το ελάχιστο Δin που απαιτείται ώστε να μετακινηθεί η τιμή μόλις πέρα από ένα όριο και να ενεργοποιηθεί το σχετικό branch του hook.
- Επιβεβαιώστε ότι ο διακανονισμός afterSwap πιστώνει στον caller περισσότερα από όσα κόστισε, αφήνοντας θετικό BalanceDelta ή πίστωση στη λογιστική του hook.
- Επαναλάβετε τα swaps για να συσσωρεύσετε πίστωση· στη συνέχεια καλέστε τη διαδρομή ανάληψης/διακανονισμού του hook.

Στο v4, ο βρόχος swap πρέπει να εκτελείται από callback ξεκλειδώματος του PoolManager· αρνητικό `amountSpecified` δηλώνει exact input, και το `sqrtPriceLimitX96` πρέπει να βρίσκεται αυστηρά εντός του έγκυρου εύρους. Μηδενικό όριο τιμής προκαλεί revert, γι’ αυτό ο παρακάτω ψευδοκώδικας χρησιμοποιεί το κατώτατο όριο για swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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

Ρύθμιση του exactInput
- Υπολογίστε τον στόχο με το core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) σε όρους πραγματικών τιμών· το αποτέλεσμα Q64.96 στρογγυλοποιείται από το TickMath.<sup>[[13]](#references)</sup>
- Προσεγγίστε την είσοδο token0 (zero-for-one) χρησιμοποιώντας τον τύπο που λαμβάνει υπόψη το Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Ακολουθήστε τη στρογγυλοποίηση ανά κατεύθυνση της core ρουτίνας.<sup>[[12]](#references)</sup>
- Προσαρμόστε το Δin κατά ±1 wei γύρω από το όριο, για να βρείτε τον κλάδο όπου το hook στρογγυλοποιεί υπέρ σας.

4) Ενίσχυση με flash loans
- Δανειστείτε ένα μεγάλο ονομαστικό ποσό (π.χ. 3M USDT ή 2000 WETH) για να εκτελέσετε πολλές επαναλήψεις ατομικά.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Εκτελέστε τον βαθμονομημένο βρόχο swap και, στη συνέχεια, κάντε ανάληψη και αποπληρωμή μέσα στο callback του flash loan.

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

5) Έξοδος και αναπαραγωγή μεταξύ αλυσίδων
- Αν τα hooks έχουν αναπτυχθεί σε πολλές αλυσίδες, επαναλάβετε την ίδια βαθμονόμηση για κάθε αλυσίδα.
- Στο περιστατικό Bunni, η ρευστότητα από flash loan και οι διαδρομές bridge διέφεραν ανά αλυσίδα, επομένως λάβετε υπόψη τους περιορισμούς κάθε αλυσίδας κατά την αναπαραγωγή της ανάλυσης.<sup>[[1]](#references)[[2]](#references)</sup>

## Συνήθεις βασικές αιτίες στα μαθηματικά των hook

- Μικτές σημασιολογίες στρογγυλοποίησης: το mulDiv στρογγυλοποιεί προς τα κάτω, ενώ οι επόμενες διαδρομές ουσιαστικά στρογγυλοποιούν προς τα πάνω· ή οι μετατροπές μεταξύ token και ρευστότητας εφαρμόζουν διαφορετική στρογγυλοποίηση.
- Σφάλματα ευθυγράμμισης tick: χρήση μη στρογγυλοποιημένων tick σε μία διαδρομή και στρογγυλοποίησης βάσει απόστασης tick σε άλλη.
- Προβλήματα προσήμου/υπερχείλισης του BalanceDelta κατά τη μετατροπή μεταξύ int256 και uint256 στη διαδικασία settlement.
- Απώλεια ακρίβειας στις μετατροπές Q64.96 (sqrtPriceX96), η οποία δεν αντισταθμίζεται στην αντίστροφη αντιστοίχιση.
- Διαδρομές συσσώρευσης: τα υπόλοιπα ανά swap καταγράφονται ως πιστώσεις που μπορούν να αναληφθούν από τον caller, αντί να καίγονται ή να διατηρούν μηδενικό καθαρό υπόλοιπο.

## Προσαρμοσμένη λογιστική και ενίσχυση delta

- Η προσαρμοσμένη λογιστική του Uniswap v4 επιτρέπει στα hooks να επιστρέφουν deltas που προσαρμόζουν άμεσα όσα οφείλει ή λαμβάνει ο caller. Αν το hook παρακολουθεί εσωτερικά τις πιστώσεις, τα υπόλοιπα στρογγυλοποίησης μπορούν να συσσωρευτούν σε πολλές μικρές ενέργειες **πριν** γίνει ο τελικός διακανονισμός.<sup>[[4]](#references)</sup>
- Αν το hook εκθέτει συμβατή διαδρομή ανάληψης, ένας attacker μπορεί να εναλλάσσει `swap → withdraw → swap` μέσα στο ίδιο callback ξεκλειδώματος του PoolManager, αναγκάζοντας το hook να επανυπολογίζει τα deltas σε ελαφρώς διαφορετική κατάσταση, ενώ τα υπόλοιπα παραμένουν σε εκκρεμότητα μέχρι τον διακανονισμό του unlock.<sup>[[4]](#references)[[10]](#references)</sup>
- Κατά τον έλεγχο hooks, να ιχνηλατείτε πάντα τον τρόπο παραγωγής και διακανονισμού των BalanceDelta/HookDelta. Μία μεροληπτική στρογγυλοποίηση σε έναν κλάδο μπορεί να μετατραπεί σε πιστωτικό υπόλοιπο που αυξάνεται κάθε φορά που επανυπολογίζονται τα deltas.

## Αμυντικές οδηγίες

- Διαφορικός έλεγχος: συγκρίνετε τα μαθηματικά του hook με μια υλοποίηση αναφοράς που χρησιμοποιεί αριθμητική ρητών αριθμών υψηλής ακρίβειας και επιβεβαιώστε την ισότητα ή ένα φραγμένο σφάλμα που είναι πάντα εις βάρος του attacker (ποτέ υπέρ του caller).
- Έλεγχοι invariant/property:
  - Το άθροισμα των deltas (token, ρευστότητας) στις διαδρομές swap και στις προσαρμογές hook πρέπει να διατηρεί την αξία, με εξαίρεση τα fees.
  - Καμία διαδρομή δεν πρέπει να δημιουργεί θετική καθαρή πίστωση για τον initiator του swap έπειτα από επαναλαμβανόμενες επαναλήψεις exactInput.
  - Έλεγχοι ορίων threshold/tick για εισόδους ±1 wei, τόσο για exactInput όσο και για exactOutput.
- Πολιτική στρογγυλοποίησης: συγκεντρώστε τις βοηθητικές συναρτήσεις στρογγυλοποίησης σε ένα σημείο και φροντίστε να στρογγυλοποιούν πάντα εις βάρος του χρήστη· εξαλείψτε ασυνεπείς casts και σιωπηρές στρογγυλοποιήσεις προς τα κάτω.
- Προορισμοί διακανονισμού: συγκεντρώνετε τα αναπόφευκτα υπόλοιπα στρογγυλοποίησης στο treasury του πρωτοκόλλου ή τα καίτε· ποτέ μην τα αποδίδετε στο msg.sender.
- Όρια/προστατευτικές δικλείδες: ελάχιστα μεγέθη swap για triggers επανεξισορρόπησης· απενεργοποίηση επανεξισορρόπησης αν τα deltas είναι μικρότερα από wei· έλεγχος λογικότητας των deltas σε σχέση με τα αναμενόμενα εύρη.
- Εξετάστε συνολικά τα callbacks του hook: τα beforeSwap/afterSwap και οι before/after αλλαγές ρευστότητας πρέπει να συμφωνούν ως προς την ευθυγράμμιση tick και τη στρογγυλοποίηση delta.

## Μελέτη περίπτωσης: Bunni V2 (2025‑09‑02)

- Πρωτόκολλο: Bunni V2, ένα hook του Uniswap v4 που χρησιμοποιεί Liquidity Density Function (LDF) για τον υπολογισμό της πυκνότητας token και των εκτιμήσεων συνολικής ρευστότητας.<sup>[[1]](#references)[[2]](#references)</sup>
- Επηρεαζόμενα pools: USDC/USDT στο Ethereum και weETH/ETH στο Unichain, συνολικής αξίας περίπου $8.4M.<sup>[[1]](#references)</sup>
- Βήμα 1 (ώθηση τιμής): ο attacker δανείστηκε μέσω flash loan περίπου 3M USDT και έκανε swap για να ωθήσει το tick περίπου στο 5000, μειώνοντας το **ενεργό** υπόλοιπο USDC σε περίπου 28 wei.<sup>[[1]](#references)</sup>
- Βήμα 2 (αποστράγγιση μέσω στρογγυλοποίησης): 44 μικρές αναλήψεις εκμεταλλεύτηκαν τη στρογγυλοποίηση προς τα κάτω στο `BunniHubLogic::withdraw()` για να μειώσουν το ενεργό υπόλοιπο USDC από 28 wei σε 4 wei (-85.7%), ενώ κάηκε μόνο ένα μικρό κλάσμα των μεριδίων LP. Η συνολική ρευστότητα μειώθηκε κατά περίπου 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Βήμα 3 (sandwich με ανάκαμψη ρευστότητας): ένα μεγάλο swap μετέφερε το tick περίπου στο 839,189 (1 USDC ≈ 2.77e36 USDT). Οι εκτιμήσεις ρευστότητας αντιστράφηκαν και αυξήθηκαν κατά περίπου 16.8%, επιτρέποντας ένα sandwich κατά το οποίο ο attacker έκανε swap ξανά στην υπερτιμημένη τιμή και αποχώρησε με κέρδος.<sup>[[1]](#references)</sup>
- Διόρθωση που εντοπίστηκε στην post-mortem ανάλυση: αλλαγή της ενημέρωσης του αδρανούς υπολοίπου ώστε να γίνεται στρογγυλοποίηση **προς τα πάνω**, για να μην μπορούν οι επαναλαμβανόμενες μικροαναλήψεις να μειώνουν σταδιακά το ενεργό υπόλοιπο του pool.<sup>[[1]](#references)</sup>

Απλοποιημένη ευάλωτη γραμμή (και διόρθωση της post-mortem ανάλυσης).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Λίστα ελέγχου διερεύνησης

- Χρησιμοποιεί το pool διεύθυνση hooks διάφορη του μηδενός; Ποια callbacks είναι ενεργοποιημένα;
- Γίνονται αναδιανομές/εξισορροπήσεις ανά swap με προσαρμοσμένα μαθηματικά; Υπάρχει λογική tick/κατωφλίου;
- Πού χρησιμοποιούνται διαιρέσεις/mulDiv, μετατροπές Q64.96 ή SafeCast; Είναι συνεπείς οι κανόνες στρογγυλοποίησης σε όλο το σύστημα;
- Μπορείς να κατασκευάσεις Δin που υπερβαίνει οριακά ένα όριο και ενεργοποιεί ευνοϊκό κλάδο στρογγυλοποίησης; Δοκίμασε και τις δύο κατευθύνσεις, καθώς και exactInput και exactOutput.
- Παρακολουθεί το hook credits ή deltas ανά caller, τα οποία μπορούν να αποσυρθούν αργότερα; Βεβαιώσου ότι το υπόλοιπο εξουδετερώνεται.

## References

- [1] [Απολογισμός μετά το exploit του Bunni (Σεπ. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit του Bunni V2: Πλήρης ανάλυση του hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit του Bunni V2: $8.3M αποστραγγίστηκαν μέσω ελαττώματος ρευστότητας (σύνοψη)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Λευκή βίβλος του Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Υπόβαθρο του Uniswap v4 (έρευνα QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
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
