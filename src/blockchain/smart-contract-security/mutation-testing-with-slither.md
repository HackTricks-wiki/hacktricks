# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Το mutation testing "tests your tests" εισάγει συστηματικά μικρές αλλαγές (mutants) στον κώδικα Solidity και επανεκτελεί το test suite. Αν κάποιο test αποτύχει, ο mutant σκοτώνεται. Αν τα tests συνεχίσουν να περνούν, ο mutant επιβιώνει, αποκαλύπτοντας ένα τυφλό σημείο στο test suite σου που η κάλυψη γραμμής/διακλάδωσης δεν μπορεί να ανιχνεύσει.

Key idea: Η κάλυψη δείχνει ότι ο κώδικας εκτελέστηκε· το mutation testing δείχνει αν η συμπεριφορά όντως επαληθεύεται.

## Γιατί η κάλυψη μπορεί να παραπλανήσει

Εξετάστε αυτόν τον απλό έλεγχο ορίου:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Τα unit tests που ελέγχουν μόνο μια τιμή κάτω και μια τιμή πάνω από το όριο μπορούν να πετύχουν 100% κάλυψη γραμμής/κλάδου ενώ αποτυγχάνουν να επαληθεύσουν το σύνορο ισότητας (==). Η αλλαγή σε `deposit >= 2 ether` θα περνούσε επίσης τέτοια tests, σιωπηλά σπάζοντας τη λογική του πρωτοκόλλου.

Το mutation testing αποκαλύπτει αυτό το κενό μεταλλάσσοντας τη συνθήκη και επαληθεύοντας ότι τα tests αποτυγχάνουν.

## Συνηθισμένοι mutation operators της Solidity

Ο μηχανισμός mutation του Slither εφαρμόζει πολλές μικρές τροποποιήσεις που αλλάζουν τη σημασιολογία, όπως:
- Αντικατάσταση τελεστών: `+` ↔ `-`, `*` ↔ `/`, κ.λπ.
- Αντικατάσταση ανάθεσης: `+=` → `=`, `-=` → `=`
- Αντικατάσταση σταθερών: μη-μηδενικό → `0`, `true` ↔ `false`
- Άρνηση/αντικατάσταση συνθήκης μέσα σε `if`/βρόχους
- Σχολιασμός ολόκληρων γραμμών (CR: Comment Replacement)
- Αντικατάσταση μιας γραμμής με `revert()`
- Ανταλλαγή τύπων δεδομένων: π.χ. `int128` → `int64`

Στόχος: Να εξαλειφθούν το 100% των παραγόμενων mutants, ή να δικαιολογηθούν οι επιζώντες με σαφή αιτιολόγηση.

## Εκτέλεση mutation testing με slither-mutate

Απαιτήσεις: Slither v0.10.2+.

- Καταγραφή επιλογών και mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry παράδειγμα (καταγραφή αποτελεσμάτων και διατήρηση πλήρους αρχείου):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Αν δεν χρησιμοποιείτε Foundry, αντικαταστήστε το `--test-cmd` με τον τρόπο που τρέχετε τα tests (π.χ., `npx hardhat test`, `npm test`).

Τα artifacts και οι αναφορές αποθηκεύονται στο `./mutation_campaign` από προεπιλογή. Οι μη εξουδετερωμένοι (επιζώντες) mutants αντιγράφονται εκεί για επιθεώρηση.

### Understanding the output

Οι γραμμές της αναφοράς μοιάζουν με:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Το tag σε αγκύλες είναι το ψευδώνυμο του mutator (π.χ., `CR` = Comment Replacement).
- `UNCAUGHT` σημαίνει ότι τα tests πέρασαν υπό τη μεταλλαγμένη συμπεριφορά → έλλειψη assertion.

## Μείωση χρόνου εκτέλεσης: προτεραιοποιήστε τις πιο επιδραστικές μεταλλάξεις

Οι εκστρατείες μεταλλάξεων μπορεί να διαρκέσουν ώρες ή ημέρες. Συμβουλές για μείωση κόστους:
- Scope: Ξεκινήστε μόνο με κρίσιμα contracts/directories, μετά επεκταθείτε.
- Προτεραιοποιήστε mutators: Αν ένας high-priority mutant σε μια γραμμή επιβιώσει (π.χ., ολόκληρη γραμμή σχολιασμένη), μπορείτε να παραλείψετε παραλλαγές χαμηλότερης προτεραιότητας για εκείνη τη γραμμή.
- Παράλληλη εκτέλεση tests αν ο runner σας το επιτρέπει· cache dependencies/builds.
- Fail-fast: σταματήστε νωρίς όταν μια αλλαγή επιδεικνύει ξεκάθαρα κενό assertions.

## Ροή αξιολόγησης για επιζώντες mutants

1) Εξετάστε τη μεταλλαγμένη γραμμή και τη συμπεριφορά.
- Αναπαραγάγετε τοπικά εφαρμόζοντας τη μεταλλαγμένη γραμμή και τρέχοντας ένα στοχευμένο test.

2) Ενισχύστε τα tests ώστε να ελέγχουν κατάσταση, όχι μόνο τιμές επιστροφής.
- Προσθέστε ελέγχους ορίων ισότητας (π.χ., test threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects, και emitted events.

3) Αντικαταστήστε υπερβολικά επιεικείς mocks με ρεαλιστική συμπεριφορά.
- Βεβαιωθείτε ότι τα mocks επιβάλλουν transfers, failure paths, και event emissions που συμβαίνουν on-chain.

4) Προσθέστε invariants για fuzz tests.
- Π.χ., conservation of value, μη αρνητικά balances, authorization invariants, monotonic supply όπου εφαρμόζεται.

5) Ξανατρέξτε slither-mutate μέχρι οι επιζήσαντες να εξουδετερωθούν ή να δικαιολογηθούν ρητά.

## Μελέτη περίπτωσης: αποκάλυψη ελλειπόντων assertions κατάστασης (πρωτόκολλο Arkis)

Μια εκστρατεία μεταλλάξεων κατά τη διάρκεια ενός audit του πρωτοκόλλου Arkis DeFi ανέδειξε επιζήσαντες όπως:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Το σχολιασμό της ανάθεσης δεν προκάλεσε αποτυχία στα tests, αποδεικνύοντας την απουσία επιβεβαιώσεων μετά-κατάστασης. Βασική αιτία: ο κώδικας εμπιστευόταν ένα χειρισμένο από τον χρήστη `_cmd.value` αντί να επικυρώνει τις πραγματικές μεταφορές token. Ένας επιτιθέμενος θα μπορούσε να αποσυντονίσει τις αναμενόμενες έναντι των πραγματικών μεταφορών για να στραγγίξει κεφάλαια. Αποτέλεσμα: υψηλής σοβαρότητας κίνδυνος για τη φερεγγυότητα του πρωτοκόλλου.

Κατευθυντήριες οδηγίες: Θεωρήστε ως υψηλού κινδύνου τους επιζώντες που επηρεάζουν μεταφορές αξίας, λογιστική ή έλεγχο πρόσβασης μέχρι να εξουδετερωθούν.

## Πρακτικός κατάλογος ελέγχου

- Εκτελέστε μια στοχευμένη εκστρατεία:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Κάντε ταξινόμηση (triage) των επιζώντων και γράψτε tests/invariants που θα απέτυχαν υπό τη μεταλλαγμένη συμπεριφορά.
- Επαληθεύστε υπόλοιπα, συνολική προσφορά, εξουσιοδοτήσεις και γεγονότα.
- Προσθέστε δοκιμές ορίων (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Αντικαταστήστε μη ρεαλιστικά mocks· προσομοιώστε σενάρια αποτυχίας.
- Επαναλάβετε μέχρι όλες οι μεταλλάξεις να εξαλειφθούν ή να δικαιολογηθούν με σχόλια και αιτιολόγηση.

## Αναφορές

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
