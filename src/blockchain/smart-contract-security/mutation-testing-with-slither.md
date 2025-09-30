# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

Mutation testing "δοκιμάζει τα tests σου" εισάγοντας συστηματικά μικρές αλλαγές (mutants) στον κώδικα Solidity σου και επανεκτελώντας το test suite σου. Αν ένα test αποτύχει, το mutant "πεθαίνει". Αν τα tests συνεχίσουν να περνούν, το mutant επιβιώνει, αποκαλύπτοντας ένα τυφλό σημείο στο test suite σου που το line/branch coverage δεν μπορεί να εντοπίσει.

Βασική ιδέα: Η κάλυψη δείχνει ότι ο κώδικας εκτελέστηκε· το Mutation testing δείχνει αν η συμπεριφορά έχει πραγματικά επιβεβαιωθεί.

## Why coverage can deceive

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
Τα unit tests που μόνο ελέγχουν μια τιμή κάτω και μια τιμή πάνω από το όριο μπορούν να φτάσουν 100% κάλυψη γραμμών/κλάδων ενώ αποτυγχάνουν να ελέγξουν το σύνορο ισότητας (==). Μια αλλαγή σε `deposit >= 2 ether` θα περνούσε ακόμα τέτοια tests, σιωπηρά σπάζοντας τη λογική του πρωτοκόλλου.

Το mutation testing αποκαλύπτει αυτό το κενό μεταλλάσσοντας τη συνθήκη και επαληθεύοντας ότι τα tests σας αποτυγχάνουν.

## Common Solidity mutation operators

Η mutation engine του Slither εφαρμόζει πολλές μικρές τροποποιήσεις που αλλάζουν τη σημασιολογία, όπως:
- Αντικατάσταση τελεστή: `+` ↔ `-`, `*` ↔ `/`, etc.
- Αντικατάσταση ανάθεσης: `+=` → `=`, `-=` → `=`
- Αντικατάσταση σταθερών: non-zero → `0`, `true` ↔ `false`
- Άρνηση/αντικατάσταση συνθήκης μέσα σε `if`/βρόχους
- Σχολιασμός ολόκληρων γραμμών (CR: Comment Replacement)
- Αντικατάσταση μιας γραμμής με `revert()`
- Ανταλλαγή τύπων δεδομένων: π.χ. `int128` → `int64`

Στόχος: Να εξουδετερωθεί το 100% των παραγόμενων mutants, ή να δικαιολογηθούν οι επιζώντες με σαφή αιτιολόγηση.

## Running mutation testing with slither-mutate

Απαιτήσεις: Slither v0.10.2+.

- Εμφάνιση επιλογών και mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry παράδειγμα (καταγράψτε τα αποτελέσματα και κρατήστε πλήρες αρχείο καταγραφής):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Αν δεν χρησιμοποιείτε Foundry, αντικαταστήστε το `--test-cmd` με τον τρόπο που τρέχετε τα tests (π.χ., `npx hardhat test`, `npm test`).

Τα αρχεία και οι αναφορές αποθηκεύονται στο `./mutation_campaign` από προεπιλογή. Οι μη ανιχνευθέντες (επιζώντες) mutants αντιγράφονται εκεί για επιθεώρηση.

### Κατανόηση της εξόδου

Οι γραμμές της αναφοράς μοιάζουν με:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Η ετικέτα σε αγκύλες είναι το mutator alias (π.χ., `CR` = Comment Replacement).
- `UNCAUGHT` σημαίνει ότι τα tests πέρασαν υπό τη μεταβλημένη συμπεριφορά → λείπει assertion.

## Μείωση χρόνου εκτέλεσης: προτεραιοποίηση σημαντικών mutants

Mutation campaigns μπορεί να διαρκέσουν ώρες ή μέρες. Συμβουλές για μείωση κόστους:
- Scope: Ξεκινήστε μόνο με κρίσιμα contracts/directories, και μετά επεκταθείτε.
- Prioritize mutators: Αν ένας high-priority mutant σε μια γραμμή επιβιώσει (π.χ., ολόκληρη γραμμή σχολιασμένη), μπορείτε να παραλείψετε lower-priority παραλλαγές για εκείνη τη γραμμή.
- Parallelize tests αν ο runner σας το επιτρέπει; cache dependencies/builds.
- Fail-fast: σταματήστε νωρίς όταν μια αλλαγή δείχνει σαφώς έλλειμμα σε assertions.

## Διαδικασία triage για τους επιζώντες mutants

1) Εξετάστε τη μεταβλημένη γραμμή και τη συμπεριφορά.
- Αναπαράγετε το τοπικά εφαρμόζοντας τη μεταβλημένη γραμμή και τρέχοντας ένα focused test.

2) Ενισχύστε τα tests ώστε να assert-άρουν την κατάσταση, όχι μόνο τιμές επιστροφής.
- Προσθέστε ελέγχους ισότητας/ορίων (π.χ., test threshold `==`).
- Assert post-conditions: υπόλοιπα, συνολική προσφορά, επιπτώσεις εξουσιοδότησης, και εκπεμπόμενα events.

3) Αντικαταστήστε υπερβολικά επιεικείς mocks με ρεαλιστική συμπεριφορά.
- Διασφαλίστε ότι τα mocks επιβάλλουν transfers, failure paths και event emissions που συμβαίνουν on-chain.

4) Προσθέστε invariants για fuzz tests.
- Π.χ., διατήρηση αξίας, μη-αρνητικά υπόλοιπα, invariants εξουσιοδότησης, και μονοτονική προσφορά όπου εφαρμόζεται.

5) Εκτελέστε ξανά slither-mutate μέχρι οι επιζώντες να εξουδετερωθούν ή να δικαιολογηθούν ρητά.

## Μελέτη περίπτωσης: αποκάλυψη ελλείψεων σε assertions κατάστασης (Arkis protocol)

Μια mutation campaign κατά τη διάρκεια ενός audit του Arkis DeFi protocol ανέδειξε επιζώντες όπως:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Το σχολιασμός της ανάθεσης δεν έσπασε τα tests, αποδεικνύοντας την απουσία post-state assertions. Κύρια αιτία: ο κώδικας εμπιστεύτηκε μια τιμή ελεγχόμενη από χρήστη `_cmd.value` αντί να επαληθεύσει τις πραγματικές μεταφορές token. Ένας επιτιθέμενος θα μπορούσε να αποσυντονίσει τις αναμενόμενες από τις πραγματικές μεταφορές και να στραγγίξει κεφάλαια. Αποτέλεσμα: κίνδυνος υψηλής σοβαρότητας για τη φερεγγυότητα του πρωτοκόλλου.

Κατευθυντήρια: Θεωρήστε τους επιζώντες που επηρεάζουν μεταφορές αξίας, λογιστική ή έλεγχο πρόσβασης ως υψηλού κινδύνου μέχρι να εξουδετερωθούν.

## Πρακτικός κατάλογος ελέγχου

- Run a targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Κατηγοριοποιήστε τους επιζώντες και γράψτε tests/invariants που θα αποτύχουν υπό τη μεταλλαγμένη συμπεριφορά.
- Επαληθεύστε υπόλοιπα, συνολική προσφορά, εξουσιοδοτήσεις και συμβάντα.
- Προσθέστε boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Αντικαταστήστε μη ρεαλιστικά mocks· προσομοιώστε failure modes.
- Επαναλάβετε μέχρι όλοι οι mutants να εξουδετερωθούν ή να δικαιολογηθούν με σχόλια και αιτιολόγηση.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
