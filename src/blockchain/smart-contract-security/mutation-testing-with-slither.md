# Mutation Testing για Solidity με Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" εισάγοντας συστηματικά μικρές αλλαγές (mutants) στον κώδικά σας σε Solidity και επανεκτελώντας το test suite σας. Αν ένα test αποτύχει, ο mutant σκοτώνεται. Αν τα tests εξακολουθούν να περνούν, ο mutant επιβιώνει, αποκαλύπτοντας ένα τυφλό σημείο στο test suite σας που η line/branch coverage δεν μπορεί να εντοπίσει.

Κεντρική ιδέα: Η coverage δείχνει ότι ο κώδικας εκτελέστηκε· το mutation testing δείχνει αν η συμπεριφορά πράγματι επιβεβαιώνεται.

## Γιατί η coverage μπορεί να παραπλανήσει

Εξετάστε αυτόν τον απλό έλεγχο κατωφλίου:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Τα unit tests που ελέγχουν μόνο μια τιμή κάτω και μια τιμή πάνω από το όριο μπορούν να φτάσουν στο 100% κάλυψη γραμμών/διακλαδώσεων ενώ αποτυγχάνουν να ελέγξουν το όριο ισότητας (==). Μια αναδιάρθρωση σε `deposit >= 2 ether` θα περνούσε ακόμα τέτοια tests, σιωπηρά σπάζοντας τη λογική του πρωτοκόλλου.

Mutation testing αποκαλύπτει αυτό το κενό μεταλλάσσοντας τη συνθήκη και επαληθεύοντας ότι τα tests σας αποτυγχάνουν.

## Common Solidity mutation operators

Slither’s mutation engine εφαρμόζει πολλές μικρές, που αλλάζουν τη σημασιολογία, τροποποιήσεις, όπως:
- Αντικατάσταση τελεστή: `+` ↔ `-`, `*` ↔ `/`, κ.λπ.
- Αντικατάσταση ανάθεσης: `+=` → `=`, `-=` → `=`
- Αντικατάσταση σταθεράς: μη μηδενικό → 0, `true` ↔ `false`
- Άρνηση/αντικατάσταση συνθήκης εντός `if`/βρόχων
- Μετατροπή ολόκληρων γραμμών σε σχόλια (CR: Comment Replacement)
- Αντικατάσταση μιας γραμμής με `revert()`
- Ανταλλαγές τύπου δεδομένων: π.χ. `int128` → `int64`

Goal: Kill 100% of generated mutants, or justify survivors with clear reasoning.

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- Εμφάνιση επιλογών και mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry παράδειγμα (καταγράψτε τα αποτελέσματα και κρατήστε πλήρες αρχείο καταγραφής):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Αν δεν χρησιμοποιείτε Foundry, αντικαταστήστε το `--test-cmd` με τον τρόπο που τρέχετε τα tests (π.χ. `npx hardhat test`, `npm test`).

Τα artifacts και οι αναφορές αποθηκεύονται στο `./mutation_campaign` από προεπιλογή. Οι μη εντοπισμένοι (επιζώντες) mutants αντιγράφονται εκεί για έλεγχο.

### Κατανόηση της εξόδου

Οι γραμμές της αναφοράς μοιάζουν ως εξής:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Το tag σε αγκύλες είναι το alias του mutator (π.χ., `CR` = Comment Replacement).
- Το `UNCAUGHT` σημαίνει ότι οι δοκιμές πέρασαν υπό τη μεταλλαγμένη συμπεριφορά → λείπει assertion.

## Μείωση χρόνου εκτέλεσης: προτεραιοποίηση σημαντικών mutants

Mutation campaigns μπορεί να διαρκέσουν ώρες ή ημέρες. Συμβουλές για μείωση κόστους:
- Scope: Ξεκινήστε μόνο με κρίσιμα contracts/καταλόγους, μετά επεκταθείτε.
- Προτεραιοποιήστε mutators: Αν ένας high-priority mutant σε μια γραμμή επιβιώσει (π.χ., ολόκληρη γραμμή σχολιασμένη), μπορείτε να παραλείψετε παραλλαγές χαμηλότερης προτεραιότητας για εκείνη τη γραμμή.
- Παράλληλες δοκιμές αν ο runner σας το επιτρέπει; cache dependencies/builds.
- Fail-fast: σταματήστε νωρίς όταν μια αλλαγή δείχνει σαφώς κενό assertion.

## Ροή εργασίας triage για τους επιζώντες mutants

1) Εξετάστε τη μεταλλαγμένη γραμμή και τη συμπεριφορά.
- Αναπαράγετε το τοπικά εφαρμόζοντας τη μεταλλαγμένη γραμμή και τρέχοντας ένα στοχευμένο test.

2) Ενισχύστε τα tests ώστε να assert-άρουν την κατάσταση, όχι μόνο τις τιμές επιστροφής.
- Προσθέστε equality-boundary checks (π.χ., test threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects, και emitted events.

3) Αντικαταστήστε υπερβολικά επιεικείς mocks με ρεαλιστική συμπεριφορά.
- Βεβαιωθείτε ότι τα mocks επιβάλλουν transfers, failure paths, και event emissions που συμβαίνουν on-chain.

4) Προσθέστε invariants για fuzz tests.
- Π.χ., conservation of value, μη αρνητικά balances, authorization invariants, μονοτονική supply όπου εφαρμόζεται.

5) Τρέξτε ξανά slither-mutate μέχρι οι επιζώντες να εξαλειφθούν ή να δικαιολογηθούν ρητά.

## Μελέτη περίπτωσης: αποκάλυψη ελλείπων assertions κατάστασης (Arkis protocol)

Μια mutation campaign κατά τη διάρκεια ενός audit του Arkis DeFi protocol ανέδειξε επιζώντες όπως:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Ο σχολιασμός της ανάθεσης δεν έσπασε τα tests, αποδεικνύοντας την έλλειψη post-state assertions. Βασική αιτία: ο κώδικας εμπιστεύτηκε μια από τον χρήστη ελεγχόμενη `_cmd.value` αντί να επικυρώνει τις πραγματικές μεταφορές token. An attacker could desynchronize expected vs. actual transfers to drain funds. Αποτέλεσμα: κίνδυνος υψηλής σοβαρότητας για τη φερεγγυότητα του πρωτοκόλλου.

Οδηγίες: Θεωρείτε τους survivors που επηρεάζουν μεταφορές αξίας, λογιστική ή access control ως υψηλού ρίσκου μέχρι να εξουδετερωθούν.

## Πρακτική λίστα ελέγχου

- Εκτελέστε μια στοχευμένη εκστρατεία:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Κατηγοριοποιήστε τους επιζώντες και γράψτε tests/invariants που θα απέτυχαν υπό τη μεταλλαγμένη συμπεριφορά.
- Επιβεβαιώστε τα υπόλοιπα, το supply, τις εξουσιοδοτήσεις και τα events.
- Προσθέστε boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Αντικαταστήστε μη ρεαλιστικά mocks· προσομοιώστε σενάρια αποτυχίας.
- Επαναλάβετε μέχρι όλοι οι mutants να εξουδετερωθούν ή να δικαιολογηθούν με σχόλια και αιτιολόγηση.

## Αναφορές

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
