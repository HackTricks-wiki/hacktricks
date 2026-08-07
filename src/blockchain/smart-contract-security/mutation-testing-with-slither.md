# Mutation Testing για Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Το Mutation Testing «δοκιμάζει τα tests σας» εισάγοντας συστηματικά μικρές αλλαγές (mutants) στον κώδικα του contract και εκτελώντας ξανά τη σουίτα tests. Αν ένα test αποτύχει, ο mutant εξουδετερώνεται. Αν τα tests εξακολουθούν να περνούν, ο mutant επιβιώνει, αποκαλύπτοντας ένα blind spot που δεν μπορεί να εντοπίσει το line/branch coverage.

Βασική ιδέα: Το coverage δείχνει ότι ο κώδικας εκτελέστηκε· το mutation testing δείχνει αν η συμπεριφορά ελέγχεται πραγματικά από assertions.<sup>[[2]](#references)</sup>

## Γιατί το coverage μπορεί να είναι παραπλανητικό

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
Unit tests που ελέγχουν μόνο μια τιμή κάτω και μια τιμή πάνω από το threshold μπορούν να φτάσουν σε 100% line/branch coverage, ενώ αποτυγχάνουν να ελέγξουν το όριο ισότητας (==). Ένα refactor σε `deposit >= 2 ether` θα περνούσε και πάλι από αυτά τα tests, παραβιάζοντας σιωπηρά τη λογική του protocol.<sup>[[2]](#references)</sup>

Το Mutation testing αποκαλύπτει αυτό το κενό, μεταλλάσσοντας τη συνθήκη και επαληθεύοντας ότι τα tests αποτυγχάνουν.

Για τα smart contracts, οι mutants που επιβιώνουν συχνά αντιστοιχούν σε ελλιπείς ελέγχους γύρω από:
- Όρια Authorization και ρόλων
- Invariants λογιστικής και μεταφοράς value
- Συνθήκες revert και failure paths
- Συνθήκες ορίων (`==`, μηδενικές τιμές, κενά arrays, μέγιστες/ελάχιστες τιμές)

## Mutation operators με το υψηλότερο security signal

Χρήσιμες κατηγορίες mutations για contract auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **Υψηλή σοβαρότητα**: αντικατάσταση statements με `revert()` για την αποκάλυψη paths που δεν εκτελούνται
- **Μεσαία σοβαρότητα**: σχολιασμός γραμμών / αφαίρεση logic για την αποκάλυψη μη επαληθευμένων side effects
- **Χαμηλή σοβαρότητα**: ανεπαίσθητες αντικαταστάσεις operators ή constants, όπως `>=` -> `>` ή `+` -> `-`
- Άλλες συνηθισμένες αλλαγές: αντικατάσταση assignments, αντιστροφές boolean, άρνηση συνθηκών και αλλαγές τύπων

Πρακτικός στόχος: να εξουδετερωθούν όλοι οι meaningful mutants και να αιτιολογηθούν ρητά όσοι επιβιώνουν, όταν είναι άσχετοι ή σημασιολογικά ισοδύναμοι.

## Γιατί το syntax-aware mutation είναι καλύτερο από το regex

Οι παλαιότεροι mutation engines βασίζονταν σε regex ή σε line-oriented rewrites. Αυτό λειτουργεί, αλλά έχει σημαντικούς περιορισμούς:<sup>[[1]](#references)</sup>
- Οι multi-line statements είναι δύσκολο να μεταλλαχθούν με ασφάλεια
- Δεν γίνεται κατανοητή η δομή της γλώσσας, επομένως τα comments/tokens μπορεί να στοχευτούν λανθασμένα
- Η δημιουργία κάθε πιθανού variant σε ένα αδύναμο line σπαταλά μεγάλες ποσότητες runtime

Τα εργαλεία που βασίζονται σε AST ή Tree-sitter το βελτιώνουν αυτό, στοχεύοντας structured nodes αντί για raw lines:<sup>[[1]](#references)</sup>
- **slither-mutate** χρησιμοποιεί το Solidity AST του Slither
- **mewt** χρησιμοποιεί το Tree-sitter ως language-agnostic core
- Το **MuTON** βασίζεται στο `mewt` και προσθέτει first-class support για TON languages όπως οι FunC, Tolk και Tact

Έτσι, τα multi-line constructs και τα expression-level mutations γίνονται πολύ πιο αξιόπιστα από τις προσεγγίσεις που βασίζονται αποκλειστικά σε regex.

## Εκτέλεση mutation testing με slither-mutate

Απαιτήσεις: Slither v0.10.2+.

- Λίστα options και mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Παράδειγμα Foundry (καταγραφή αποτελεσμάτων και διατήρηση πλήρους log):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Αν δεν χρησιμοποιείτε Foundry, αντικαταστήστε το `--test-cmd` με τον τρόπο που εκτελείτε τα tests (π.χ. `npx hardhat test`, `npm test`).

Τα artifacts αποθηκεύονται από προεπιλογή στο `./mutation_campaign`. Οι μη εντοπισμένοι (surviving) mutants αντιγράφονται εκεί για επιθεώρηση.<sup>[[5]](#references)</sup>

### Κατανόηση του output

Οι γραμμές της αναφοράς έχουν την εξής μορφή:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Το tag σε αγκύλες είναι το alias του mutator (π.χ. `CR` = Comment Replacement).
- Το `UNCAUGHT` σημαίνει ότι τα tests πέρασαν με τη mutated συμπεριφορά → λείπει assertion.

## Μείωση του runtime: δώστε προτεραιότητα στους πιο σημαντικούς mutants

Οι mutation campaigns μπορεί να διαρκέσουν ώρες ή ημέρες. Συμβουλές για τη μείωση του κόστους:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: Ξεκινήστε μόνο με critical contracts/directories και, στη συνέχεια, επεκταθείτε.
- Δώστε προτεραιότητα στους mutators: Αν ένας high-priority mutant σε μια γραμμή επιβιώσει (για παράδειγμα `revert()` ή comment-out), παραλείψτε τις παραλλαγές χαμηλότερης προτεραιότητας για τη συγκεκριμένη γραμμή.
- Χρησιμοποιήστε campaigns δύο φάσεων: εκτελέστε πρώτα focused/fast tests και, στη συνέχεια, επαναλάβετε τα tests μόνο για τους uncaught mutants με ολόκληρο το suite.
- Αντιστοιχίστε τους mutation targets σε συγκεκριμένες εντολές test όπου είναι δυνατό (για παράδειγμα auth code -> auth tests).
- Περιορίστε τις campaigns σε mutants με high/medium severity όταν ο χρόνος είναι περιορισμένος.
- Εκτελέστε τα tests παράλληλα αν το runner σας το επιτρέπει· κάντε cache τα dependencies/builds.
- Fail-fast: σταματήστε νωρίς όταν μια αλλαγή αποδεικνύει ξεκάθαρα ένα assertion gap.

Τα μαθηματικά του runtime είναι αμείλικτα: `1000 mutants x 5-minute tests ~= 83 hours`, επομένως ο σχεδιασμός της campaign είναι εξίσου σημαντικός με τον ίδιο τον mutator.

## Persistent campaigns και triage σε μεγάλη κλίμακα

Μία αδυναμία παλαιότερων workflows είναι η αποθήκευση των αποτελεσμάτων μόνο στο `stdout`. Για μακροχρόνιες campaigns, αυτό δυσκολεύει το pause/resume, το filtering και το review.<sup>[[1]](#references)</sup>

Τα `mewt`/`MuTON` το βελτιώνουν αποθηκεύοντας τους mutants και τα outcomes σε campaigns που βασίζονται σε SQLite. Οφέλη:<sup>[[1]](#references)</sup>
- Pause και resume μακροχρόνιων runs χωρίς απώλεια προόδου
- Filter μόνο των uncaught mutants σε συγκεκριμένο file ή mutation class
- Export/translate των αποτελεσμάτων σε SARIF για review tooling
- Παροχή μικρότερων, φιλτραρισμένων result sets για AI-assisted triage, αντί για raw terminal logs

Τα persistent results είναι ιδιαίτερα χρήσιμα όταν το mutation testing γίνεται μέρος ενός audit pipeline αντί για ένα one-off manual review.

## Triage workflow για surviving mutants

1) Επιθεωρήστε τη mutated γραμμή και συμπεριφορά.
- Κάντε reproduce locally εφαρμόζοντας τη mutated γραμμή και εκτελώντας ένα focused test.

2) Ενισχύστε τα tests ώστε να κάνουν assert το state και όχι μόνο τις return values.
- Προσθέστε equality-boundary checks (π.χ. test threshold `==`).
- Κάντε assert τα post-conditions: balances, total supply, authorization effects και emitted events.

3) Αντικαταστήστε τα υπερβολικά permissive mocks με ρεαλιστική συμπεριφορά.
- Βεβαιωθείτε ότι τα mocks επιβάλλουν transfers, failure paths και event emissions που συμβαίνουν on-chain.

4) Προσθέστε invariants για fuzz tests.
- Π.χ. conservation of value, non-negative balances, authorization invariants και monotonic supply όπου εφαρμόζεται.

5) Διαχωρίστε τα true positives από τα semantic no-ops.
- Παράδειγμα: `x > 0` -> `x != 0` δεν έχει νόημα όταν το `x` είναι unsigned.

6) Εκτελέστε ξανά την campaign μέχρι οι survivors να killed ή να αιτιολογηθούν ρητά.

## Case study: αποκάλυψη missing state assertions (Arkis protocol)

Μια mutation campaign κατά τη διάρκεια audit του Arkis DeFi protocol αποκάλυψε survivors όπως:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Το σχολιασμό της ανάθεσης δεν διέκοψε τα tests, αποδεικνύοντας την απουσία assertions για το post-state. Βασική αιτία: ο κώδικας εμπιστευόταν ένα user-controlled `_cmd.value` αντί να επικυρώνει τις πραγματικές μεταφορές token. Ένας attacker θα μπορούσε να αποσυγχρονίσει τις αναμενόμενες από τις πραγματικές μεταφορές, ώστε να κάνει drain κεφάλαια. Αποτέλεσμα: κίνδυνος high severity για τη solvency του protocol.<sup>[[2]](#references)[[3]](#references)</sup>

Οδηγία: Θεωρείτε τους survivors που επηρεάζουν μεταφορές αξίας, accounting ή access control ως high-risk μέχρι να εξουδετερωθούν.

## Μην δημιουργείτε tests χωρίς σκέψη για να εξουδετερώσετε κάθε mutant

Η δημιουργία tests με βάση mutation μπορεί να έχει αντίθετα αποτελέσματα, αν η τρέχουσα υλοποίηση είναι λανθασμένη. Παράδειγμα: η μετάλλαξη του `priority >= 2` σε `priority > 2` αλλάζει τη συμπεριφορά, όμως η σωστή διόρθωση δεν είναι πάντα «γράψτε ένα test για `priority == 2`». Η ίδια η συμπεριφορά μπορεί να αποτελεί το bug.<sup>[[1]](#references)</sup>

Ασφαλέστερο workflow:
- Χρησιμοποιήστε τους surviving mutants για να εντοπίσετε ασαφείς απαιτήσεις
- Επικυρώστε την αναμενόμενη συμπεριφορά από τα specs, τα protocol docs ή τους reviewers
- Μόνο τότε κωδικοποιήστε τη συμπεριφορά ως test/invariant

Διαφορετικά, κινδυνεύετε να ενσωματώσετε στο test suite τυχαίες λεπτομέρειες της υλοποίησης και να αποκτήσετε false confidence.

## Πρακτικό checklist

- Εκτελέστε μια στοχευμένη campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Προτιμήστε syntax-aware mutators (AST/Tree-sitter) αντί για mutation που βασίζεται αποκλειστικά σε regex, όταν είναι διαθέσιμοι.
- Κάντε triage στους survivors και γράψτε tests/invariants που θα αποτύγχαναν υπό τη mutated συμπεριφορά.
- Κάντε assertions για balances, supply, authorizations και events.
- Προσθέστε boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Αντικαταστήστε τα μη ρεαλιστικά mocks και προσομοιώστε failure modes.
- Αποθηκεύστε τα αποτελέσματα όταν το tooling το υποστηρίζει και φιλτράρετε τους uncaught mutants πριν από το triage.
- Χρησιμοποιήστε campaigns δύο φάσεων ή ανά target, ώστε να διατηρείται διαχειρίσιμος ο χρόνος εκτέλεσης.
- Επαναλάβετε έως ότου όλοι οι mutants εξουδετερωθούν ή τεκμηριωθούν με σχόλια και rationale.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
