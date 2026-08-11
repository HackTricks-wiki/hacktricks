# Mutation Testing για Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Το Mutation testing «δοκιμάζει τα tests σας» εισάγοντας συστηματικά μικρές αλλαγές (mutants) στον κώδικα του contract και εκτελώντας ξανά τη test suite. Αν ένα test αποτύχει, το mutant σκοτώνεται. Αν τα tests συνεχίσουν να περνούν, το mutant επιβιώνει, αποκαλύπτοντας ένα blind spot που το line/branch coverage δεν μπορεί να εντοπίσει.

Βασική ιδέα: Το coverage δείχνει ότι ο κώδικας εκτελέστηκε· το mutation testing δείχνει αν η συμπεριφορά ελέγχεται πράγματι από assertions.<sup>[[2]](#references)</sup>

## Γιατί το coverage μπορεί να παραπλανήσει

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
Τα unit tests που ελέγχουν μόνο μια τιμή κάτω και μια τιμή πάνω από το όριο μπορούν να φτάσουν σε 100% line/branch coverage, χωρίς να ελέγχουν το όριο ισότητας (`==`). Ένα refactor σε `deposit >= 2 ether` θα περνούσε και πάλι αυτά τα tests, παραβιάζοντας σιωπηρά τη λογική του protocol.<sup>[[2]](#references)</sup>

Το mutation testing αποκαλύπτει αυτό το κενό, μεταλλάσσοντας τη συνθήκη και επαληθεύοντας ότι τα tests αποτυγχάνουν.

Για τα smart contracts, οι μεταλλάξεις που επιβιώνουν συχνά αντιστοιχούν σε ελλείποντες ελέγχους γύρω από:
- Authorization και όρια ρόλων
- Accounting/value-transfer invariants
- Συνθήκες revert και failure paths
- Συνθήκες ορίων (`==`, μηδενικές τιμές, κενά arrays, μέγιστες/ελάχιστες τιμές)

## Mutation operators με το υψηλότερο security signal

Χρήσιμες κατηγορίες μεταλλάξεων για contract auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **Υψηλή σοβαρότητα**: αντικατάσταση statements με `revert()` για την αποκάλυψη paths που δεν εκτελούνται
- **Μεσαία σοβαρότητα**: σχολιασμός γραμμών / αφαίρεση logic για την αποκάλυψη μη επαληθευμένων side effects
- **Χαμηλή σοβαρότητα**: subtle operator ή constant swaps, όπως `>=` -> `>` ή `+` -> `-`
- Άλλες συνηθισμένες τροποποιήσεις: αντικατάσταση assignments, boolean flips, άρνηση συνθηκών και αλλαγές τύπων

Πρακτικός στόχος: να εξουδετερωθούν όλες οι ουσιαστικές μεταλλάξεις και να αιτιολογηθούν ρητά όσες επιβιώνουν επειδή είναι άσχετες ή σημασιολογικά ισοδύναμες.

## Γιατί το syntax-aware mutation είναι καλύτερο από το regex

Οι παλαιότεροι mutation engines βασίζονταν σε regex ή σε line-oriented rewrites. Αυτό λειτουργεί, αλλά έχει σημαντικούς περιορισμούς:<sup>[[1]](#references)</sup>
- Οι δηλώσεις πολλών γραμμών είναι δύσκολο να μεταλλαχθούν με ασφάλεια
- Η δομή της γλώσσας δεν γίνεται κατανοητή, επομένως τα comments/tokens μπορεί να στοχευθούν λανθασμένα
- Η δημιουργία κάθε πιθανού variant σε μια αδύναμη γραμμή σπαταλά μεγάλες ποσότητες runtime

Τα εργαλεία που βασίζονται σε AST ή Tree-sitter το βελτιώνουν αυτό, στοχεύοντας structured nodes αντί για raw lines:<sup>[[1]](#references)</sup>
- **slither-mutate** χρησιμοποιεί το Solidity AST του Slither.<sup>[[4]](#references)</sup>
- **mewt** χρησιμοποιεί το Tree-sitter ως language-agnostic core.<sup>[[6]](#references)</sup>
- Το **MuTON** βασίζεται στο `mewt` και προσθέτει first-class support για TON languages όπως οι FunC, Tolk και Tact.<sup>[[7]](#references)</sup>

Αυτό καθιστά τα multi-line constructs και τα expression-level mutations πολύ πιο αξιόπιστα από approaches που βασίζονται αποκλειστικά σε regex.

## Εκτέλεση mutation testing με slither-mutate

Requirements: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Παράδειγμα Foundry (καταγραφή των αποτελεσμάτων και διατήρηση πλήρους log):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Αν δεν χρησιμοποιείτε Foundry, αντικαταστήστε το `--test-cmd` με τον τρόπο εκτέλεσης των tests (π.χ. `npx hardhat test`, `npm test`).

Τα artifacts αποθηκεύονται από προεπιλογή στο `./mutation_campaign`. Οι μη εντοπισμένες (surviving) μεταλλάξεις αντιγράφονται εκεί για επιθεώρηση.<sup>[[5]](#references)</sup>

### Κατανόηση της εξόδου

Οι γραμμές της αναφοράς μοιάζουν με:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Η ετικέτα σε αγκύλες είναι το alias του mutator (π.χ. `CR` = Comment Replacement).
- Το `UNCAUGHT` σημαίνει ότι τα tests πέρασαν με τη mutated συμπεριφορά → λείπει assertion.

## Μείωση του runtime: προτεραιοποίηση mutants με σημαντικό αντίκτυπο

Οι mutation campaigns μπορεί να διαρκέσουν ώρες ή ημέρες. Συμβουλές για τη μείωση του κόστους:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: Ξεκινήστε μόνο με critical contracts/directories και, στη συνέχεια, επεκταθείτε.
- Προτεραιοποίηση mutators: Αν ένας mutant υψηλής προτεραιότητας σε μια γραμμή επιβιώσει (για παράδειγμα `revert()` ή comment-out), παραλείψτε τις variants χαμηλότερης προτεραιότητας για αυτήν τη γραμμή.
- Χρησιμοποιήστε campaigns δύο φάσεων: εκτελέστε πρώτα focused/fast tests και, στη συνέχεια, επαναλάβετε τα tests μόνο για τους uncaught mutants με ολόκληρο το suite.
- Αντιστοιχίστε τα mutation targets σε συγκεκριμένες test commands όπου είναι δυνατό (για παράδειγμα auth code -> auth tests).
- Περιορίστε τις campaigns σε mutants υψηλής/μεσαίας σοβαρότητας όταν ο χρόνος είναι περιορισμένος.
- Εκτελέστε τα tests παράλληλα αν το runner σας το επιτρέπει· αποθηκεύστε σε cache τα dependencies/builds.
- Fail-fast: σταματήστε νωρίς όταν μια αλλαγή αποδεικνύει ξεκάθαρα ένα assertion gap.

Τα μαθηματικά του runtime είναι ανελέητα: `1000 mutants x 5-minute tests ~= 83 hours`, επομένως ο σχεδιασμός της campaign είναι εξίσου σημαντικός με τον ίδιο τον mutator.<sup>[[1]](#references)</sup>

## Persistent campaigns και triage σε μεγάλη κλίμακα

Μία αδυναμία των παλαιότερων workflows είναι η αποθήκευση των αποτελεσμάτων μόνο στο `stdout`. Σε campaigns μεγάλης διάρκειας, αυτό δυσκολεύει την παύση/συνέχιση, το filtering και το review.<sup>[[1]](#references)</sup>

Τα `mewt`/`MuTON` το βελτιώνουν αποθηκεύοντας τους mutants και τα outcomes σε campaigns που βασίζονται σε SQLite. Οφέλη:<sup>[[1]](#references)</sup>
- Παύση και συνέχιση runs μεγάλης διάρκειας χωρίς απώλεια προόδου
- Filtering μόνο των uncaught mutants σε συγκεκριμένο αρχείο ή mutation class
- Export/μετάφραση των αποτελεσμάτων σε SARIF για review tooling
- Παροχή μικρότερων, φιλτραρισμένων result sets για AI-assisted triage αντί για raw terminal logs

Τα persistent results είναι ιδιαίτερα χρήσιμα όταν το mutation testing γίνεται μέρος ενός audit pipeline αντί για one-off manual review.

## Triage workflow για surviving mutants

1) Ελέγξτε τη mutated γραμμή και τη συμπεριφορά.
- Αναπαραγάγετε τοπικά εφαρμόζοντας τη mutated γραμμή και εκτελώντας ένα focused test.

2) Ενισχύστε τα tests ώστε να ελέγχουν το state και όχι μόνο τις return values.
- Προσθέστε equality-boundary checks (π.χ. test του threshold `==`).
- Ελέγξτε τα post-conditions: balances, total supply, authorization effects και emitted events.

3) Αντικαταστήστε τα υπερβολικά permissive mocks με ρεαλιστική συμπεριφορά.
- Βεβαιωθείτε ότι τα mocks επιβάλλουν τα transfers, τα failure paths και τα event emissions που συμβαίνουν on-chain.

4) Προσθέστε invariants για fuzz tests.
- Π.χ. conservation of value, non-negative balances, authorization invariants και monotonic supply όπου εφαρμόζεται.

5) Διαχωρίστε τα true positives από τα semantic no-ops.
- Παράδειγμα: `x > 0` -> `x != 0` δεν έχει νόημα όταν το `x` είναι unsigned.

6) Εκτελέστε ξανά την campaign μέχρι οι survivors να εξουδετερωθούν ή να αιτιολογηθούν ρητά.

## Case study: αποκάλυψη missing state assertions (Arkis protocol)

Μια mutation campaign κατά τη διάρκεια audit του Arkis DeFi protocol αποκάλυψε survivors όπως:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Ο σχολιασμός της ανάθεσης δεν προκάλεσε αποτυχία των tests, αποδεικνύοντας την απουσία assertions για την post-state. Βασική αιτία: ο κώδικας εμπιστευόταν ένα user-controlled `_cmd.value` αντί να επικυρώνει τις πραγματικές μεταφορές token. Ένας attacker θα μπορούσε να αποσυγχρονίσει τις αναμενόμενες από τις πραγματικές μεταφορές και να αποστραγγίσει κεφάλαια. Αποτέλεσμα: υψηλής σοβαρότητας κίνδυνος για τη φερεγγυότητα του protocol.<sup>[[2]](#references)[[3]](#references)</sup>

Οδηγία: Αντιμετωπίζετε τους survivors που επηρεάζουν μεταφορές αξίας, accounting ή access control ως υψηλού κινδύνου μέχρι να killed.

## Μην δημιουργείτε tests τυφλά για να killed κάθε mutant

Η δημιουργία tests με mutation-driven τρόπο μπορεί να έχει αντίθετα αποτελέσματα αν η τρέχουσα υλοποίηση είναι λανθασμένη. Παράδειγμα: η μετάλλαξη του `priority >= 2` σε `priority > 2` αλλάζει τη συμπεριφορά, αλλά η σωστή διόρθωση δεν είναι πάντα «γράψε ένα test για `priority == 2`». Η ίδια η συμπεριφορά μπορεί να αποτελεί το bug.<sup>[[1]](#references)</sup>

Ασφαλέστερη ροή εργασίας:
- Χρησιμοποιήστε τους surviving mutants για να εντοπίσετε αμφίσημες απαιτήσεις
- Επικυρώστε την αναμενόμενη συμπεριφορά από τα specs, τα protocol docs ή τους reviewers
- Μόνο τότε κωδικοποιήστε τη συμπεριφορά ως test/invariant

Διαφορετικά, κινδυνεύετε να ενσωματώσετε στο test suite τυχαία χαρακτηριστικά της υλοποίησης και να αποκτήσετε false confidence.

## Πρακτικό checklist

- Εκτελέστε μια στοχευμένη campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Προτιμήστε syntax-aware mutators (AST/Tree-sitter) έναντι mutation που βασίζεται αποκλειστικά σε regex, όταν είναι διαθέσιμοι.
- Κάντε triage στους survivors και γράψτε tests/invariants που θα αποτύγχαναν υπό τη μεταλλαγμένη συμπεριφορά.
- Κάντε assert σε balances, supply, authorizations και events.
- Προσθέστε boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Αντικαταστήστε τα μη ρεαλιστικά mocks· προσομοιώστε failure modes.
- Αποθηκεύστε τα αποτελέσματα όταν το tooling το υποστηρίζει και φιλτράρετε τους uncaught mutants πριν από το triage.
- Χρησιμοποιήστε two-phase ή per-target campaigns για να διατηρήσετε διαχειρίσιμο το runtime.
- Επαναλάβετε μέχρι να killed όλοι οι mutants ή να αιτιολογηθούν με comments και rationale.

## References

- [1] [Mutation testing για την agentic εποχή](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Χρησιμοποιήστε mutation testing για να εντοπίσετε τα bugs που δεν εντοπίζουν τα tests σας (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Security Review του Arkis DeFi Prime Brokerage (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Τεκμηρίωση του Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
