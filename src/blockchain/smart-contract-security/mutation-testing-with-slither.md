# Mutation Testing για Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Το Mutation testing «δοκιμάζει τα tests σας», εισάγοντας συστηματικά μικρές αλλαγές (mutants) στον κώδικα του contract και εκτελώντας ξανά τη test suite. Αν ένα test αποτύχει, ο mutant σκοτώνεται. Αν τα tests συνεχίσουν να περνούν, ο mutant επιβιώνει, αποκαλύπτοντας ένα blind spot που δεν μπορεί να εντοπίσει το line/branch coverage.

Βασική ιδέα: Το coverage δείχνει ότι ο κώδικας εκτελέστηκε· το mutation testing δείχνει αν η συμπεριφορά ελέγχεται πράγματι από assertions.<sup>[[2]](#references)</sup>

## Γιατί το coverage μπορεί να είναι παραπλανητικό

Εξετάστε αυτόν τον απλό έλεγχο threshold:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Τα unit tests που ελέγχουν μόνο μια τιμή κάτω και μια τιμή πάνω από το threshold μπορούν να επιτύχουν 100% line/branch coverage, χωρίς να ελέγχουν το boundary της ισότητας (`==`). Ένα refactor σε `deposit >= 2 ether` θα περνούσε και πάλι αυτά τα tests, παραβιάζοντας σιωπηρά τη λογική του protocol.<sup>[[2]](#references)</sup>

Το mutation testing αποκαλύπτει αυτό το κενό, μεταλλάσσοντας τη συνθήκη και επαληθεύοντας ότι τα tests αποτυγχάνουν.

Για τα smart contracts, οι mutants που επιβιώνουν αντιστοιχούν συχνά σε ελλιπείς ελέγχους σχετικά με:
- Authorization και όρια ρόλων
- Invariants λογιστικής/μεταφοράς αξίας
- Συνθήκες revert και failure paths
- Boundary conditions (`==`, μηδενικές τιμές, κενά arrays, μέγιστες/ελάχιστες τιμές)

## Mutation operators με το υψηλότερο security signal

Χρήσιμες κατηγορίες mutations για contract auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **Υψηλή σοβαρότητα**: αντικατάσταση statements με `revert()` για την αποκάλυψη paths που δεν εκτελούνται
- **Μεσαία σοβαρότητα**: σχολιασμός γραμμών / αφαίρεση logic για την αποκάλυψη side effects που δεν επαληθεύονται
- **Χαμηλή σοβαρότητα**: subtle swaps τελεστών ή constants, όπως `>=` -> `>` ή `+` -> `-`
- Άλλες συνηθισμένες τροποποιήσεις: αντικατάσταση assignments, boolean flips, negation συνθηκών και αλλαγές τύπων

Πρακτικός στόχος: να εξουδετερωθούν όλοι οι meaningful mutants και να αιτιολογηθούν ρητά όσοι επιβιώνουν επειδή είναι irrelevant ή semantically equivalent.

## Γιατί το syntax-aware mutation είναι καλύτερο από το regex

Οι παλαιότεροι mutation engines βασίζονταν σε regex ή σε line-oriented rewrites. Αυτό λειτουργεί, αλλά έχει σημαντικούς περιορισμούς:<sup>[[1]](#references)</sup>
- Οι multi-line statements είναι δύσκολο να μεταλλαχθούν με ασφάλεια
- Δεν γίνεται κατανοητή η δομή της γλώσσας, επομένως τα comments/tokens μπορεί να στοχοποιηθούν λανθασμένα
- Η δημιουργία κάθε πιθανού variant σε μια weak line σπαταλά μεγάλες ποσότητες runtime

Τα εργαλεία που βασίζονται σε AST ή Tree-sitter το βελτιώνουν αυτό, στοχεύοντας structured nodes αντί για raw lines:<sup>[[1]](#references)</sup>
- **slither-mutate** χρησιμοποιεί το Solidity AST του Slither<sup>[[4]](#references)</sup>
- **mewt** χρησιμοποιεί το Tree-sitter ως language-agnostic core<sup>[[6]](#references)</sup>
- **MuTON** βασίζεται στο `mewt` και προσθέτει first-class support για TON languages, όπως FunC, Tolk και Tact<sup>[[7]](#references)</sup>

Αυτό καθιστά τα multi-line constructs και τα expression-level mutations πολύ πιο αξιόπιστα από προσεγγίσεις που βασίζονται αποκλειστικά σε regex.

## Εκτέλεση mutation testing με slither-mutate

Requirements: Slither v0.10.2+.

- Εμφάνιση options και mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Παράδειγμα Foundry (καταγραφή των αποτελεσμάτων και διατήρηση πλήρους log):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Αν δεν χρησιμοποιείτε Foundry, αντικαταστήστε το `--test-cmd` με τον τρόπο που εκτελείτε τα tests (π.χ. `npx hardhat test`, `npm test`).

Τα artifacts αποθηκεύονται από προεπιλογή στο `./mutation_campaign`. Οι mutants που δεν ανιχνεύτηκαν (surviving) αντιγράφονται εκεί για επιθεώρηση.<sup>[[5]](#references)</sup>

### Κατανόηση των αποτελεσμάτων

Οι γραμμές της αναφοράς έχουν την εξής μορφή:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Το tag σε αγκύλες είναι το alias του mutator (π.χ. `CR` = Comment Replacement).
- `UNCAUGHT` σημαίνει ότι τα tests πέρασαν με τη mutated συμπεριφορά → λείπει assertion.

## Μείωση του runtime: δώστε προτεραιότητα στους impactful mutants

Οι mutation campaigns μπορεί να διαρκέσουν ώρες ή ημέρες. Συμβουλές για τη μείωση του κόστους:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: Ξεκινήστε μόνο με τα critical contracts/directories και, στη συνέχεια, επεκταθείτε.
- Δώστε προτεραιότητα στους mutators: Αν ένας high-priority mutant σε μια γραμμή επιβιώσει (για παράδειγμα `revert()` ή comment-out), παραλείψτε τις lower-priority παραλλαγές για αυτήν τη γραμμή.
- Χρησιμοποιήστε two-phase campaigns: εκτελέστε πρώτα focused/fast tests και, στη συνέχεια, επαναλάβετε τα tests μόνο για τους uncaught mutants με ολόκληρο το suite.
- Αντιστοιχίστε τα mutation targets σε συγκεκριμένες test commands όπου είναι δυνατόν (για παράδειγμα auth code -> auth tests).
- Περιορίστε τις campaigns σε high/medium severity mutants όταν ο χρόνος είναι περιορισμένος.
- Εκτελέστε τα tests παράλληλα, αν το runner σας το επιτρέπει· κάντε cache τα dependencies/builds.
- Fail-fast: σταματήστε νωρίς όταν μια αλλαγή αποδεικνύει ξεκάθαρα ένα assertion gap.

Τα μαθηματικά του runtime είναι σκληρά: `1000 mutants x 5-minute tests ~= 83 hours`, επομένως ο σχεδιασμός της campaign έχει εξίσου μεγάλη σημασία με τον ίδιο τον mutator.<sup>[[1]](#references)</sup>

## Persistent campaigns και triage σε μεγάλη κλίμακα

Μία αδυναμία των παλαιότερων workflows είναι η καταγραφή των αποτελεσμάτων μόνο στο `stdout`. Σε long campaigns, αυτό δυσκολεύει το pause/resume, το filtering και το review.<sup>[[1]](#references)</sup>

Τα `mewt`/`MuTON` το βελτιώνουν αποθηκεύοντας τους mutants και τα outcomes σε SQLite-backed campaigns. Οφέλη:<sup>[[1]](#references)</sup>
- Pause και resume long runs χωρίς απώλεια προόδου
- Filter μόνο τους uncaught mutants σε συγκεκριμένο file ή mutation class
- Export/translate των results σε SARIF για review tooling
- Παροχή μικρότερων, filtered result sets για AI-assisted triage αντί για raw terminal logs

Τα persistent results είναι ιδιαίτερα χρήσιμα όταν το mutation testing γίνεται μέρος ενός audit pipeline αντί για ένα one-off manual review.

## Triage workflow για surviving mutants

1) Επιθεωρήστε τη mutated γραμμή και τη συμπεριφορά.
- Κάντε local reproduce εφαρμόζοντας τη mutated γραμμή και εκτελώντας ένα focused test.

2) Ενισχύστε τα tests ώστε να κάνουν assert το state και όχι μόνο τις return values.
- Προσθέστε equality-boundary checks (π.χ. test για threshold `==`).
- Κάντε assert τα post-conditions: balances, total supply, authorization effects και emitted events.

3) Αντικαταστήστε τα υπερβολικά permissive mocks με realistic behavior.
- Βεβαιωθείτε ότι τα mocks επιβάλλουν transfers, failure paths και event emissions που συμβαίνουν on-chain.

4) Προσθέστε invariants για fuzz tests.
- Π.χ. conservation of value, non-negative balances, authorization invariants και monotonic supply όπου εφαρμόζεται.

5) Διαχωρίστε τα true positives από τα semantic no-ops.
- Παράδειγμα: `x > 0` -> `x != 0` δεν έχει νόημα όταν το `x` είναι unsigned.

6) Εκτελέστε ξανά την campaign μέχρι οι survivors να killed ή να δικαιολογηθούν ρητά.

## Case study: αποκάλυψη missing state assertions (Arkis protocol)

Μια mutation campaign κατά τη διάρκεια audit του Arkis DeFi protocol αποκάλυψε survivors όπως:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Το σχολιασμό της ανάθεσης δεν διέκοψε τα tests, αποδεικνύοντας την απουσία assertions για το post-state. Βασική αιτία: ο κώδικας εμπιστευόταν ένα ελεγχόμενο από τον χρήστη `_cmd.value` αντί να επικυρώνει τις πραγματικές μεταφορές token. Ένας attacker θα μπορούσε να αποσυγχρονίσει τις αναμενόμενες από τις πραγματικές μεταφορές και να αποστραγγίσει κεφάλαια. Αποτέλεσμα: υψηλής σοβαρότητας κίνδυνος για τη φερεγγυότητα του protocol.<sup>[[2]](#references)[[3]](#references)</sup>

Οδηγία: Αντιμετωπίζετε τους survivors που επηρεάζουν μεταφορές αξίας, accounting ή access control ως υψηλού κινδύνου μέχρι να εξουδετερωθούν.

## Μην δημιουργείτε τυφλά tests για να εξουδετερώσετε κάθε mutant

Η δημιουργία tests με βάση τα mutations μπορεί να αποτύχει αν η τρέχουσα υλοποίηση είναι λανθασμένη. Παράδειγμα: η μετάλλαξη του `priority >= 2` σε `priority > 2` αλλάζει τη συμπεριφορά, όμως η σωστή διόρθωση δεν είναι πάντα «γράψε ένα test για `priority == 2`». Αυτή η συμπεριφορά μπορεί να είναι η ίδια το bug.<sup>[[1]](#references)</sup>

Ασφαλέστερη ροή εργασίας:
- Χρησιμοποιήστε τους surviving mutants για να εντοπίσετε ασαφείς απαιτήσεις
- Επικυρώστε την αναμενόμενη συμπεριφορά από τα specs, τα protocol docs ή τους reviewers
- Μόνο τότε κωδικοποιήστε τη συμπεριφορά ως test/invariant

Διαφορετικά, υπάρχει κίνδυνος να hard-code-άρετε τυχαίες λεπτομέρειες της υλοποίησης στη test suite και να αποκτήσετε false confidence.

## Πρακτικό checklist

- Εκτελέστε μια στοχευμένη campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Προτιμήστε syntax-aware mutators (AST/Tree-sitter) αντί για mutation που βασίζεται αποκλειστικά σε regex, όταν είναι διαθέσιμα.
- Κάντε triage στους survivors και γράψτε tests/invariants που θα αποτύγχαναν με τη mutated συμπεριφορά.
- Κάντε assertions για balances, supply, authorizations και events.
- Προσθέστε boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Αντικαταστήστε τα μη ρεαλιστικά mocks· προσομοιώστε failure modes.
- Αποθηκεύστε τα αποτελέσματα όταν το tooling το υποστηρίζει και φιλτράρετε τους uncaught mutants πριν από το triage.
- Χρησιμοποιήστε two-phase ή per-target campaigns για να διατηρήσετε τον χρόνο εκτέλεσης διαχειρίσιμο.
- Επαναλάβετε μέχρι να εξουδετερωθούν όλοι οι mutants ή να δικαιολογηθούν με comments και rationale.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
