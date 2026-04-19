# Mutation Testing for Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Το mutation testing "tests your tests" εισάγοντας συστηματικά μικρές αλλαγές (mutants) στον κώδικα του contract και εκτελώντας ξανά το test suite. Αν ένα test αποτύχει, το mutant is killed. Αν τα tests συνεχίσουν να περνούν, το mutant survives, αποκαλύπτοντας ένα blind spot που το line/branch coverage cannot detect.

Κεντρική ιδέα: Το Coverage δείχνει ότι ο κώδικας εκτελέστηκε· το mutation testing δείχνει αν η συμπεριφορά όντως επιβεβαιώνεται.

## Why coverage can deceive

Consider this simple threshold check:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Οι unit tests που ελέγχουν μόνο μια τιμή κάτω και μια τιμή πάνω από το threshold μπορούν να φτάσουν 100% line/branch coverage ενώ αποτυγχάνουν να κάνουν assert το equality boundary (==). Ένα refactor σε `deposit >= 2 ether` θα περνούσε ακόμα τέτοια tests, σπάζοντας σιωπηλά τη λογική του protocol.

Το mutation testing αποκαλύπτει αυτό το κενό κάνοντας mutate τη συνθήκη και επαληθεύοντας ότι τα tests αποτυγχάνουν.

Για smart contracts, τα surviving mutants συχνά αντιστοιχούν σε ελλείποντες ελέγχους γύρω από:
- Authorization και role boundaries
- Accounting/value-transfer invariants
- Revert conditions και failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## Mutation operators with the highest security signal

Χρήσιμες mutation classes για contract auditing:
- **High severity**: replace statements with `revert()` to expose unexecuted paths
- **Medium severity**: comment out lines / remove logic to reveal unverified side effects
- **Low severity**: subtle operator or constant swaps such as `>=` -> `>` or `+` -> `-`
- Άλλες συνηθισμένες αλλαγές: assignment replacement, boolean flips, condition negation, και type changes

Πρακτικός στόχος: kill all meaningful mutants, και τεκμηρίωσε ρητά τους survivors που είναι άσχετοι ή semantically equivalent.

## Why syntax-aware mutation is better than regex

Παλαιότεροι mutation engines βασίζονταν σε regex ή line-oriented rewrites. Αυτό δουλεύει, αλλά έχει σημαντικούς περιορισμούς:
- Τα multi-line statements είναι δύσκολο να mutated με ασφάλεια
- Η δομή της γλώσσας δεν γίνεται κατανοητή, οπότε comments/tokens μπορεί να στοχευτούν άσχημα
- Η παραγωγή κάθε δυνατής παραλλαγής πάνω σε μια weak line σπαταλά τεράστιο runtime

AST- ή Tree-sitter-based tooling βελτιώνει αυτό στοχεύοντας structured nodes αντί για raw lines:
- **slither-mutate** χρησιμοποιεί το Solidity AST του Slither
- **mewt** χρησιμοποιεί το Tree-sitter ως language-agnostic core
- **MuTON** βασίζεται στο `mewt` και προσθέτει first-class support για TON languages όπως FunC, Tolk, και Tact

Αυτό κάνει τα multi-line constructs και τα expression-level mutations πολύ πιο αξιόπιστα από τις regex-only approaches.

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Παράδειγμα Foundry (capture results και διατήρησε πλήρες log):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Αν δεν χρησιμοποιείς Foundry, αντικατάστησε το `--test-cmd` με τον τρόπο που τρέχεις τα tests (π.χ. `npx hardhat test`, `npm test`).

Τα artifacts αποθηκεύονται στο `./mutation_campaign` από προεπιλογή. Τα uncaught (surviving) mutants αντιγράφονται εκεί για επιθεώρηση.

### Κατανόηση του output

Οι γραμμές του report μοιάζουν με:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Η ετικέτα σε αγκύλες είναι το alias του mutator (π.χ., `CR` = Comment Replacement).
- `UNCAUGHT` σημαίνει ότι τα tests πέρασαν υπό τη mutated συμπεριφορά → λείπει assertion.

## Μείωση runtime: δώσε προτεραιότητα σε impactful mutants

Οι mutation campaigns μπορεί να διαρκέσουν ώρες ή ημέρες. Tips για να μειώσεις το κόστος:
- Scope: Ξεκίνα μόνο με κρίσιμα contracts/directories, και μετά επεκτάσου.
- Prioritize mutators: Αν ένας high-priority mutant σε μια γραμμή επιβιώσει (για παράδειγμα `revert()` ή comment-out), παράλειψε lower-priority variants για εκείνη τη γραμμή.
- Χρησιμοποίησε two-phase campaigns: τρέξε πρώτα focused/fast tests, και μετά ξανατρέξε μόνο τα uncaught mutants με το full suite.
- Αντιστοίχισε mutation targets σε συγκεκριμένα test commands όπου γίνεται (για παράδειγμα auth code -> auth tests).
- Περιόρισε τις campaigns σε high/medium severity mutants όταν ο χρόνος είναι περιορισμένος.
- Κάνε parallelize τα tests αν το runner το επιτρέπει· κάνε cache dependencies/builds.
- Fail-fast: σταμάτα νωρίς όταν μια αλλαγή δείχνει ξεκάθαρα assertion gap.

Το runtime math είναι brutal: `1000 mutants x 5-minute tests ~= 83 hours`, οπότε ο σχεδιασμός της campaign έχει τόση σημασία όσο και ο mutator ίδιος.

## Persistent campaigns και triage σε κλίμακα

Μια αδυναμία παλαιότερων workflows είναι ότι ρίχνουν τα results μόνο στο `stdout`. Για μακρές campaigns, αυτό κάνει το pause/resume, το filtering και το review πιο δύσκολα.

`mewt`/`MuTON` το βελτιώνουν αυτό αποθηκεύοντας mutants και outcomes σε SQLite-backed campaigns. Benefits:
- Pause και resume μακρές εκτελέσεις χωρίς να χάνεις πρόοδο
- Φιλτράρεις μόνο τα uncaught mutants σε συγκεκριμένο file ή mutation class
- Export/translate results σε SARIF για review tooling
- Δίνεις στο AI-assisted triage μικρότερα, φιλτραρισμένα result sets αντί για raw terminal logs

Τα persistent results είναι ιδιαίτερα χρήσιμα όταν το mutation testing γίνεται μέρος ενός audit pipeline αντί για ένα one-off manual review.

## Triage workflow για surviving mutants

1) Εξέτασε τη mutated γραμμή και τη συμπεριφορά.
- Reproduce locally εφαρμόζοντας τη mutated γραμμή και τρέχοντας ένα focused test.

2) Ενίσχυσε τα tests ώστε να κάνουν assert state, όχι μόνο return values.
- Πρόσθεσε equality-boundary checks (π.χ., test threshold `==`).
- Κάνε assert post-conditions: balances, total supply, authorization effects, και emitted events.

3) Αντικατάστησε overly permissive mocks με realistic behavior.
- Βεβαιώσου ότι τα mocks επιβάλλουν transfers, failure paths, και event emissions που συμβαίνουν on-chain.

4) Πρόσθεσε invariants για fuzz tests.
- Π.χ., conservation of value, non-negative balances, authorization invariants, monotonic supply όπου εφαρμόζεται.

5) Χώρισε τα true positives από τα semantic no-ops.
- Παράδειγμα: `x > 0` -> `x != 0` είναι meaningless όταν το `x` είναι unsigned.

6) Ξανατρέξε την campaign μέχρι οι survivors να σκοτωθούν ή να δικαιολογηθούν ρητά.

## Case study: revealing missing state assertions (Arkis protocol)

Μια mutation campaign κατά τη διάρκεια audit του Arkis DeFi protocol ανέδειξε survivors όπως:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Το σχόλιασμα της ανάθεσης δεν χάλασε τα tests, αποδεικνύοντας ότι λείπουν post-state assertions. Αιτία: ο κώδικας εμπιστευόταν ένα `_cmd.value` υπό τον έλεγχο του χρήστη αντί να επαληθεύει τις πραγματικές μεταφορές token. Ένας attacker θα μπορούσε να αποσυγχρονίσει τις αναμενόμενες έναντι των πραγματικών μεταφορών για να αποστραγγίσει κεφάλαια. Αποτέλεσμα: υψηλού κινδύνου ρίσκο για τη φερεγγυότητα του protocol.

Καθοδήγηση: Θεώρησε ως υψηλού κινδύνου τους survivors που επηρεάζουν value transfers, accounting, ή access control μέχρι να killed.

## Μην παράγεις τυφλά tests για να σκοτώνεις κάθε mutant

Η δημιουργία tests με βάση mutation μπορεί να γυρίσει μπούμερανγκ αν η τρέχουσα υλοποίηση είναι λάθος. Παράδειγμα: το να μετατρέψεις το `priority >= 2` σε `priority > 2` αλλάζει τη συμπεριφορά, αλλά η σωστή διόρθωση δεν είναι πάντα το "γράψε ένα test για `priority == 2`". Αυτή η συμπεριφορά μπορεί να είναι η ίδια το bug.

Πιο ασφαλής ροή εργασίας:
- Χρησιμοποίησε survivors για να εντοπίσεις ασαφείς απαιτήσεις
- Επικύρωσε την αναμενόμενη συμπεριφορά από specs, protocol docs, ή reviewers
- Μόνο τότε κωδικοποίησε τη συμπεριφορά ως test/invariant

Αλλιώς, κινδυνεύεις να κάνεις hard-code τυχαία implementation accidents στο test suite και να αποκτήσεις ψεύτικη αυτοπεποίθηση.

## Πρακτικό checklist

- Τρέξε μια στοχευμένη campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Προτίμησε syntax-aware mutators (AST/Tree-sitter) αντί για regex-only mutation όταν είναι διαθέσιμα.
- Κάνε triage survivors και γράψε tests/invariants που θα αποτύγχαναν κάτω από τη mutated συμπεριφορά.
- Έλεγξε balances, supply, authorizations, και events.
- Πρόσθεσε boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Αντικατάστησε μη ρεαλιστικά mocks· προσομοίωσε failure modes.
- Διατήρησε τα αποτελέσματα όταν το tooling το υποστηρίζει, και φιλτράρισε uncaught mutants πριν το triage.
- Χρησιμοποίησε two-phase ή per-target campaigns για να κρατήσεις το runtime διαχειρίσιμο.
- Επανάλαβε μέχρι να killed όλοι οι mutants ή να δικαιολογηθούν με σχόλια και rationale.

## Αναφορές

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
