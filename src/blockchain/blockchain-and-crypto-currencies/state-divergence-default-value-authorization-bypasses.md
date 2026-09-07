# Παράκαμψη εξουσιοδότησης μέσω απόκλισης κατάστασης και προεπιλεγμένων τιμών

{{#include ../../banners/hacktricks-training.md}}

Η εξουσιοδότηση μερικές φορές εξαρτάται από παράγωγη οικονομική κατάσταση αντί για έναν explicit ρόλο—για παράδειγμα, «ο caller κατέχει ολόκληρη την προσφορά». Αν οι τιμές αυτού του predicate προέρχονται από διαφορετικά stores, ένα stale αντίγραφο μπορεί να μετατρέψει μια νόμιμη συντόμευση ιδιοκτησίας σε authorization bypass. Το Provenance marker module απέδειξε τον επικίνδυνο συνδυασμό: ένα live υπόλοιπο caller συγκρινόταν με supply metadata τοπικά στο marker, το οποίο δεν ενημερωνόταν για assets με μη-fixed supply.<sup>[[1]](#references)</sup>

## Έλεγχος duplicated state ως authorization boundary

Για κάθε τιμή που χρησιμοποιείται από έναν permission check, καταγράψτε **όλες τις αναπαραστάσεις**: canonical module state, object fields, cached aggregates, indexes, snapshots, bridge records και off-chain mirrors. Στη συνέχεια, ιχνηλατήστε κάθε διαδρομή create, mint, burn, transfer, reset, migration και synchronization, ώστε να προσδιορίσετε ποιο αντίγραφο ενημερώνεται σε κάθε object mode. Ένα field μπορεί να είναι authoritative για ένα mode και informational για ένα άλλο.<sup>[[1]](#references)</sup>

Μια πρακτική ροή ελέγχου είναι:<sup>[[1]](#references)</sup>

1. Εντοπίστε τις protected actions και απλοποιήστε κάθε authorization branch σε ένα boolean predicate.
2. Για κάθε operand, καταγράψτε το store του, τις update paths, τα lifecycle states και το source of truth.
3. Δημιουργήστε transitions που ενημερώνουν μόνο μία αναπαράσταση και, στη συνέχεια, συγκρίνετε όλα τα αντίγραφα.
4. Επιχειρήστε την protected action από έναν fresh account μετά από κάθε transition.
5. Συνεχίστε πέρα από το bypass: αν η action τροποποιεί ένα ACL, αποδώστε στον εαυτό σας persistent roles και καλέστε τα κανονικά privileged APIs.

Ύποπτα patterns περιλαμβάνουν `cachedSupply == balance`, `metadataOwner == caller` ή `snapshotShares == currentShares`, όταν οι δύο πλευρές έχουν διαφορετικούς κανόνες synchronization. Η ανάκτηση μιας authoritative τιμής για το ένα operand δεν καθιστά τη σύγκριση ασφαλή όταν το άλλο operand είναι stale.<sup>[[1]](#references)</sup>

## Παράκαμψη ισότητας προεπιλεγμένων τιμών

Ένα equality predicate είναι επίσης μη ασφαλές όταν και τα δύο operands μπορούν ανεξάρτητα να λάβουν την ίδια default value. Ο παρακάτω check παρέχει «πλήρη έλεγχο της προσφοράς» σε οποιονδήποτε empty account όταν το `supply` είναι μηδέν, ανεξάρτητα από το αν το μηδέν προκύπτει από stale metadata ή από ένα legitimately unfunded object.<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
Η μετάβαση στο canonical store διορθώνει το divergence, αλλά **όχι** την περίπτωση του empty-object. Η ιδιότητα ασφάλειας πρέπει να περιλαμβάνει μια ανεξάρτητη συνθήκη εγκυρότητας· το Provenance patch χρησιμοποιεί το live bank supply και απορρίπτει nil ή supply ίσο με μηδέν πριν συγκρίνει το caller balance.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
Εφαρμόστε την ίδια λογική σε counts απαρτίας, ποσοστά ιδιοκτησίας, χρέος, collateral, epochs, nonces, timestamps και counters: το `callerValue == protectedValue` δεν πρέπει να εξουσιοδοτεί έναν caller έως ότου η protected value είναι ανεξάρτητα έγκυρη και ανήκει στο αναμενόμενο domain.<sup>[[1]](#references)</sup>

## ACL takeover to legitimate privileged operations

Ένα bypass σε μια operation επεξεργασίας ACL αποτελεί έναν μόνιμο primitive κλιμάκωσης προνομίων. Στην περίπτωση του Provenance, ένας λογαριασμός χωρίς προνόμια και με μηδενικά tokens μπορούσε να περάσει το stale τεστ `0 == 0` για το supply, να εκχωρήσει στον εαυτό του administrative, mint και withdrawal permissions και, στη συνέχεια, να χρησιμοποιήσει ordinary message handlers για να κάνει mint assets ή να πραγματοποιήσει withdrawal από escrow. Επομένως, το exploit δεν απαιτούσε δεύτερο vulnerability μετά την αλλαγή του ACL.<sup>[[1]](#references)</sup>

Γενική ακολουθία exploitation:<sup>[[1]](#references)</sup>

1. Βρείτε ένα object του οποίου ένα non-authoritative field διαφέρει από το live state ή του οποίου η protected value είναι η default.
2. Χρησιμοποιήστε μια νέα/κενή identity, ώστε η local value της να ταιριάζει με αυτήν τη stale/default value.
3. Καλέστε το role-management, ownership-transfer ή policy-update endpoint και εκχωρήστε στον εαυτό σας durable capabilities.
4. Επιβεβαιώστε την persistence διαβάζοντας το ACL από το canonical state.
5. Καλέστε την legitimate high-impact operation (mint, withdraw, upgrade, transfer ownership ή change policy).

Κατά την αξιολόγηση του impact, ελέγξτε κάθε capability που είναι προσβάσιμη από τον νέο role, αντί να σταματήσετε στο authorization bypass. Λογαριασμοί τύπου escrow μπορεί να διατηρούν assets που δεν σχετίζονται με το object του οποίου τα stale metadata επέτρεψαν το takeover.<sup>[[1]](#references)</sup>

## Invariant and stateful-fuzzing targets

Ορίστε την authorization ανεξάρτητα από την implementation. Για ένα full-supply shortcut, το ελάχιστο invariant είναι:<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
Χρησιμοποίησε έναν model/state-machine fuzzer για να δημιουργείς sequences — όχι μεμονωμένα calls — καλύπτοντας τη δημιουργία, την αρχικοποίηση με zero-value, την activation/finalization, το minting, το burning, τα transfers, τα resets, τα migrations, τα sync calls και τις αλλαγές ACL. Μετά από κάθε transition, σύγκρινε τις duplicated representations και επιβεβαίωσε ότι ένας fresh account δεν μπορεί να εκτελέσει καμία protected action. Πρόσθεσε explicit cases για zero, one unit, partial ownership, full ownership, stale-low και stale-high values.<sup>[[1]](#references)[[2]](#references)</sup>

Οι regression properties με υψηλό signal είναι:<sup>[[1]](#references)[[2]](#references)</sup>

- Το zero authoritative supply δεν υποδηλώνει ποτέ ownership ή administration.
- Οι partial holders δεν μπορούν να γίνουν administrators όταν ένα duplicate supply ισούται με το balance τους.
- Ένας true full holder διατηρεί το intended shortcut όταν το live supply είναι positive.
- Τα failed self-grants δεν μεταβάλλουν το ACL ούτε ενεργοποιούν downstream privileged calls.
- Οι mode changes δεν μπορούν να αλλάξουν σιωπηρά ποια representation θεωρεί authoritative ένα authorization check.

## References

- [1] [Η state divergence επιτρέπει unauthorized access (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Διόρθωση stale supply checks](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Απόρριψη zero supply στο total-supply authorization shortcut](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
