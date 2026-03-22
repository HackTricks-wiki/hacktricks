# Χώρος Ονομάτων Χρόνου

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το time namespace εικονικοποιεί επιλεγμένα ρολόγια, ειδικά **`CLOCK_MONOTONIC`** και **`CLOCK_BOOTTIME`**. Είναι ένας νεότερος και πιο εξειδικευμένος namespace από τα mount, PID, network, ή user namespaces, και σπάνια είναι το πρώτο που σκέφτεται ένας operator όταν συζητά container hardening. Παρ' όλα αυτά, αποτελεί μέρος της σύγχρονης οικογένειας namespaces και αξίζει να γίνει κατανοητός σε εννοιολογικό επίπεδο.

Ο κύριος σκοπός είναι να επιτρέπει σε μια διεργασία να παρατηρεί ελεγχόμενα offsets για συγκεκριμένα ρολόγια χωρίς να αλλάζει την παγκόσμια εικόνα χρόνου του host. Αυτό είναι χρήσιμο για checkpoint/restore workflows, deterministic testing, και ορισμένη προηγμένη runtime συμπεριφορά. Συνήθως δεν αποτελεί κύριο μέτρο απομόνωσης με τον ίδιο τρόπο όπως τα mount ή user namespaces, αλλά συμβάλλει στο να γίνει το περιβάλλον της διεργασίας πιο αυτοτελές.

## Εργαστήριο

Αν ο host kernel και το userspace το υποστηρίζουν, μπορείτε να επιθεωρήσετε το namespace με:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Η υποστήριξη διαφέρει ανάλογα με την έκδοση του kernel και των εργαλείων, οπότε αυτή η σελίδα αφορά περισσότερο την κατανόηση του μηχανισμού παρά το να περιμένετε ότι θα είναι ορατή σε κάθε εργαστηριακό περιβάλλον.

### Μετατοπίσεις χρόνου

Τα time namespaces του Linux εικονικοποιούν μετατοπίσεις για `CLOCK_MONOTONIC` και `CLOCK_BOOTTIME`. Οι τρέχουσες μετατοπίσεις ανά namespace εκτίθενται μέσω του `/proc/<pid>/timens_offsets`, τα οποία, σε kernels που τα υποστηρίζουν, μπορούν επίσης να τροποποιηθούν από μια διαδικασία που κατέχει `CAP_SYS_TIME` μέσα στο σχετικό namespace:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Το αρχείο περιέχει διαφορές σε νανοδευτερόλεπτα. Η ρύθμιση του `monotonic` κατά δύο ημέρες αλλάζει παρατηρήσεις τύπου uptime εντός αυτού του namespace χωρίς να αλλάζει το host wall clock.

### `unshare` Βοηθητικές Σημαίες

Πρόσφατες εκδόσεις του `util-linux` παρέχουν βολικές σημαίες που γράφουν αυτόματα τις τιμές μετατόπισης:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Αυτές οι σημαίες είναι κυρίως μια βελτίωση της ευχρηστίας, αλλά διευκολύνουν επίσης την αναγνώριση της λειτουργίας στην τεκμηρίωση και στις δοκιμές.

## Χρήση κατά την εκτέλεση

Οι time namespaces είναι νεότεροι και λιγότερο ευρέως αξιοποιούμενοι σε σχέση με τα mount ή PID namespaces. Το OCI Runtime Specification v1.1 πρόσθεσε ρητή υποστήριξη για το `time` namespace και το πεδίο `linux.timeOffsets`, και οι νεότερες εκδόσεις του `runc` υλοποιούν αυτό το μέρος του μοντέλου. Ένα ελάχιστο OCI απόσπασμα μοιάζει ως εξής:
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Αυτό έχει σημασία επειδή μετατρέπει το time namespacing από ένα niche kernel primitive σε κάτι που τα runtimes μπορούν να ζητήσουν φορητά.

## Επιπτώσεις Ασφαλείας

Υπάρχουν λιγότερα κλασικά περιστατικά breakout που εστιάζουν στο time namespace σε σχέση με άλλους τύπους namespaces. Ο κίνδυνος εδώ συνήθως δεν είναι ότι το time namespace επιτρέπει άμεσα escape, αλλά ότι οι αναγνώστες το αγνοούν εντελώς και χάνουν πώς τα advanced runtimes μπορεί να διαμορφώνουν τη συμπεριφορά των process. Σε εξειδικευμένα περιβάλλοντα, οι αλλοιωμένες προβολές του ρολογιού μπορούν να επηρεάσουν checkpoint/restore, observability ή forensic υποθέσεις.

## Κατάχρηση

Συνήθως δεν υπάρχει εδώ άμεσο breakout primitive, αλλά η αλλοιωμένη συμπεριφορά του ρολογιού μπορεί ακόμη να είναι χρήσιμη για την κατανόηση του execution environment και την αναγνώριση advanced runtime features:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Αν συγκρίνετε δύο διεργασίες, οι διαφορές εδώ μπορούν να βοηθήσουν να εξηγήσουν ασυνήθιστη συμπεριφορά χρονισμού, artifacts από checkpoint/restore, ή αποκλίσεις στην καταγραφή ειδικές για το περιβάλλον.

Impact:

- σχεδόν πάντα reconnaissance ή κατανόηση του περιβάλλοντος
- χρήσιμο για την εξήγηση της καταγραφής, του uptime, ή ανωμαλιών από checkpoint/restore
- συνήθως δεν αποτελεί από μόνο του άμεσο container-escape μηχανισμό

Η σημαντική λεπτομέρεια κατά την κατάχρηση είναι ότι τα namespaces χρόνου δεν εικονικοποιούν το `CLOCK_REALTIME`, οπότε από μόνα τους δεν επιτρέπουν σε έναν επιτιθέμενο να πλαστογραφήσει το host wall clock ή να παρακάμψει απευθείας τους ελέγχους λήξης πιστοποιητικών σε όλο το σύστημα. Η αξία τους είναι κυρίως στο να μπερδέψουν λογική που βασίζεται σε monotonic-time, στην αναπαραγωγή σφαλμάτων ειδικών για το περιβάλλον, ή στην κατανόηση προηγμένης συμπεριφοράς του runtime.

## Checks

Αυτοί οι έλεγχοι αφορούν κυρίως την επιβεβαίωση κατά πόσο το runtime χρησιμοποιεί ιδιωτικό namespace χρόνου.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Τι είναι ενδιαφέρον εδώ:

- Σε πολλά περιβάλλοντα αυτές οι τιμές δεν θα οδηγήσουν σε άμεσο εύρημα ασφαλείας, αλλά δείχνουν αν μια εξειδικευμένη runtime λειτουργία είναι ενεργή.
- Αν συγκρίνετε δύο διαδικασίες, οι διαφορές εδώ μπορεί να εξηγήσουν συγκεχυμένο χρονισμό ή συμπεριφορά checkpoint/restore.

Για τα περισσότερα container breakouts, το time namespace δεν είναι ο πρώτος έλεγχος που θα διερευνήσετε. Παρ' όλα αυτά, μια πλήρης ενότητα container-security θα πρέπει να το αναφέρει επειδή αποτελεί μέρος του σύγχρονου μοντέλου του πυρήνα και περιστασιακά έχει σημασία σε προηγμένα runtime σενάρια.
{{#include ../../../../../banners/hacktricks-training.md}}
