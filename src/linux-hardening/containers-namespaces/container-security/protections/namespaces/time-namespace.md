# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το time namespace εικονικοποιεί επιλεγμένα ρολόγια μονοτονικού τύπου αντί για το wall clock του host. Στην πράξη, αυτό σημαίνει ιδιωτικά offsets για τα **`CLOCK_MONOTONIC`** και **`CLOCK_BOOTTIME`**, καθώς και για τις στενά σχετιζόμενες όψεις **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** και **`CLOCK_BOOTTIME_ALARM`**. Δεν εικονικοποιεί το **`CLOCK_REALTIME`**, επομένως τα `date` και η λογική λήξης πιστοποιητικών εξακολουθούν να παρατηρούν το wall clock του host, εκτός αν παρεμβαίνει κάποιος άλλος μηχανισμός.

Ο κύριος σκοπός είναι να επιτρέπεται σε μια διεργασία να παρατηρεί ελεγχόμενα offsets του χρόνου που έχει παρέλθει, χωρίς να αλλάζει η συνολική προβολή χρόνου του host. Αυτό είναι χρήσιμο για workflows checkpoint/restore, deterministic testing και προηγμένη συμπεριφορά runtime. Συνήθως δεν αποτελεί βασικό μηχανισμό isolation, όπως τα mount ή user namespaces, αλλά εξακολουθεί να συμβάλλει στο να γίνεται το περιβάλλον της διεργασίας πιο αυτοτελές.

Από offensive άποψη, αυτό το namespace είναι συνήθως πιο σχετικό με **reconnaissance, timer skew και κατανόηση του runtime** παρά με άμεσο breakout. Παρ' όλα αυτά, έχει σημασία επειδή όλο και περισσότερα container runtimes και workflows checkpoint/restore μπορούν πλέον να το ζητήσουν ρητά.

## Εργαστήριο

Αν το kernel και το userspace του host το υποστηρίζουν, μπορείτε να επιθεωρήσετε το namespace με:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
Η υποστήριξη διαφέρει ανάλογα με τις εκδόσεις του kernel και των εργαλείων, επομένως αυτή η σελίδα αφορά περισσότερο την κατανόηση του μηχανισμού παρά την προσδοκία ότι θα είναι ορατός σε κάθε lab environment. Η σημαντική παρατήρηση είναι ότι το `date` θα πρέπει να εξακολουθεί να αντικατοπτρίζει το wall clock του host, ενώ οι τιμές που βασίζονται σε monotonic/boottime είναι αυτές που αλλάζουν όταν ρυθμίζονται μη μηδενικά offsets.

### Ιδιαιτερότητα δημιουργίας

Τα time namespaces είναι ελαφρώς ασυνήθιστα σε σύγκριση με τα mount, PID ή network namespaces:

- Το `unshare(CLONE_NEWTIME)` δημιουργεί ένα νέο time namespace για **μελλοντικά child processes**.
- Το task που το καλεί παραμένει στο τρέχον time namespace του.
- Επομένως, το `/proc/<pid>/ns/time_for_children` είναι συχνά πιο ενδιαφέρον από το `/proc/<pid>/ns/time` κατά το debugging του runtime setup.

Το write window είναι επίσης ειδικό. Τα offsets στο `/proc/<pid>/timens_offsets` πρέπει να εγγραφούν πριν το νέο time namespace γεμίσει πλήρως με running tasks· στην πράξη, τα runtimes το κάνουν κατά το στενό setup window μεταξύ της δημιουργίας του namespace και της εκκίνησης του τελικού payload. Μόλις εκτελείται ήδη κάποιο task εκεί, οι μεταγενέστερες εγγραφές αποτυγχάνουν με `EACCES`. Γι’ αυτό τα low-level runtimes χειρίζονται το time-namespace setup ως early bootstrap step, αντί να προσπαθούν να τροποποιήσουν τα offsets από μέσα από μια ήδη εκκινημένη container process.

### Time Offsets

Τα Linux time namespaces εκθέτουν τα per-namespace offsets μέσω του `/proc/<pid>/timens_offsets`. Η μορφή αποτελείται από ένα σύνολο clock names ή IDs, μαζί με deltas δευτερολέπτων/νανοδευτερολέπτων σε σχέση με το initial time namespace.

Στην πράξη, το πιο αξιόπιστο user-facing workflow είναι να αφήσετε το `unshare` να γράψει αυτά τα offsets για εσάς:
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Το σημαντικό σημείο δεν είναι η ακριβής σύνταξη της εντολής, αλλά η συμπεριφορά: ένα container μπορεί να παρατηρεί μια διαφορετική προβολή τύπου uptime χωρίς να αλλάζει το wall clock του host.

### Βοηθητικά flags του `unshare`

Οι πρόσφατες εκδόσεις του `util-linux` παρέχουν flags ευκολίας που εγγράφουν αυτόματα τα offsets κατά τη δημιουργία του namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Αυτά τα flags αποτελούν κυρίως βελτίωση usability, αλλά διευκολύνουν επίσης την αναγνώριση του feature σε documentation, test harnesses και runtime wrappers.

## Χρήση Runtime

Τα time namespaces είναι νεότερα και χρησιμοποιούνται λιγότερο καθολικά από τα mount ή PID namespaces. Το OCI Runtime Specification v1.1 πρόσθεσε explicit support για το `time` namespace και το πεδίο `linux.timeOffsets`, ενώ τα σύγχρονα runtimes μπορούν να αντιστοιχίσουν αυτά τα δεδομένα στη διαδικασία bootstrap του kernel. Ένα minimal OCI fragment είναι το εξής:
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
Αυτό έχει σημασία επειδή μετατρέπει το time namespacing από ένα niche kernel primitive σε κάτι που τα runtimes μπορούν να ζητούν με portable τρόπο. Εξηγεί επίσης γιατί τα runtime internals χρειάζονται ένα explicit synchronization step: το offset πρέπει να γραφτεί στο `/proc/<pid>/timens_offsets` πριν το container payload εισέλθει πλήρως στο νέο namespace.

Stacks για checkpoint/restore, όπως το CRIU, είναι ένας από τους βασικούς λόγους ύπαρξης αυτής της δυνατότητας. Χωρίς time namespaces, η επαναφορά ενός paused workload θα έκανε τα monotonic και boot-time clocks να μεταπηδούν κατά το χρονικό διάστημα που το workload παρέμεινε suspended.

## Επίδραση στην Ασφάλεια

Υπάρχουν λιγότερες κλασικές ιστορίες breakout που επικεντρώνονται στο time namespace απ' ό,τι σε άλλους τύπους namespace. Ο κίνδυνος εδώ συνήθως δεν είναι ότι το time namespace επιτρέπει άμεσα escape, αλλά ότι οι αναγνώστες το αγνοούν εντελώς και επομένως δεν αντιλαμβάνονται πώς τα advanced runtimes μπορεί να διαμορφώνουν τη συμπεριφορά των processes.

Σε specialized environments, οι τροποποιημένες monotonic ή boottime views μπορούν να επηρεάσουν:

- τη συμπεριφορά των timeouts και των retries
- τα watchdogs και τη lease logic
- τη συμπεριφορά των `timerfd`, `nanosleep` και `clock_nanosleep`
- το checkpoint/restore forensics
- τα elapsed-time telemetry και τα uptime-based heuristics

Επομένως, παρότι αυτό σπάνια είναι το πρώτο namespace που θα κάνετε abuse, μπορεί σίγουρα να εξηγεί "impossible" timing behavior κατά τη διάρκεια ενός assessment.

## Κατάχρηση

Συνήθως δεν υπάρχει εδώ κάποιο direct breakout primitive, όμως η τροποποιημένη συμπεριφορά των clocks μπορεί να είναι χρήσιμη για την κατανόηση του execution environment, τον εντοπισμό advanced runtime features και τον εντοπισμό timer-based logic που μετράται με βάση monotonic clocks αντί για wall clock time:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Εάν συγκρίνετε δύο processes, οι διαφορές εδώ μπορούν να βοηθήσουν στην εξήγηση ασυνήθιστης συμπεριφοράς χρονισμού, artifacts από checkpoint/restore ή mismatches στο logging που εξαρτώνται από το environment.

Πρακτικές οπτικές σχετικές με attacker:

- να προκαλέσουν σύγχυση σε backoff, sleep ή watchdog logic που υλοποιείται με monotonic clocks
- να εξηγήσουν γιατί το `/proc/uptime` και η συμπεριφορά που καθοδηγείται από timers διαφωνούν με τις προσδοκίες του host-side wall-clock
- να αναγνωρίσουν workflows CRIU/checkpoint-restore και άλλα advanced runtime features
- να εντοπίσουν environments όπου η σύνδεση σε ένα target time namespace με `nsenter -T -t <pid> -- ...` μπορεί να αναπαράγει τη container-local συμπεριφορά των timers για debugging ή post-exploitation

Επίπτωση:

- σχεδόν πάντα reconnaissance ή κατανόηση του environment
- χρήσιμο για την εξήγηση anomalies σε logging, uptime ή checkpoint/restore
- χρήσιμο για την ανάλυση sleeps, retries και timers που βασίζονται σε monotonic time
- συνήθως δεν αποτελεί από μόνο του άμεσο container-escape mechanism

Η σημαντική λεπτομέρεια σχετικά με την κατάχρηση είναι ότι τα time namespaces δεν virtualize το `CLOCK_REALTIME`, επομένως από μόνα τους δεν επιτρέπουν σε έναν attacker να παραποιήσει το host wall clock ή να παρακάμψει άμεσα τους ελέγχους λήξης certificates σε ολόκληρο το system. Η αξία τους αφορά κυρίως τη σύγχυση logic που βασίζεται σε monotonic time, την αναπαραγωγή bugs που εξαρτώνται από το environment ή την κατανόηση advanced runtime behavior.

## Checks

Αυτοί οι έλεγχοι αφορούν κυρίως την επιβεβαίωση του αν το runtime χρησιμοποιεί private time namespace και του αν έχει πράγματι ορίσει nonzero offsets.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
Τι είναι ενδιαφέρον εδώ:

- Σε πολλά περιβάλλοντα, αυτές οι τιμές δεν θα οδηγήσουν σε άμεσο security finding, αλλά δείχνουν αν χρησιμοποιείται κάποια εξειδικευμένη runtime δυνατότητα.
- Αν το `time_for_children` διαφέρει από το `time`, ο caller ενδέχεται να έχει προετοιμάσει ένα time namespace μόνο για child processes, στο οποίο δεν έχει εισέλθει ο ίδιος.
- Αν το `date` ταιριάζει με το host, αλλά οι τιμές που βασίζονται σε monotonic/boottime διαφέρουν, πιθανότατα εξετάζετε time namespacing και όχι παραποίηση του wall clock.
- Αν συγκρίνετε δύο processes, οι διαφορές εδώ μπορεί να εξηγούν συγκεχυμένη συμπεριφορά σε θέματα timing ή checkpoint/restore.

Για τα περισσότερα container breakouts, το time namespace δεν είναι ο πρώτος μηχανισμός που θα διερευνήσετε. Παρ' όλα αυτά, μια πλήρης ενότητα για την ασφάλεια των containers θα πρέπει να το αναφέρει, επειδή αποτελεί μέρος του σύγχρονου kernel model και περιστασιακά έχει σημασία σε advanced runtime scenarios.

## Αναφορές

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
