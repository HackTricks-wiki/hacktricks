# Namespace Χρόνου

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το time namespace εικονικοποιεί επιλεγμένα ρολόγια μονοτονικού τύπου αντί για το wall clock του host. Στην πράξη, αυτό σημαίνει ιδιωτικά offsets για τα **`CLOCK_MONOTONIC`** και **`CLOCK_BOOTTIME`**, καθώς και για τις στενά σχετιζόμενες προβολές **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** και **`CLOCK_BOOTTIME_ALARM`**. Δεν εικονικοποιεί το **`CLOCK_REALTIME`**, επομένως τα `date` και η λογική λήξης πιστοποιητικών εξακολουθούν να παρατηρούν το wall clock του host, εκτός αν παρεμβαίνει κάποιος άλλος μηχανισμός.<sup>[[1]](#references)</sup>

Ο κύριος σκοπός του είναι να επιτρέπει σε μια διεργασία να παρατηρεί ελεγχόμενα offsets του elapsed time χωρίς να αλλάζει τη συνολική προβολή χρόνου του host. Αυτό είναι χρήσιμο για workflows checkpoint/restore, deterministic testing και προηγμένες συμπεριφορές runtime. Συνήθως δεν αποτελεί βασικό μηχανισμό isolation, όπως τα mount ή user namespaces, αλλά εξακολουθεί να συμβάλλει στο να γίνεται το περιβάλλον της διεργασίας πιο self-contained.

Από offensive point of view, αυτό το namespace είναι συνήθως πιο σχετικό με **reconnaissance, timer skew και κατανόηση του runtime** παρά με ένα άμεσο breakout. Ωστόσο, έχει σημασία επειδή όλο και περισσότερα container runtimes και workflows checkpoint/restore μπορούν πλέον να το ζητήσουν ρητά.

## Lab

Αν το kernel του host και το userspace το υποστηρίζουν, μπορείτε να επιθεωρήσετε το namespace με:
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

Τα time namespaces είναι ελαφρώς ασυνήθιστα σε σύγκριση με τα mount, PID ή network namespaces:<sup>[[1]](#references)</sup>

- Το `unshare(CLONE_NEWTIME)` δημιουργεί ένα νέο time namespace για **μελλοντικά children**.
- Το task που εκτελεί την κλήση παραμένει στο τρέχον time namespace του.
- Επομένως, το `/proc/<pid>/ns/time_for_children` είναι συχνά πιο ενδιαφέρον από το `/proc/<pid>/ns/time` κατά το debugging του runtime setup.

Το write window είναι επίσης ιδιαίτερο. Τα offsets στο `/proc/<pid>/timens_offsets` πρέπει να εγγραφούν πριν το νέο time namespace γεμίσει πλήρως με running tasks· στην πράξη, τα runtimes το κάνουν κατά το στενό setup window μεταξύ της δημιουργίας του namespace και της εκκίνησης του τελικού payload. Μόλις εκτελείται ήδη κάποιο task εκεί, οι μεταγενέστερες εγγραφές αποτυγχάνουν με `EACCES`. Αυτός είναι ο λόγος για τον οποίο τα low-level runtimes χειρίζονται το time-namespace setup ως πρώιμο bootstrap step, αντί να προσπαθούν να τροποποιήσουν τα offsets μέσα από μια ήδη εκκινημένη container process.<sup>[[1]](#references)</sup>

### Time Offsets

Τα Linux time namespaces εκθέτουν τα per-namespace offsets μέσω του `/proc/<pid>/timens_offsets`. Η μορφή είναι ένα σύνολο από clock names ή IDs, μαζί με deltas δευτερολέπτων/νανοδευτερολέπτων σε σχέση με το initial time namespace.<sup>[[1]](#references)</sup>

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

### Σημαίες βοηθητικού προγράμματος `unshare`

Οι πρόσφατες εκδόσεις του `util-linux` παρέχουν flags ευκολίας που γράφουν αυτόματα τα offsets κατά τη δημιουργία του namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Αυτά τα flags αποτελούν κυρίως βελτίωση στη χρηστικότητα, αλλά διευκολύνουν επίσης την αναγνώριση του feature σε documentation, test harnesses και runtime wrappers.

## Χρήση κατά το Runtime

Τα Time namespaces είναι νεότερα και χρησιμοποιούνται λιγότερο καθολικά σε σχέση με τα mount ή PID namespaces. Το OCI Runtime Specification v1.1 πρόσθεσε ρητή υποστήριξη για το `time` namespace και το πεδίο `linux.timeOffsets`, ενώ τα σύγχρονα runtimes μπορούν να αντιστοιχίσουν αυτά τα δεδομένα στη διαδικασία bootstrap του kernel. Ένα ελάχιστο OCI απόσπασμα μοιάζει ως εξής:
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
Αυτό έχει σημασία επειδή μετατρέπει το time namespacing από μια εξειδικευμένη primitive του kernel σε κάτι που τα runtimes μπορούν να ζητούν με portable τρόπο. Εξηγεί επίσης γιατί τα internals των runtimes χρειάζονται ένα ρητό βήμα συγχρονισμού: το offset πρέπει να γραφτεί στο `/proc/<pid>/timens_offsets` πριν το payload του container εισέλθει πλήρως στο νέο namespace.

Stacks για checkpoint/restore, όπως το CRIU, είναι ένας από τους κύριους λόγους ύπαρξης αυτής της δυνατότητας στην πράξη. Χωρίς time namespaces, η επαναφορά ενός paused workload θα προκαλούσε άλμα στα monotonic και boot-time clocks κατά το χρονικό διάστημα που το workload παρέμεινε σε αναστολή.<sup>[[2]](#references)</sup>

## Επιπτώσεις Ασφαλείας

Υπάρχουν λιγότερες κλασικές ιστορίες breakout που επικεντρώνονται στο time namespace σε σχέση με άλλους τύπους namespaces. Ο κίνδυνος εδώ συνήθως δεν είναι ότι το time namespace επιτρέπει άμεσα escape, αλλά ότι οι αναλυτές το αγνοούν εντελώς και έτσι δεν αντιλαμβάνονται πώς τα advanced runtimes μπορεί να διαμορφώνουν τη συμπεριφορά των processes.

Σε εξειδικευμένα περιβάλλοντα, τροποποιημένες monotonic ή boottime views μπορούν να επηρεάσουν:

- τη συμπεριφορά των timeouts και των retries
- τα watchdogs και τη λογική των leases
- τη συμπεριφορά των `timerfd`, `nanosleep` και `clock_nanosleep`
- τα forensics του checkpoint/restore
- το telemetry του elapsed time και τα heuristics που βασίζονται στο uptime

Επομένως, παρότι αυτό σπάνια είναι το πρώτο namespace που θα κάνετε abuse, μπορεί να εξηγήσει πλήρως "impossible" συμπεριφορά χρονισμού κατά τη διάρκεια ενός assessment.

## Κατάχρηση

Συνήθως δεν υπάρχει εδώ κάποιο άμεσο breakout primitive, όμως η τροποποιημένη συμπεριφορά των clocks μπορεί να είναι χρήσιμη για την κατανόηση του execution environment, τον εντοπισμό advanced runtime features και την ανίχνευση logic που βασίζεται σε timers και μετράται σε σχέση με monotonic clocks αντί για wall clock time:
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
Αν συγκρίνετε δύο processes, οι διαφορές εδώ μπορούν να βοηθήσουν στην εξήγηση ασυνήθιστης συμπεριφοράς χρονισμού, artifacts από checkpoint/restore ή mismatches σε logging που εξαρτώνται από το environment.

Πρακτικές οπτικές που σχετίζονται με attackers:

- να προκαλέσουν σύγχυση σε backoff, sleep ή watchdog logic που υλοποιείται με monotonic clocks
- να εξηγήσουν γιατί το `/proc/uptime` και η συμπεριφορά που βασίζεται σε timers διαφωνούν με τις προσδοκίες για το wall-clock του host
- να αναγνωρίσουν workflows CRIU/checkpoint-restore και άλλα advanced runtime features
- να εντοπίσουν environments στα οποία η σύνδεση σε ένα target time namespace με `nsenter -T -t <pid> -- ...` μπορεί να αναπαράγει τη συμπεριφορά των container-local timers για debugging ή post-exploitation

Επίπτωση:

- σχεδόν πάντα αφορά reconnaissance ή κατανόηση του environment
- χρήσιμο για την εξήγηση anomalies σε logging, uptime ή checkpoint/restore
- χρήσιμο για την ανάλυση sleeps, retries και timers που βασίζονται σε monotonic time
- συνήθως δεν αποτελεί από μόνο του άμεσο μηχανισμό container escape

Η σημαντική λεπτομέρεια σχετικά με το abuse είναι ότι τα time namespaces δεν virtualize-άρουν το `CLOCK_REALTIME`, επομένως από μόνα τους δεν επιτρέπουν σε έναν attacker να παραποιήσει το wall clock του host ή να παρακάμψει άμεσα τους ελέγχους certificate-expiry σε ολόκληρο το system. Η αξία τους αφορά κυρίως τη σύγχυση logic που βασίζεται σε monotonic time, την αναπαραγωγή bugs που εξαρτώνται από το environment ή την κατανόηση advanced runtime behavior.

## Έλεγχοι

Αυτοί οι έλεγχοι αφορούν κυρίως την επιβεβαίωση του αν το runtime χρησιμοποιεί private time namespace και του αν έχει ορίσει πράγματι nonzero offsets.
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

- Σε πολλά περιβάλλοντα, αυτές οι τιμές δεν θα οδηγήσουν σε άμεσο security finding, αλλά δείχνουν αν χρησιμοποιείται κάποια εξειδικευμένη δυνατότητα του runtime.
- Αν το `time_for_children` διαφέρει από το `time`, ο caller ενδέχεται να έχει προετοιμάσει ένα time namespace μόνο για child processes, στο οποίο δεν έχει εισέλθει ο ίδιος.
- Αν το `date` ταιριάζει με το host, αλλά οι τιμές που βασίζονται σε monotonic/boottime διαφέρουν, πιθανότατα εξετάζετε time namespacing και όχι παραποίηση του wall-clock.
- Αν συγκρίνετε δύο processes, οι διαφορές εδώ μπορεί να εξηγούν συγκεχυμένη συμπεριφορά σχετικά με τον χρόνο ή το checkpoint/restore.

Για τα περισσότερα container breakouts, το time namespace δεν είναι ο πρώτος μηχανισμός που θα εξετάσετε. Ωστόσο, μια πλήρης ενότητα για την ασφάλεια των containers θα πρέπει να το αναφέρει, επειδή αποτελεί μέρος του σύγχρονου μοντέλου του kernel και περιστασιακά έχει σημασία σε advanced runtime scenarios.

## Αναφορές

- [1] [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Per-Container Clock Offsets for CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
