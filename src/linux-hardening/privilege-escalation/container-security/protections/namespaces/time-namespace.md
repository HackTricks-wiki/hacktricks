# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Το time namespace εικονικοποιεί επιλεγμένα monotonic-style clocks αντί για το host wall clock. Στην πράξη αυτό σημαίνει ιδιωτικά offsets για **`CLOCK_MONOTONIC`** και **`CLOCK_BOOTTIME`**, μαζί με τα στενά συγγενικά **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`**, και **`CLOCK_BOOTTIME_ALARM`** views. Δεν εικονικοποιεί το **`CLOCK_REALTIME`**, οπότε το `date` και η λογική λήξης πιστοποιητικών εξακολουθούν να βλέπουν το host wall clock εκτός αν παρεμβαίνει κάποιο άλλο mechanism.

Ο κύριος σκοπός είναι να επιτρέπει σε μια process να παρατηρεί ελεγχόμενα elapsed-time offsets χωρίς να αλλάζει το global time view του host. Αυτό είναι χρήσιμο για checkpoint/restore workflows, deterministic testing, και advanced runtime behavior. Συνήθως δεν είναι βασικός control απομόνωσης με τον ίδιο τρόπο όπως τα mount ή user namespaces, αλλά εξακολουθεί να συμβάλλει στο να γίνεται το process environment πιο self-contained.

Από offensive άποψη, αυτό το namespace είναι συνήθως πιο σχετικό για **reconnaissance, timer skew, και runtime understanding** παρά για ένα άμεσο breakout. Παρ’ όλα αυτά, έχει σημασία επειδή περισσότεροι container runtimes και checkpoint/restore workflows μπορούν πλέον να το ζητήσουν ρητά.

## Lab

Αν το host kernel και το userspace το υποστηρίζουν, μπορείτε να επιθεωρήσετε το namespace με:
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
Η υποστήριξη διαφέρει ανάλογα με το kernel και τις εκδόσεις των εργαλείων, οπότε αυτή η σελίδα αφορά περισσότερο την κατανόηση του μηχανισμού παρά το να περιμένεις ότι θα είναι ορατός σε κάθε lab environment. Η σημαντική παρατήρηση είναι ότι το `date` θα πρέπει να συνεχίζει να αντανακλά το wall clock του host, ενώ οι τιμές βασισμένες σε monotonic/boottime είναι αυτές που αλλάζουν όταν έχουν ρυθμιστεί μη μηδενικά offsets.

### Nuance Δημιουργίας

Τα Time namespaces είναι λίγο ασυνήθιστα σε σύγκριση με mount, PID ή network namespaces:

- Το `unshare(CLONE_NEWTIME)` δημιουργεί ένα νέο time namespace για μελλοντικά παιδιά.
- Η διεργασία που το καλεί παραμένει στο τρέχον time namespace της.
- Το `/proc/<pid>/ns/time_for_children` είναι επομένως συχνά πιο ενδιαφέρον από το `/proc/<pid>/ns/time` όταν κάνεις debugging στο runtime setup.

Το write window είναι επίσης ειδικό. Τα offsets στο `/proc/<pid>/timens_offsets` πρέπει να γραφτούν πριν το νέο time namespace γεμίσει πλήρως με running tasks· στην πράξη, τα runtimes το κάνουν αυτό κατά το στενό setup window ανάμεσα στη δημιουργία του namespace και την εκκίνηση του τελικού payload. Μόλις μια διεργασία τρέχει ήδη εκεί, τα μεταγενέστερα writes αποτυγχάνουν με `EACCES`. Γι' αυτό τα low-level runtimes χειρίζονται το setup του time-namespace ως πρώιμο bootstrap βήμα αντί να προσπαθούν να κάνουν patch τα offsets από μέσα σε ένα container process που έχει ήδη ξεκινήσει.

### Time Offsets

Τα Linux time namespaces εκθέτουν τα per-namespace offsets μέσω του `/proc/<pid>/timens_offsets`. Η μορφή είναι ένα σύνολο από clock names ή IDs μαζί με second/nanosecond deltas σε σχέση με το initial time namespace.

Στην πράξη, το πιο αξιόπιστο user-facing workflow είναι να αφήσεις το `unshare` να γράψει αυτά τα offsets για εσένα:
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
Το σημαντικό σημείο δεν είναι η ακριβής σύνταξη της εντολής αλλά η συμπεριφορά: ένα container μπορεί να παρατηρήσει μια διαφορετική, τύπου uptime, προβολή χωρίς να αλλάξει το wall clock του host.

### `unshare` Helper Flags

Πρόσφατες εκδόσεις του `util-linux` παρέχουν flags ευκολίας που γράφουν αυτόματα τα offsets κατά τη δημιουργία του namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Αυτά τα flags είναι κυρίως βελτίωση χρηστικότητας, αλλά επίσης κάνουν ευκολότερη την αναγνώριση του feature σε documentation, test harnesses και runtime wrappers.

## Runtime Usage

Τα Time namespaces είναι νεότερα και λιγότερο καθολικά χρησιμοποιούμενα από τα mount ή PID namespaces. Η OCI Runtime Specification v1.1 πρόσθεσε ρητή υποστήριξη για το `time` namespace και το `linux.timeOffsets` field, και τα σύγχρονα runtimes μπορούν να αντιστοιχίσουν αυτά τα δεδομένα στη ροή bootstrap του kernel. Ένα ελάχιστο OCI fragment μοιάζει ως εξής:
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
Αυτό έχει σημασία επειδή μετατρέπει το time namespacing από ένα εξειδικευμένο kernel primitive σε κάτι που τα runtimes μπορούν να ζητήσουν με φορητό τρόπο. Επίσης εξηγεί γιατί τα internals του runtime χρειάζονται ένα explicit synchronization step: το offset πρέπει να γραφτεί στο `/proc/<pid>/timens_offsets` πριν το container payload εισέλθει πλήρως στο νέο namespace.

Checkpoint/restore stacks όπως το CRIU είναι ένας από τους κύριους πραγματικούς λόγους που αυτό υπάρχει καν. Χωρίς time namespaces, η επαναφορά ενός paused workload θα έκανε τα monotonic και boot-time clocks να πηδήξουν κατά το χρονικό διάστημα που το workload πέρασε suspended.

## Security Impact

Υπάρχουν λιγότερες κλασικές breakout ιστορίες που επικεντρώνονται στο time namespace από ό,τι σε άλλους τύπους namespace. Ο κίνδυνος εδώ συνήθως δεν είναι ότι το time namespace επιτρέπει άμεσα escape, αλλά ότι οι αναγνώστες το αγνοούν εντελώς και έτσι χάνουν το πώς τα advanced runtimes μπορεί να διαμορφώνουν τη συμπεριφορά των processes.

Σε εξειδικευμένα περιβάλλοντα, οι αλλοιωμένες monotonic ή boottime προβολές μπορούν να επηρεάσουν:

- timeout και retry συμπεριφορά
- watchdogs και lease logic
- συμπεριφορά των `timerfd`, `nanosleep`, και `clock_nanosleep`
- checkpoint/restore forensics
- telemetry elapsed-time και heuristics βασισμένα στο uptime

Άρα, παρότι σπάνια είναι το πρώτο namespace που θα abuse-άρεις, μπορεί απολύτως να εξηγήσει "αδύνατη" χρονική συμπεριφορά κατά τη διάρκεια μιας assessment.

## Abuse

Συνήθως δεν υπάρχει εδώ direct breakout primitive, αλλά η αλλοιωμένη συμπεριφορά του clock μπορεί παρ' όλα αυτά να είναι χρήσιμη για να κατανοήσεις το execution environment, να εντοπίσεις advanced runtime features, και να εντοπίσεις timer-based logic που μετριέται έναντι monotonic clocks αντί για wall clock time:
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
Εάν συγκρίνεις δύο processes, οι διαφορές εδώ μπορούν να βοηθήσουν να εξηγηθούν περίεργη χρονική συμπεριφορά, checkpoint/restore artifacts ή ασυμφωνίες σε environment-specific logging.

Πρακτικές attacker-relevant γωνίες:

- confuse backoff, sleep, ή watchdog logic που υλοποιείται με monotonic clocks
- εξήγησε γιατί το `/proc/uptime` και η συμπεριφορά που καθοδηγείται από timers διαφωνούν με τις host-side wall-clock προσδοκίες
- αναγνώρισε CRIU/checkpoint-restore workflows και άλλα advanced runtime features
- εντόπισε environments όπου το να ενωθείς με ένα target time namespace με `nsenter -T -t <pid> -- ...` μπορεί να αναπαράγει container-local timer συμπεριφορά για debugging ή post-exploitation

Impact:

- σχεδόν πάντα reconnaissance ή κατανόηση του environment
- χρήσιμο για να εξηγηθούν logging, uptime ή checkpoint/restore anomalies
- χρήσιμο για την ανάλυση monotonic-time-based sleeps, retries, και timers
- συνήθως δεν είναι από μόνο του direct container-escape mechanism

Η σημαντική nuance κατάχρησης είναι ότι τα time namespaces δεν virtualize το `CLOCK_REALTIME`, οπότε δεν επιτρέπουν από μόνα τους σε έναν attacker να falsify το host wall clock ή να σπάσει άμεσα certificate-expiry checks σε όλο το σύστημα. Η αξία τους είναι κυρίως στο να confuses monotonic-time-based logic, να αναπαράγουν environment-specific bugs ή να κατανοούν advanced runtime συμπεριφορά.

## Checks

Αυτά τα checks αφορούν κυρίως το αν το runtime χρησιμοποιεί καθόλου private time namespace και αν όντως έχει ορίσει nonzero offsets.
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

- Σε πολλά περιβάλλοντα αυτές οι τιμές δεν θα οδηγήσουν σε άμεσο security finding, αλλά δείχνουν αν χρησιμοποιείται ένα εξειδικευμένο runtime feature.
- Αν το `time_for_children` διαφέρει από το `time`, ο caller μπορεί να έχει προετοιμάσει ένα child-only time namespace στο οποίο δεν έχει μπει ο ίδιος.
- Αν το `date` ταιριάζει με το host αλλά οι τιμές monotonic/boottime-based δεν ταιριάζουν, πιθανότατα βλέπεις time namespacing αντί για wall-clock tampering.
- Αν συγκρίνεις δύο processes, οι διαφορές εδώ μπορεί να εξηγήσουν confusing timing ή checkpoint/restore behavior.

Για τα περισσότερα container breakouts, το time namespace δεν είναι το πρώτο control που θα εξετάσεις. Παρ’ όλα αυτά, ένα πλήρες container-security section θα πρέπει να το αναφέρει επειδή είναι μέρος του σύγχρονου kernel model και περιστασιακά έχει σημασία σε advanced runtime scenarios.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
