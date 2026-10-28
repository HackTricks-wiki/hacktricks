# Namespace PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το namespace PID ελέγχει τον τρόπο αρίθμησης των διεργασιών και ποιες διεργασίες είναι ορατές. Γι’ αυτό ένα container μπορεί να έχει το δικό του PID 1, παρότι δεν είναι πραγματικό μηχάνημα. Μέσα στο namespace, το workload βλέπει κάτι που μοιάζει με τοπικό δέντρο διεργασιών. Έξω από το namespace, ο host εξακολουθεί να βλέπει τα πραγματικά PID του host και ολόκληρο το τοπίο διεργασιών.<sup>[[3]](#references)</sup>

Από άποψη ασφάλειας, το namespace PID έχει σημασία επειδή η ορατότητα των διεργασιών είναι πολύτιμη. Αν ένα workload μπορεί να δει διεργασίες του host, ενδέχεται να παρατηρήσει ονόματα υπηρεσιών, ορίσματα γραμμής εντολών, μυστικά που περνούν ως ορίσματα διεργασιών, κατάσταση που προκύπτει από το περιβάλλον μέσω του `/proc` και πιθανούς στόχους εισόδου σε namespace. Αν μπορεί να κάνει περισσότερα από το να βλέπει απλώς αυτές τις διεργασίες —για παράδειγμα, να στέλνει σήματα ή να χρησιμοποιεί ptrace υπό τις κατάλληλες συνθήκες— το πρόβλημα γίνεται πολύ σοβαρότερο.

## Λειτουργία

Ένα νέο namespace PID ξεκινά με τη δική του εσωτερική αρίθμηση διεργασιών. Η πρώτη διεργασία που δημιουργείται μέσα σε αυτό γίνεται PID 1 από τη σκοπιά του namespace, πράγμα που σημαίνει επίσης ότι αποκτά ειδική σημασιολογία τύπου init για ορφανά παιδιά και τη συμπεριφορά των σημάτων. Αυτό εξηγεί πολλές ιδιομορφίες των container σχετικά με τις διεργασίες init, την αποκομιδή zombie και τον λόγο που μερικές φορές χρησιμοποιούνται μικρά wrappers init σε container.<sup>[[3]](#references)</sup>

Τα namespace PID σχηματίζουν ιεραρχία. Μια διεργασία σε πρόγονο namespace μπορεί να προσπελάσει απογόνους χρησιμοποιώντας το PID που έχει εκχωρηθεί σε αυτόν τον πρόγονο, αλλά ένας απόγονος δεν μπορεί να προσπελάσει εργασίες που υπάρχουν μόνο σε πρόγονο μέσω συνηθισμένων κλήσεων συστήματος που βασίζονται σε PID ή να χρησιμοποιήσει `setns()` για να ανέβει σε πρόγονο namespace PID. Ένα procfs που ανήκει σε πρόγονο και έχει εκτεθεί σκόπιμα στον απόγονο μπορεί και πάλι να διαρρεύσει την εικόνα των διεργασιών του προγόνου. Επίσης, η είσοδος σε ένα namespace PID με `setns()` αλλάζει το namespace για **τα μελλοντικά παιδιά**, όχι για την ίδια την καλούσα διεργασία· γι’ αυτό τα εργαλεία κάνουν fork μετά την είσοδο. Ένα mount procfs διατηρεί την εικόνα PID της διεργασίας που το έκανε mount, γι’ αυτό η δημιουργία νέου procfs μετά από `unshare(CLONE_NEWPID)` είναι σημαντική για την ασφάλεια και όχι απλώς αισθητική.<sup>[[3]](#references)</sup>

Το σημαντικό δίδαγμα για την ασφάλεια είναι ότι μια διεργασία μπορεί να φαίνεται απομονωμένη επειδή βλέπει μόνο το δικό της δέντρο PID, αλλά αυτή η απομόνωση μπορεί να αρθεί σκόπιμα. Το Docker το παρέχει μέσω του `--pid=host`, ενώ το Kubernetes το κάνει μέσω του `hostPID: true`. Μόλις το container ενταχθεί στο namespace PID του host, το workload βλέπει απευθείας τις διεργασίες του host και πολλές επόμενες διαδρομές επίθεσης γίνονται πολύ πιο ρεαλιστικές.

## Εργαστήριο

Για να δημιουργήσετε χειροκίνητα ένα namespace PID:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

Το shell βλέπει πλέον μια ιδιωτική προβολή διεργασιών. Η σημαία `--mount-proc` είναι σημαντική, επειδή προσαρτά ένα στιγμιότυπο procfs που αντιστοιχεί στο νέο PID namespace, κάνοντας τη λίστα διεργασιών συνεπή από το εσωτερικό.<sup>[[3]](#references)</sup>

Για να συγκρίνετε τη συμπεριφορά των containers:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

Η διαφορά είναι άμεση και εύκολα κατανοητή, γι’ αυτό αποτελεί ένα καλό πρώτο lab για τους αναγνώστες.

## Χρήση κατά το runtime

Τα συνηθισμένα containers σε Docker, Podman, containerd και CRI-O αποκτούν το δικό τους PID namespace. Τα containers στο Kubernetes έχουν συνήθως ξεχωριστές προβολές PID· η ρύθμιση `shareProcessNamespace: true` δημιουργεί σκόπιμα μία κοινή προβολή για ολόκληρο το Pod.<sup>[[4]](#references)</sup> Αντίθετα, η ρύθμιση `hostPID: true` επιλέγει το PID namespace του κόμβου. Τα περιβάλλοντα LXC/Incus βασίζονται στην ίδια primitive του kernel, αν και οι περιπτώσεις χρήσης system-container μπορεί να εκθέτουν πιο περίπλοκα process trees και να ενθαρρύνουν περισσότερες συντομεύσεις για debugging.

Ο ίδιος κανόνας ισχύει παντού: αν το runtime επέλεξε να μην απομονώσει το PID namespace, αυτό αποτελεί σκόπιμη μείωση του ορίου ασφαλείας του container.

## Λανθασμένες ρυθμίσεις

Η χαρακτηριστική λανθασμένη ρύθμιση είναι η κοινή χρήση του PID namespace του host. Οι ομάδες συχνά τη δικαιολογούν για λόγους debugging, monitoring ή ευκολίας στη διαχείριση υπηρεσιών, αλλά πρέπει πάντα να αντιμετωπίζεται ως ουσιαστική εξαίρεση ασφαλείας. Ακόμη κι αν το container δεν διαθέτει άμεσα primitive εγγραφής στις διεργασίες του host, η ορατότητα από μόνη της μπορεί να αποκαλύψει πολλά για το σύστημα. Αν προστεθούν capabilities όπως το `CAP_SYS_PTRACE` ή χρήσιμη πρόσβαση στο procfs, ο κίνδυνος αυξάνεται σημαντικά.

Ένα άλλο λάθος είναι η υπόθεση ότι, επειδή το workload δεν μπορεί από προεπιλογή να τερματίσει διεργασίες του host ή να χρησιμοποιήσει ptrace σε αυτές, η κοινή χρήση του PID namespace του host είναι ακίνδυνη. Αυτό το συμπέρασμα αγνοεί την αξία της απαρίθμησης, τη διαθεσιμότητα στόχων για είσοδο σε namespace και τον τρόπο με τον οποίο η ορατότητα PID συνδυάζεται με άλλους αποδυναμωμένους ελέγχους.

### Κοινή χρήση διεργασιών σε επίπεδο Pod στο Kubernetes

Η ρύθμιση `shareProcessNamespace: true` διαφέρει από το `hostPID`: εκθέτει τις διεργασίες των **άλλων containers στο ίδιο Pod**, όχι τις διεργασίες του κόμβου. Έτσι, ένα παραβιασμένο sidecar ή debug container μπορεί να απαριθμεί τις γραμμές εντολών και τα δεδομένα περιβάλλοντος των sibling containers, με την επιφύλαξη των ελέγχων πρόσβασης του procfs, να στέλνει σήματα όταν το επιτρέπουν τα διαπιστευτήρια και να περιηγείται στο filesystem ενός sibling μέσω του `/proc/<pid>/root`. Το Kubernetes προειδοποιεί ρητά ότι, σε αυτή την περίπτωση, τα secrets της γραμμής εντολών και του περιβάλλοντος, καθώς και τα filesystems των containers, προστατεύονται μόνο από τα ισχύοντα Unix permissions.<sup>[[4]](#references)</sup>

Χρήσιμος έλεγχος από την πλευρά του cluster:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Από ένα παραβιασμένο container σε ένα PID namespace σε επίπεδο Pod, ελέγξτε πρώτα την πραγματική πρόσβαση αντί να υποθέτετε ότι η ορατότητα ισοδυναμεί με αναγνωσιμότητα:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### Στοχευμένα ephemeral containers σε υπάρχον Kubernetes Pod

Μια ταυτότητα Kubernetes με δικαίωμα τροποποίησης του `pods/ephemeralcontainers` μπορεί να προσθέσει ένα debugger σε ένα Pod που εκτελείται, ακόμη κι αν το `shareProcessNamespace` δεν έχει οριστεί. Με το `--target`, το debugger συμμετέχει στο process namespace του κατονομαζόμενου container, αν το runtime υποστηρίζει targeting namespaces. Αυτό παρέχει ορατότητα στις διεργασίες αυτού του container, όχι στο host PID namespace του node.<sup>[[5]](#references)</sup>

Το API χρησιμοποιεί ξεχωριστό subresource, οπότε ελέγξτε τα δικαιώματα `patch`/`update` αντί να υποθέσετε ότι καλύπτεται από τα συνηθισμένα δικαιώματα εγγραφής στο Pod.<sup>[[6]](#references)</sup>

Για ένα Pod και container μέσα σε εξουσιοδοτημένο namespace, ελέγξτε τη στοχευμένη ορατότητα:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

Αν το runtime δεν υλοποιεί το targeting, ο debugger μπορεί να μην ξεκινήσει ή να παραμείνει σε απομονωμένο PID namespace.<sup>[[5]](#references)</sup> Αν το targeting λειτουργεί, χρησιμοποιήστε τους ελέγχους στην ενότητα [Kubernetes Pod-wide process sharing](#kubernetes-pod-wide-process-sharing) για να δοκιμάσετε την πρόσβαση στο `/proc/<pid>`. Η ορατότητα δεν συνεπάγεται άδεια ανάγνωσης των secrets του στόχου ή αποστολής σημάτων σε αυτόν: εξακολουθούν να ισχύουν τα δικαιώματα Unix και οι έλεγχοι πρόσβασης του procfs.<sup>[[4]](#references)[[8]](#references)</sup> Τα Pod Security Standards περιορίζουν επίσης τις ρυθμίσεις privileged στα ephemeral containers.<sup>[[7]](#references)</sup>

## Κατάχρηση

Αν είναι κοινόχρηστο το host PID namespace, ένας attacker μπορεί να επιθεωρήσει διεργασίες του host, να συλλέξει ορίσματα διεργασιών, να εντοπίσει ενδιαφέρουσες υπηρεσίες, να βρει υποψήφια PIDs για το `nsenter` ή να συνδυάσει την ορατότητα διεργασιών με προνόμια σχετικά με το ptrace, ώστε να παρέμβει σε workloads του host ή γειτονικών workloads. Σε ορισμένες περιπτώσεις, αρκεί να εντοπιστεί η σωστή διεργασία μακράς εκτέλεσης για να αλλάξει η υπόλοιπη στρατηγική επίθεσης.

Το πρώτο πρακτικό βήμα είναι πάντα να επιβεβαιώσετε ότι οι διεργασίες του host είναι πράγματι ορατές:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

Μόλις είναι ορατά τα host PIDs, τα ορίσματα διεργασιών και οι στόχοι εισόδου σε namespaces συχνά αποτελούν την πιο χρήσιμη πηγή πληροφοριών:

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

Αν το `nsenter` είναι διαθέσιμο και υπάρχουν επαρκή δικαιώματα, ελέγξτε αν μια ορατή διεργασία του host μπορεί να χρησιμοποιηθεί ως γέφυρα namespace:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

Ακόμα κι όταν η είσοδος είναι αποκλεισμένη, η κοινή χρήση των PID του host είναι ήδη χρήσιμη, επειδή αποκαλύπτει τη διάταξη των υπηρεσιών, τα στοιχεία του runtime και υποψήφιες privileged διεργασίες για επόμενο στόχο. Η ορατότητα των PID από μόνη της **δεν** παρέχει άδεια για αποστολή σημάτων, ιχνηλάτηση, ανάγνωση ευαίσθητων εγγραφών του `/proc/<pid>` ή ένταξη στα άλλα namespaces του στόχου· εξακολουθούν να έχουν σημασία τα credentials, η dumpability, τα capabilities στο user namespace που κατέχει το namespace του στόχου, η πολιτική Yama/LSM και το seccomp.<sup>[[3]](#references)</sup> Δείτε το [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) για παραδείγματα process-injection.

Η ορατότητα των PID του host κάνει επίσης πιο ρεαλιστική την κατάχρηση file descriptor. Αν μια privileged διεργασία του host ή ένα γειτονικό workload έχει ανοιχτό ένα ευαίσθητο αρχείο ή socket, ο επιτιθέμενος ενδέχεται να μπορεί να επιθεωρήσει το `/proc/<pid>/fd/` και να αποκτήσει πρόσβαση στο υποκείμενο αντικείμενο, ανάλογα με τους ελέγχους τύπου ptrace, την ιδιοκτησία, τις επιλογές προσάρτησης του procfs, τον τύπο του αντικειμένου και το μοντέλο της υπηρεσίας-στόχου. Η απλή εμφάνιση ενός συμβολικού συνδέσμου FD δεν σημαίνει ότι μπορεί να ανοιχτεί, και ένα socket δεν μπορεί να αντιγραφεί απλώς ανοίγοντας τον συμβολικό σύνδεσμό του `/proc/<pid>/fd/N`. Για το ξεχωριστό primitive `pidfd_getfd()` και τους ελέγχους εξουσιοδότησής του, δείτε το [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

Αυτές οι εντολές είναι χρήσιμες επειδή δείχνουν αν το `hidepid=1` ή το `hidepid=2` περιορίζει την ορατότητα μεταξύ διεργασιών και αν είναι ορατοί καθόλου προφανώς ενδιαφέροντες descriptors, όπως ανοιχτά αρχεία με μυστικά, logs ή Unix sockets.

### Πλήρες παράδειγμα: host PID + `nsenter`

Η κοινή χρήση host PID μπορεί να επιτρέψει host escape όταν η διεργασία διαθέτει τα απαιτούμενα capabilities για να εισέλθει στα host namespaces και να υιοθετήσει το root της διεργασίας του host. Για το τελευταίο απαιτείται το `nsenter --root` (`-r`): η αλλαγή μόνο του mount namespace δεν αλλάζει τον ριζικό κατάλογο του καλούντος.<sup>[[9]](#references)</sup> Η πρόσβαση στο `/proc/1/root` υπόκειται σε έλεγχο ανάγνωσης ptrace, ενώ για την αλλαγή του root απαιτείται `CAP_SYS_CHROOT` στο user namespace του καλούντος.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

Αν η εντολή εκτελεστεί με επιτυχία, το νέο shell χρησιμοποιεί τα mount, UTS, network, IPC και PID namespaces του host, καθώς και το root filesystem της διεργασίας PID 1. Ελέγξτε την πραγματική ταυτότητα και τα δικαιώματα πρόσβασης αντί να υποθέτετε ότι η ορατότητα των PID από μόνη της παρέχει προνόμια στο host.<sup>[[9]](#references)</sup>

Ακόμα κι αν λείπει το ίδιο το `nsenter`, μπορεί να επιτευχθεί το ίδιο αποτέλεσμα μέσω του binary του host, εφόσον είναι προσαρτημένο το filesystem του host:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### Πρόσφατες σημειώσεις για το runtime

Ορισμένες επιθέσεις που σχετίζονται με τα PID namespaces δεν οφείλονται σε παραδοσιακές εσφαλμένες ρυθμίσεις `hostPID: true`, αλλά σε σφάλματα υλοποίησης του runtime σχετικά με τον τρόπο εφαρμογής των προστασιών του procfs κατά τη ρύθμιση του container.

#### Race condition στο `maskedPaths` προς το host procfs

Σε ευάλωτες εκδόσεις του `runc`, επιτιθέμενοι που μπορούσαν να ελέγξουν το image του container ή το workload του `runc exec` μπορούσαν να εκμεταλλευτούν ένα race condition κατά τη φάση masking, αντικαθιστώντας το `/dev/null` στην πλευρά του container με ένα symlink προς μια ευαίσθητη διαδρομή procfs, όπως η `/proc/sys/kernel/core_pattern`. Αν το race condition πετύχαινε, το bind mount του masked path μπορούσε να εφαρμοστεί σε λάθος προορισμό και να εκθέσει καθολικές ρυθμίσεις του host στο νέο container.<sup>[[1]](#references)</sup>

Χρήσιμη εντολή για έλεγχο:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

Αυτό είναι σημαντικό, επειδή ο τελικός αντίκτυπος μπορεί να είναι ίδιος με την άμεση έκθεση του procfs: εγγράψιμα `core_pattern` ή `sysrq-trigger`, που ακολουθούνται από εκτέλεση κώδικα στο host ή άρνηση υπηρεσίας. Οι σελίδες [masked paths](../masked-paths.md) και [sensitive host mounts](../../sensitive-host-mounts.md) καλύπτουν τη γενική επιφάνεια επίθεσης του procfs χωρίς να την επαναλαμβάνουν εδώ.

#### Namespace injection με `insject`

Εργαλεία namespace injection όπως το `insject` δείχνουν ότι η αλληλεπίδραση με PID namespace δεν απαιτεί πάντα την είσοδο στο namespace-στόχο πριν από τη δημιουργία διεργασίας. Ένα βοηθητικό πρόγραμμα μπορεί να συνδεθεί αργότερα, να χρησιμοποιήσει `setns()` και να εκτελέσει κώδικα, διατηρώντας την ορατότητα στον χώρο PID του στόχου:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Αυτό το είδος τεχνικής είναι σημαντικό κυρίως για advanced debugging, offensive tooling και post-exploitation workflows, όπου το namespace context πρέπει να συνδεθεί αφού το runtime έχει ήδη αρχικοποιήσει το workload.

### Σχετικά μοτίβα κατάχρησης FD

Αξίζει να επισημανθούν ρητά δύο μοτίβα όταν είναι ορατά τα host PIDs. Πρώτον, μια privileged διεργασία μπορεί να διατηρήσει ανοιχτό ένα ευαίσθητο file descriptor μετά το `execve()`, επειδή δεν είχε επισημανθεί με `O_CLOEXEC`. Δεύτερον, οι υπηρεσίες μπορεί να μεταβιβάζουν file descriptors μέσω Unix sockets με `SCM_RIGHTS`. Και στις δύο περιπτώσεις, το ενδιαφέρον αντικείμενο δεν είναι πλέον το pathname, αλλά το ήδη ανοιχτό handle που μπορεί να κληρονομήσει ή να λάβει μια διεργασία με χαμηλότερα προνόμια.

Αυτό έχει σημασία σε εργασίες με containers, επειδή το handle μπορεί να δείχνει στο `docker.sock`, σε ένα privileged log, σε ένα host secret file ή σε άλλο αντικείμενο υψηλής αξίας, ακόμη κι όταν η διαδρομή δεν είναι άμεσα προσβάσιμη από το filesystem του container.

## Έλεγχοι

Σκοπός αυτών των εντολών είναι να διαπιστωθεί αν η διεργασία έχει ιδιωτική προβολή PID ή αν μπορεί ήδη να απαριθμήσει ένα πολύ ευρύτερο σύνολο διεργασιών.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

Τι είναι ενδιαφέρον εδώ:<sup>[[3]](#references)</sup>

- Αν η λίστα διεργασιών περιλαμβάνει προφανείς υπηρεσίες του host, πιθανότατα είναι ήδη ενεργοποιημένη η κοινή χρήση PID του host.
- Το να βλέπετε μόνο ένα μικρό δέντρο διεργασιών τοπικό στο container είναι το φυσιολογικό baseline· το να βλέπετε `systemd`, `dockerd` ή άσχετους daemons δεν είναι.
- Το `NSpid` μπορεί να αποκαλύψει την αντιστοίχιση PID σε εμφωλευμένα namespaces. Η αριστερότερη τιμή είναι σχετική με το PID namespace που συσχετίζεται με το procfs mount και ακολουθούν τιμές για διαδοχικά εμφωλευμένα namespaces.
- Το `readlink /proc/self/ns/pid` από μόνο του δεν αποδεικνύει το `hostPID`: ένα απομονωμένο container έχει επίσης έγκυρο inode PID namespace. Διασταυρώστε το με τη λίστα διεργασιών, το procfs mount, τη ρύθμιση του runtime και ένα inode namespace από την πλευρά του host, αν είναι διαθέσιμο.
- Μόλις γίνουν ορατά τα PID του host, ακόμη και οι πληροφορίες διεργασιών μόνο για ανάγνωση γίνονται χρήσιμες για αναγνώριση.

Αν διαπιστώσετε ότι ένα container εκτελείται με κοινή χρήση PID του host, μην το θεωρήσετε απλώς μια επιφανειακή διαφορά. Αλλάζει σημαντικά το τι μπορεί να παρατηρεί και ενδεχομένως να επηρεάζει το workload.





## References

- [1] [Συμβουλευτική ασφαλείας του runc: διαφυγή από container μέσω κατάχρησης «masked path» λόγω συνθηκών ανταγωνισμού στα mounts (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Κυκλοφορία εργαλείου – insject: Ένα εργαλείο εισαγωγής σε Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Βιβλίο Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Κοινή χρήση Process Namespace μεταξύ Containers σε ένα Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [Αποσφαλμάτωση Pods που εκτελούνται](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [KEP για Ephemeral Containers](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Πρότυπα ασφάλειας Pod](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
