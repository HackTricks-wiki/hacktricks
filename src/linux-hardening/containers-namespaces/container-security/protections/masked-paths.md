# Καλυμμένες διαδρομές

{{#include ../../../../banners/hacktricks-training.md}}

Οι καλυμμένες διαδρομές είναι προστασίες κατά τον χρόνο εκτέλεσης που αποκρύπτουν από το container ιδιαίτερα ευαίσθητες θέσεις του συστήματος αρχείων που σχετίζονται με τον kernel, προσαρτώντας πάνω τους bind mounts ή καθιστώντας τες με άλλον τρόπο απρόσιτες. Η προδιαγραφή OCI για τα runtimes ορίζει το `maskedPaths` ως απόλυτες διαδρομές που δεν πρέπει να είναι αναγνώσιμες μέσα στο container. <sup>[[1]](#references)</sup>

Αυτό έχει σημασία επειδή πολλές τεχνικές διαφυγής από container και πρόκλησης επιπτώσεων στον host ξεκινούν με την ανάγνωση ή την εγγραφή ειδικών αρχείων κάτω από τα `/proc` ή `/sys`. Αν αυτές οι θέσεις είναι καλυμμένες, ο επιτιθέμενος χάνει την άμεση πρόσβαση σε ένα χρήσιμο τμήμα της επιφάνειας ελέγχου του kernel, ακόμη κι αν έχει ήδη αποκτήσει τη δυνατότητα εκτέλεσης κώδικα μέσα στο container.

## Λειτουργία

Τα runtimes συνήθως καλύπτουν επιλεγμένες διαδρομές όπως:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Η ακριβής λίστα εξαρτάται από το runtime και τη διαμόρφωση του host. Το σημαντικό είναι ότι η διαδρομή γίνεται απρόσιτη ή αντικαθίσταται από την οπτική του container, παρόλο που εξακολουθεί να υπάρχει στον host.

## Εργαστήριο

Επιθεωρήστε τη διαμόρφωση των καλυμμένων διαδρομών που εκθέτει το Docker:

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

Ελέγξτε την πραγματική συμπεριφορά του mount μέσα στο workload:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

Μια αναφερόμενη διαδρομή δεν είναι απαραίτητα αναγνώσιμη: το runc μπορεί να καλύψει ένα αρχείο με ένα bind mount στο `/dev/null` και έναν κατάλογο με ένα κενό tmpfs μόνο για ανάγνωση. Ελέγξτε το ακριβές σημείο προσάρτησης και όχι μόνο αν πετυχαίνει η `ls`. <sup>[[4]](#references)</sup>

## Security Impact

Η κάλυψη δεν δημιουργεί το κύριο όριο απομόνωσης, αλλά αφαιρεί αρκετούς στόχους υψηλής αξίας μετά την παραβίαση. Χωρίς κάλυψη, ένα παραβιασμένο container μπορεί να είναι σε θέση να επιθεωρήσει την κατάσταση του kernel, να διαβάσει ευαίσθητες πληροφορίες διεργασιών ή κλειδιών ή να αλληλεπιδράσει με αντικείμενα procfs/sysfs που δεν θα έπρεπε ποτέ να είναι ορατά στην εφαρμογή.

## Misconfigurations

Το κύριο λάθος είναι η άρση της κάλυψης για ευρείες κατηγορίες διαδρομών για λόγους ευκολίας ή debugging. Στο Podman αυτό μπορεί να εμφανίζεται ως `--security-opt unmask=ALL` ή ως στοχευμένη άρση κάλυψης. <sup>[[2]](#references)</sup> Στο Kubernetes, η υπερβολικά ευρεία έκθεση του proc μπορεί να εμφανίζεται μέσω του `procMount: Unmasked`· οι τρέχουσες εκδόσεις του Kubernetes απαιτούν `spec.hostUsers: false` (ένα user namespace) για αυτήν τη ρύθμιση, ενώ οι εκδόσεις 1.12–1.29 δεν επέβαλλαν αυτήν την απαίτηση. <sup>[[3]](#references)</sup> Ένα άλλο σοβαρό πρόβλημα είναι η έκθεση του host `/proc` ή `/sys` μέσω ενός bind mount, κάτι που παρακάμπτει πλήρως την ιδέα μιας περιορισμένης οπτικής του container.

## Abuse

Αν η κάλυψη είναι ανεπαρκής ή απουσιάζει, ξεκινήστε εντοπίζοντας ποιες ευαίσθητες διαδρομές procfs/sysfs είναι άμεσα προσβάσιμες:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

Αν μια διαδρομή που υποτίθεται ότι είναι masked είναι προσβάσιμη, εξέτασέ την προσεκτικά:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

Τι μπορούν να αποκαλύψουν αυτές οι εντολές:

- Το `/proc/timer_list` μπορεί να εκθέσει δεδομένα του host για τους χρονοδιακόπτες και τον scheduler. Πρόκειται κυρίως για primitive αναγνώρισης, αλλά επιβεβαιώνει ότι το container μπορεί να διαβάσει πληροφορίες που αφορούν τον kernel και συνήθως είναι κρυφές.
- Το `/proc/keys` παραθέτει metadata μόνο για τα keys για τα οποία ο αναγνώστης έχει δικαίωμα **view**, με την επιφύλαξη ελέγχων LSM. Μπορεί να αποκαλύψει τύπους και περιγραφές keys, αλλά δεν εμφανίζει τα payloads των keys. <sup>[[6]](#references)</sup>
- Το `/sys/firmware` βοηθά στον εντοπισμό του τρόπου εκκίνησης, των διεπαφών firmware και των λεπτομερειών της πλατφόρμας που είναι χρήσιμες για fingerprinting του host και για να κατανοήσουμε αν το workload βλέπει κατάσταση σε επίπεδο host.
- Το `/proc/config.gz` μπορεί να αποκαλύψει τη διαμόρφωση του kernel που εκτελείται, κάτι πολύτιμο για την αντιστοίχιση προαπαιτούμενων δημόσιων kernel exploits ή για την κατανόηση του γιατί είναι προσβάσιμη μια συγκεκριμένη δυνατότητα.
- Το `/proc/sched_debug` εκθέτει την κατάσταση του scheduler και συχνά διαψεύδει την εύλογη προσδοκία ότι το PID namespace θα αποκρύπτει πλήρως πληροφορίες για άσχετες διεργασίες.

Ενδιαφέροντα αποτελέσματα είναι οι άμεσες αναγνώσεις από αυτά τα αρχεία, ενδείξεις ότι τα δεδομένα ανήκουν στον host και όχι σε μια περιορισμένη προβολή του container ή η πρόσβαση σε άλλες τοποθεσίες procfs/sysfs που συνήθως γίνονται mask από προεπιλογή.

### Race στην πηγή του mask κατά την εκκίνηση του container

Σε ευάλωτες υλοποιήσεις του runc, τα file masks εξαρτώνται από το inode του `/dev/null` του container. Ένας attacker που μπορεί να συγχρονίσει την εκκίνηση containers με κοινά mounts, συμπεριλαμβανομένων παράλληλων βημάτων BuildKit, μπορεί να εκμεταλλευτεί race και να αφαιρέσει το `/dev/null` πριν το runc το κάνει bind πάνω από masked αρχεία procfs. Τότε το runtime αντιμετωπίζει την πηγή που λείπει σαν να απουσίαζε ένας προορισμός mask και παραλείπει σιωπηλά αυτά τα file masks. Η αστοχία εξαρτάται από race κατά τη ρύθμιση του runtime· η αφαίρεση του `/dev/null` μετά την εκκίνηση δεν αναιρεί ένα mask που έχει ήδη εγκατασταθεί. <sup>[[4]](#references)</sup>

Μετά από μια ελεγχόμενη δοκιμή, συγκρίνετε τη ζητούμενη λίστα mask με τα ακριβή mountpoints μέσα στο νέο container. <sup>[[4]](#references)</sup> Το `findmnt -M` ελέγχει το συγκεκριμένο mountpoint αντί να καταφεύγει σε γονικό mount· αν το `findmnt` δεν υπάρχει, ελέγξτε το `/proc/self/mountinfo`. <sup>[[5]](#references)</sup> Η επιτυχής εκτέλεση του `ls` ή ένα κενό αποτέλεσμα από το `cat` δεν αποδεικνύει ότι απουσιάζει το mask. <sup>[[4]](#references)</sup>

Χρησιμοποιήστε τους [παρακάτω ελέγχους](#checks) για να συγκρίνετε τα ζητούμενα masks με τα ακριβή mounts στο νέο container.

Ένα file mask που παραλείφθηκε μπορεί να εκθέσει δεδομένα procfs, αν το επιτρέπουν τα συνήθη δικαιώματα και η πολιτική LSM. Από μόνο του, **δεν** καθιστά το `/proc/sys` εγγράψιμο: αυτό ελέγχεται ξεχωριστά από το [read-only-path](read-only-paths.md). Η διαφορετική περίπτωση αντικατάστασης του symlink `/dev/null`, η οποία μπορεί να ανακατευθύνει ένα bind mount σε εγγράψιμο στόχο procfs, καλύπτεται στην ενότητα [race του runtime με PID namespace](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs). <sup>[[4]](#references)</sup>

## Έλεγχοι

Σκοπός αυτών των ελέγχων είναι να διαπιστωθεί ποιες διαδρομές έκρυψε σκόπιμα το runtime και αν το τρέχον workload εξακολουθεί να βλέπει ένα περιορισμένο filesystem που παρέχει πρόσβαση σε πληροφορίες του kernel.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Χρησιμοποιήστε έλεγχο ακριβούς mount, επειδή ένα masked αρχείο μπορεί να εξακολουθεί να υπάρχει και μια ανάγνωση να επιστρέφει κενό αποτέλεσμα από το `/dev/null`. Ένα ανύπαρκτο σημείο προσάρτησης είναι εύρημα που πρέπει να διερευνηθεί, όχι απόδειξη ότι είναι προσβάσιμα δεδομένα του host. <sup>[[4]](#references)[[5]](#references)</sup>

Τι έχει ενδιαφέρον εδώ:

- Μια μεγάλη λίστα masked paths είναι φυσιολογική σε hardened runtimes.
- Η απουσία masking σε ευαίσθητες εγγραφές procfs αξίζει πιο προσεκτικό έλεγχο.
- Αν είναι προσβάσιμη μια ευαίσθητη διαδρομή και το container διαθέτει επίσης ισχυρά capabilities ή ευρείες προσαρτήσεις, η έκθεση είναι πιο σημαντική.

## Προεπιλογές Runtime

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθεις χειροκίνητες αποδυναμώσεις |
| --- | --- | --- | --- |
| Docker Engine | Ενεργό από προεπιλογή | Το Docker ορίζει μια προεπιλεγμένη λίστα masked paths | έκθεση προσαρτήσεων host proc/sys, `--privileged` |
| Podman | Ενεργό από προεπιλογή | Το Podman εφαρμόζει προεπιλεγμένα masked paths, εκτός αν γίνει χειροκίνητα unmask | `--security-opt unmask=ALL`, στοχευμένο unmasking, `--privileged` |
| Kubernetes | Κληρονομεί τις προεπιλογές του runtime | Χρησιμοποιεί τη συμπεριφορά masking του υποκείμενου runtime, εκτός αν οι ρυθμίσεις Pod αποδυναμώνουν την έκθεση του proc | `procMount: Unmasked` (στις τρέχουσες εκδόσεις απαιτεί `hostUsers: false`), μοτίβα privileged workloads, ευρείες προσαρτήσεις host |
| containerd / CRI-O στο Kubernetes | Προεπιλογή runtime | Συνήθως εφαρμόζει masked paths του OCI/runtime, εκτός αν παρακαμφθούν | άμεσες αλλαγές ρυθμίσεων runtime, οι ίδιες οδοί αποδυνάμωσης του Kubernetes |

Τα masked paths υπάρχουν συνήθως από προεπιλογή. Το κύριο λειτουργικό πρόβλημα δεν είναι η απουσία τους από το runtime, αλλά η σκόπιμη άρση του masking ή οι bind mounts του host που αναιρούν την προστασία.

## References

- [1] [Open Container Initiative - Διαμόρφωση Linux container: Masked Paths](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Τεκμηρίωση Podman - Επιλογές ασφαλείας `podman run`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Τεκμηρίωση Kubernetes - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [Συμβουλευτικό δελτίο runc: race στην πηγή mount του masked path](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [Εγχειρίδιο findmnt(8)](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [Εγχειρίδιο keyrings(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
