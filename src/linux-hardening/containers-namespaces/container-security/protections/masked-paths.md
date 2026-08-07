# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Τα masked paths είναι protections κατά το runtime που αποκρύπτουν ιδιαίτερα ευαίσθητες τοποθεσίες filesystem που επικοινωνούν με τον kernel από το container, κάνοντας bind-mount πάνω τους ή καθιστώντας τις με άλλον τρόπο μη προσβάσιμες. Σκοπός είναι να αποτραπεί η άμεση αλληλεπίδραση ενός workload με interfaces που οι ordinary applications δεν χρειάζονται, ιδιαίτερα μέσα στο procfs.

Αυτό έχει σημασία επειδή πολλά container escapes και tricks που επηρεάζουν το host ξεκινούν με την ανάγνωση ή την εγγραφή ειδικών αρχείων κάτω από τα `/proc` ή `/sys`. Αν αυτές οι τοποθεσίες είναι masked, ο attacker χάνει την άμεση πρόσβαση σε ένα χρήσιμο μέρος του kernel control surface, ακόμη και αφού αποκτήσει code execution μέσα στο container.

## Operation

Τα runtimes συνήθως κάνουν mask επιλεγμένα paths, όπως:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Η ακριβής λίστα εξαρτάται από το runtime και τη ρύθμιση του host. Η σημαντική ιδιότητα είναι ότι το path γίνεται μη προσβάσιμο ή αντικαθίσταται από την οπτική του container, παρόλο που εξακολουθεί να υπάρχει στον host.

## Lab

Επιθεωρήστε τη ρύθμιση masked paths που εκθέτει το Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Επιθεωρήστε την πραγματική συμπεριφορά των mounts μέσα στο workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Επιπτώσεις στην ασφάλεια

Το masking δεν δημιουργεί το κύριο όριο απομόνωσης, αλλά αφαιρεί αρκετούς στόχους υψηλής αξίας στο post-exploitation. Χωρίς masking, ένα compromised container ενδέχεται να μπορεί να επιθεωρήσει την κατάσταση του kernel, να διαβάσει ευαίσθητες πληροφορίες διεργασιών ή κλειδιών ή να αλληλεπιδράσει με αντικείμενα procfs/sysfs που δεν θα έπρεπε ποτέ να είναι ορατά στην εφαρμογή.

## Misconfigurations

Το κύριο λάθος είναι η κατάργηση του masking για ευρείες κατηγορίες paths για λόγους ευκολίας ή debugging. Στο Podman αυτό μπορεί να εμφανιστεί ως `--security-opt unmask=ALL` ή ως στοχευμένη κατάργηση του masking. Στο Kubernetes, υπερβολικά ευρεία έκθεση του proc μπορεί να εμφανιστεί μέσω του `procMount: Unmasked`. Ένα ακόμη σοβαρό πρόβλημα είναι η έκθεση του host `/proc` ή `/sys` μέσω ενός bind mount, κάτι που παρακάμπτει πλήρως την ιδέα μιας περιορισμένης προβολής του container.

## Abuse

Αν το masking είναι αδύναμο ή απουσιάζει, ξεκινήστε εντοπίζοντας ποια ευαίσθητα paths του procfs/sysfs είναι άμεσα προσβάσιμα:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Αν μια διαδρομή που υποτίθεται ότι είναι masked είναι προσβάσιμη, εξέτασέ την προσεκτικά:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Τι μπορούν να αποκαλύψουν αυτές οι εντολές:

- Το `/proc/timer_list` μπορεί να εκθέσει δεδομένα σχετικά με τους timers και τον scheduler του host. Πρόκειται κυρίως για reconnaissance primitive, αλλά επιβεβαιώνει ότι το container μπορεί να διαβάσει πληροφορίες που σχετίζονται με τον kernel και συνήθως είναι κρυφές.
- Το `/proc/keys` είναι πολύ πιο ευαίσθητο. Ανάλογα με τη διαμόρφωση του host, μπορεί να αποκαλύψει entries του keyring, περιγραφές keys και σχέσεις μεταξύ host services που χρησιμοποιούν το kernel keyring subsystem.
- Το `/sys/firmware` βοηθά στον εντοπισμό του boot mode, των firmware interfaces και λεπτομερειών της πλατφόρμας, οι οποίες είναι χρήσιμες για host fingerprinting και για την κατανόηση του κατά πόσο το workload βλέπει state σε επίπεδο host.
- Το `/proc/config.gz` μπορεί να αποκαλύψει τη διαμόρφωση του kernel που εκτελείται, κάτι που είναι χρήσιμο για την αντιστοίχιση των prerequisites public kernel exploits ή για την κατανόηση του λόγου για τον οποίο είναι προσβάσιμο ένα συγκεκριμένο feature.
- Το `/proc/sched_debug` εκθέτει την κατάσταση του scheduler και συχνά καταρρίπτει την intuitively αναμενόμενη υπόθεση ότι το PID namespace θα πρέπει να αποκρύπτει πλήρως πληροφορίες για άσχετες processes.

Ενδιαφέροντα αποτελέσματα περιλαμβάνουν την απευθείας ανάγνωση αυτών των αρχείων, ενδείξεις ότι τα δεδομένα ανήκουν στον host και όχι σε μια περιορισμένη προβολή του container ή πρόσβαση σε άλλες τοποθεσίες procfs/sysfs που συνήθως γίνονται masked by default.

## Έλεγχοι

Σκοπός αυτών των ελέγχων είναι να προσδιοριστεί ποιες διαδρομές έκρυψε σκόπιμα το runtime και αν το τρέχον workload εξακολουθεί να βλέπει ένα περιορισμένο kernel-facing filesystem.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Μια μεγάλη λίστα masked paths είναι φυσιολογική σε hardened runtimes.
- Η απουσία masking σε ευαίσθητες εγγραφές procfs χρήζει πιο προσεκτικής εξέτασης.
- Αν ένα ευαίσθητο path είναι προσβάσιμο και το container διαθέτει επίσης ισχυρές capabilities ή broad mounts, η έκθεση είναι σημαντικότερη.

## Προεπιλογές Runtime

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Ενεργοποιημένο by default | Το Docker ορίζει μια default masked path list | έκθεση host proc/sys mounts, `--privileged` |
| Podman | Ενεργοποιημένο by default | Το Podman εφαρμόζει default masked paths, εκτός αν γίνει χειροκίνητο unmasking | `--security-opt unmask=ALL`, targeted unmasking, `--privileged` |
| Kubernetes | Κληρονομεί τις default ρυθμίσεις του runtime | Χρησιμοποιεί τη συμπεριφορά masking του underlying runtime, εκτός αν οι ρυθμίσεις του Pod αποδυναμώνουν την έκθεση του proc | `procMount: Unmasked`, privileged workload patterns, broad host mounts |
| containerd / CRI-O under Kubernetes | Default του runtime | Συνήθως εφαρμόζει OCI/runtime masked paths, εκτός αν γίνει override | άμεσες αλλαγές στις ρυθμίσεις του runtime, οι ίδιες διαδρομές αποδυνάμωσης του Kubernetes |

Τα masked paths συνήθως υπάρχουν by default. Το κύριο operational πρόβλημα δεν είναι η απουσία τους από το runtime, αλλά το σκόπιμο unmasking ή τα host bind mounts που αναιρούν την προστασία.

{{#include ../../../../banners/hacktricks-training.md}}
