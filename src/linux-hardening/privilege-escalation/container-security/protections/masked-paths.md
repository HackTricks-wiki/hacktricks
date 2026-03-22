# Κρυμμένες Διαδρομές

{{#include ../../../../banners/hacktricks-training.md}}

Οι κρυμμένες διαδρομές είναι μηχανισμοί προστασίας κατά την εκτέλεση που αποκρύπτουν ιδιαίτερα ευαίσθητες τοποθεσίες του filesystem που απευθύνονται στον πυρήνα από το container, είτε με bind-mounting πάνω τους είτε καθιστώντας τες μη προσβάσιμες με άλλο τρόπο. Ο στόχος είναι να αποτραπεί ένα workload από την άμεση αλληλεπίδραση με διεπαφές που οι κανονικές εφαρμογές δεν χρειάζονται, ιδιαίτερα μέσα στο procfs.

Αυτό είναι σημαντικό γιατί πολλά container escapes και κόλπα που επηρεάζουν το host ξεκινούν με την ανάγνωση ή εγγραφή ειδικών αρχείων κάτω από `/proc` ή `/sys`. Εάν αυτές οι τοποθεσίες είναι αποκρυμμένες, ο επιτιθέμενος χάνει την άμεση πρόσβαση σε ένα χρήσιμο μέρος της επιφάνειας ελέγχου του πυρήνα ακόμα και μετά την απόκτηση εκτέλεσης κώδικα μέσα στο container.

## Λειτουργία

Τα runtimes συνήθως αποκρύπτουν επιλεγμένες διαδρομές, όπως:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Η ακριβής λίστα εξαρτάται από το runtime και την παραμετροποίηση του host. Το σημαντικό χαρακτηριστικό είναι ότι η διαδρομή γίνεται μη προσβάσιμη ή αντικαθίσταται από την οπτική του container, παρόλο που εξακολουθεί να υπάρχει στο host.

## Lab

Επιθεωρήστε τη ρύθμιση masked-path που εκθέτει το Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Επιθεώρησε την πραγματική συμπεριφορά του mount μέσα στο workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Επιπτώσεις στην Ασφάλεια

Το Masking δεν δημιουργεί το κύριο όριο απομόνωσης, αλλά αφαιρεί αρκετούς στόχους υψηλής αξίας για post-exploitation. Χωρίς Masking, ένα παραβιασμένο container μπορεί να είναι σε θέση να ελέγξει την κατάσταση του kernel, να διαβάσει ευαίσθητες πληροφορίες διεργασιών ή πληροφορίες κλειδιών, ή να αλληλεπιδράσει με αντικείμενα procfs/sysfs που δεν θα έπρεπε ποτέ να ήταν ορατά στην εφαρμογή.

## Λανθασμένες ρυθμίσεις

Το κύριο λάθος είναι το unmasking ευρείας κατηγορίας μονοπατιών για ευκολία ή αποσφαλμάτωση. Στο Podman αυτό μπορεί να εμφανιστεί ως `--security-opt unmask=ALL` ή ως στοχευμένο unmasking. Στο Kubernetes, η υπερβολικά ευρεία έκθεση του proc μπορεί να εμφανιστεί μέσω `procMount: Unmasked`. Ένα άλλο σοβαρό πρόβλημα είναι η έκθεση του host `/proc` ή `/sys` μέσω bind mount, που παρακάμπτει εντελώς την ιδέα μιας περιορισμένης προβολής container.

## Κατάχρηση

Εάν το Masking είναι αδύναμο ή απουσιάζει, ξεκινήστε εντοπίζοντας ποιες ευαίσθητες διαδρομές procfs/sysfs είναι άμεσα προσβάσιμες:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Αν μια υποτιθέμενα μασκαρισμένη διαδρομή είναι προσβάσιμη, επιθεωρήστε την προσεκτικά:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Τι μπορούν να αποκαλύψουν αυτές οι εντολές:

- `/proc/timer_list` μπορεί να εκθέσει δεδομένα timer και scheduler του host. Αυτό είναι κυρίως ένα reconnaissance primitive, αλλά επιβεβαιώνει ότι το container μπορεί να διαβάσει kernel-facing πληροφορίες που κανονικά είναι κρυφές.
- `/proc/keys` είναι πολύ πιο ευαίσθητο. Ανάλογα με τη διαμόρφωση του host, μπορεί να αποκαλύψει keyring entries, key descriptions, και σχέσεις μεταξύ υπηρεσιών του host που χρησιμοποιούν το kernel keyring subsystem.
- `/sys/firmware` βοηθά στην αναγνώριση του boot mode, των firmware interfaces και των λεπτομερειών πλατφόρμας που είναι χρήσιμες για host fingerprinting και για την κατανόηση κατά πόσο το workload βλέπει host-level state.
- `/proc/config.gz` μπορεί να αποκαλύψει τη τρέχουσα kernel configuration, η οποία είναι πολύτιμη για να ταιριάξει public kernel exploit prerequisites ή για να κατανοήσει γιατί μια συγκεκριμένη λειτουργία είναι προσβάσιμη.
- `/proc/sched_debug` εκθέτει το scheduler state και συχνά παρακάμπτει την ενστικτώδη προσδοκία ότι το PID namespace θα έκρυβε εντελώς μη σχετικές πληροφορίες διεργασιών.

Ενδιαφέροντα αποτελέσματα περιλαμβάνουν άμεσες αναγνώσεις από αυτά τα αρχεία, αποδείξεις ότι τα δεδομένα ανήκουν στον host αντί για στην περιορισμένη προβολή του container, ή πρόσβαση σε άλλες τοποθεσίες procfs/sysfs που συνήθως αποκρύπτονται από προεπιλογή.

## Checks

Ο σκοπός αυτών των ελέγχων είναι να προσδιορίσει ποιες διαδρομές το runtime έκρυψε σκόπιμα και εάν το τρέχον workload εξακολουθεί να βλέπει ένα μειωμένο kernel-facing filesystem.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Μια μεγάλη λίστα masked-path είναι φυσιολογική σε hardened runtimes.
- Η έλλειψη masking σε ευαίσθητες εγγραφές procfs αξίζει πιο προσεκτική εξέταση.
- Αν μια ευαίσθητη διαδρομή είναι προσβάσιμη και το container έχει επίσης ισχυρές capabilities ή ευρείες mounts, η έκθεση έχει μεγαλύτερη σημασία.

## Runtime Defaults

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Ενεργοποιημένο από προεπιλογή | Το Docker ορίζει μια προεπιλεγμένη λίστα masked paths | έκθεση host proc/sys mounts, `--privileged` |
| Podman | Ενεργοποιημένο από προεπιλογή | Το Podman εφαρμόζει προεπιλεγμένα masked paths εκτός αν το masking απενεργοποιηθεί χειροκίνητα | `--security-opt unmask=ALL`, στοχευμένο unmasking, `--privileged` |
| Kubernetes | Κληρονομεί τις προεπιλεγμένες ρυθμίσεις του runtime | Χρησιμοποιεί τη συμπεριφορά masking του υποκείμενου runtime εκτός αν οι ρυθμίσεις του Pod αποδυναμώνουν την έκθεση του proc | `procMount: Unmasked`, πρότυπα privileged workloads, ευρείες host mounts |
| containerd / CRI-O under Kubernetes | Προεπιλεγμένο runtime | Συνήθως εφαρμόζει OCI/runtime masked paths εκτός αν παρακαμφθεί | άμεσες αλλαγές στη ρύθμιση του runtime, οι ίδιες Kubernetes μέθοδοι αποδυνάμωσης |

Τα masked paths υπάρχουν συνήθως από προεπιλογή. Το κύριο επιχειρησιακό πρόβλημα δεν είναι η απουσία τους από το runtime, αλλά ο εκ προθέσεως unmasking ή τα host bind mounts που ακυρώνουν την προστασία.
{{#include ../../../../banners/hacktricks-training.md}}
