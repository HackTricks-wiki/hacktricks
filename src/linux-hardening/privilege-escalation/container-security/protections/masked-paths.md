# Μασκαρισμένες διαδρομές

{{#include ../../../../banners/hacktricks-training.md}}

Οι μασκαρισμένες διαδρομές είναι μηχανισμοί προστασίας κατά την εκτέλεση που κρύβουν ιδιαίτερα ευαίσθητες τοποθεσίες του filesystem που κοιτάνε προς τον kernel από το container, είτε με bind-mounting πάνω τους είτε κάνοντάς τες με άλλο τρόπο μη προσπελάσιμες. Ο σκοπός είναι να αποτραπεί ένα workload από το να αλληλεπιδρά άμεσα με διεπαφές που οι συνηθισμένες εφαρμογές δεν χρειάζονται, ιδιαίτερα μέσα στο procfs.

Αυτό έχει σημασία επειδή πολλές container escapes και τεχνικές που επηρεάζουν τον host ξεκινούν διαβάζοντας ή γράφοντας ειδικά αρχεία κάτω από `/proc` ή `/sys`. Αν αυτές οι τοποθεσίες είναι masked, ο επιτιθέμενος χάνει την άμεση πρόσβαση σε ένα χρήσιμο μέρος της επιφάνειας ελέγχου του kernel ακόμα και μετά την απόκτηση εκτέλεσης κώδικα μέσα στο container.

## Λειτουργία

Τα runtimes συχνά μασκάρουν επιλεγμένες διαδρομές όπως:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Η ακριβής λίστα εξαρτάται από το runtime και τη διαμόρφωση του host. Το σημαντικό χαρακτηριστικό είναι ότι η διαδρομή γίνεται μη προσπελάσιμη ή αντικαθίσταται από την οπτική γωνία του container αν και εξακολουθεί να υπάρχει στον host.

## Εργαστήριο

Επιθεωρήστε τη διαμόρφωση masked-path που αποκαλύπτει το Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Επιθεώρησε την πραγματική συμπεριφορά του mount μέσα στο workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Επιπτώσεις Ασφαλείας

Το Masking δεν δημιουργεί το κύριο όριο απομόνωσης, αλλά αφαιρεί αρκετούς στόχους υψηλής αξίας μετά την εκμετάλλευση. Χωρίς masking, ένα συμβιβασμένο container μπορεί να είναι σε θέση να ελέγξει την κατάσταση του kernel, να διαβάσει ευαίσθητες πληροφορίες διεργασιών ή πληροφορίες κλειδιών, ή να αλληλεπιδράσει με αντικείμενα procfs/sysfs που δεν θα έπρεπε ποτέ να είναι ορατά στην εφαρμογή.

## Λανθασμένες ρυθμίσεις

Το κύριο λάθος είναι το unmasking ευρέων κατηγοριών διαδρομών για λόγους ευκολίας ή debugging. Στο Podman αυτό μπορεί να εμφανιστεί ως `--security-opt unmask=ALL` ή στοχευμένο unmasking. Στο Kubernetes, υπερβολικά ευρεία έκθεση του proc μπορεί να εμφανιστεί μέσω `procMount: Unmasked`. Ένα άλλο σοβαρό πρόβλημα είναι η έκθεση του host `/proc` ή `/sys` μέσω bind mount, που παρακάμπτει εντελώς την ιδέα μιας μειωμένης προβολής του container.

## Κατάχρηση

If masking is weak or absent, start by identifying which sensitive procfs/sysfs paths are directly reachable:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Εάν μια δήθεν κρυμμένη διαδρομή είναι προσβάσιμη, επιθεώρησέ την προσεκτικά:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Τι μπορούν να αποκαλύψουν αυτές οι εντολές:

- `/proc/timer_list` μπορεί να εκθέσει host timer και scheduler δεδομένα. Αυτό είναι κυρίως ένα reconnaissance primitive, αλλά επιβεβαιώνει ότι το container μπορεί να διαβάσει kernel-facing πληροφορίες που κανονικά είναι κρυφές.
- `/proc/keys` είναι πολύ πιο ευαίσθητο. Ανάλογα με τη διαμόρφωση του host, μπορεί να αποκαλύψει keyring entries, key descriptions και σχέσεις μεταξύ host services που χρησιμοποιούν το kernel keyring subsystem.
- `/sys/firmware` βοηθά στον εντοπισμό boot mode, firmware interfaces και λεπτομερειών πλατφόρμας που είναι χρήσιμες για host fingerprinting και για την κατανόηση του κατά πόσον το workload βλέπει host-level state.
- `/proc/config.gz` μπορεί να αποκαλύψει τη διαμόρφωση του τρέχοντος kernel, κάτι που είναι πολύτιμο για να ταιριάξει public kernel exploit prerequisites ή για να καταλάβει γιατί μια συγκεκριμένη λειτουργία είναι προσβάσιμη.
- `/proc/sched_debug` εκθέτει την κατάσταση του scheduler και συχνά παρακάμπτει την ενστικτώδη προσδοκία ότι το PID namespace θα πρέπει να αποκρύπτει εντελώς μη σχετικές πληροφορίες διεργασιών.

Ενδιαφέροντα αποτελέσματα περιλαμβάνουν απευθείας αναγνώσεις από αυτά τα αρχεία, ενδείξεις ότι τα δεδομένα ανήκουν στον host αντί για μια περιορισμένη προβολή του container, ή πρόσβαση σε άλλες τοποθεσίες procfs/sysfs που συνήθως είναι masked από προεπιλογή.

## Checks

Σκοπός αυτών των ελέγχων είναι να καθορίσουν ποιες διαδρομές έκρυψε σκόπιμα το runtime και αν το τρέχον workload εξακολουθεί να βλέπει ένα reduced kernel-facing filesystem.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Μια μακρά λίστα masked paths είναι φυσιολογική σε σκληρυμένα περιβάλλοντα εκτέλεσης.
- Η απουσία masking για ευαίσθητες εγγραφές procfs αξίζει στενότερη διερεύνηση.
- Εάν μια ευαίσθητη διαδρομή είναι προσβάσιμη και το container έχει επίσης ισχυρές capabilities ή ευρείες mounts, η έκθεση έχει μεγαλύτερη σημασία.

## Προεπιλογές χρόνου εκτέλεσης

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνηθισμένες χειροκίνητες αποδυναμώσεις |
| --- | --- | --- | --- |
| Docker Engine | Ενεργοποιημένο από προεπιλογή | Docker ορίζει μια προεπιλεγμένη λίστα masked paths | έκθεση host proc/sys mounts, `--privileged` |
| Podman | Ενεργοποιημένο από προεπιλογή | Podman εφαρμόζει προεπιλεγμένα masked paths εκτός αν γίνει unmask χειροκίνητα | `--security-opt unmask=ALL`, στοχευμένο unmasking, `--privileged` |
| Kubernetes | Κληρονομεί τις προεπιλογές του runtime | Χρησιμοποιεί τη συμπεριφορά masking του υποκείμενου runtime εκτός αν οι ρυθμίσεις του Pod αποδυναμώνουν την έκθεση του proc | `procMount: Unmasked`, πρότυπα privileged workloads, ευρείες host mounts |
| containerd / CRI-O under Kubernetes | Προεπιλεγμένο runtime | Συνήθως εφαρμόζει OCI/runtime masked paths εκτός αν υπερισχύσει άλλη ρύθμιση | άμεσες αλλαγές config του runtime, οι ίδιες Kubernetes αποδυναμώσεις |

Οι masked paths συνήθως υπάρχουν ως προεπιλογή. Το κύριο λειτουργικό πρόβλημα δεν είναι η απουσία τους στο runtime, αλλά ο σκόπιμος unmasking ή τα host bind mounts που ακυρώνουν την προστασία.
