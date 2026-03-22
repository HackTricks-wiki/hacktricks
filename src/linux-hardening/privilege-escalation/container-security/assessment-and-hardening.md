# Αξιολόγηση και Σκληρύνση

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Μια καλή αξιολόγηση container πρέπει να απαντά σε δύο παράλληλα ερωτήματα. Πρώτον, τι μπορεί να κάνει ένας εισβολέας από το τρέχον workload; Δεύτερον, ποιες επιλογές του χειριστή έκαναν αυτό δυνατό; Τα εργαλεία enumeration βοηθούν με το πρώτο ερώτημα, και οι οδηγίες σκληρυνσης βοηθούν με το δεύτερο. Η συγκέντρωση και των δύο σε μία σελίδα κάνει την ενότητα πιο χρήσιμη ως πεδική αναφορά παρά απλώς έναν κατάλογο escape tricks.

## Εργαλεία Εντοπισμού

Πολλά εργαλεία παραμένουν χρήσιμα για γρήγορο χαρακτηρισμό ενός περιβάλλοντος container:

- `linpeas` μπορεί να εντοπίσει πολλούς δείκτες container, mounted sockets, sets δυνατοτήτων, επικίνδυνα filesystems και hints για breakout.
- `CDK` επικεντρώνεται ειδικά σε περιβάλλοντα container και περιλαμβάνει enumeration μαζί με κάποιους αυτοματοποιημένους ελέγχους escape.
- `amicontained` είναι ελαφρύ και χρήσιμο για τον εντοπισμό περιορισμών container, δυνατοτήτων, έκθεσης namespace και πιθανών κατηγοριών breakout.
- `deepce` είναι ένας ακόμα enumerator με προσανατολισμένους σε breakout ελέγχους.
- `grype` είναι χρήσιμο όταν η αξιολόγηση περιλαμβάνει ανασκόπηση ευπαθειών πακέτων image αντί μόνο ανάλυση escape σε runtime.

Η αξία αυτών των εργαλείων είναι η ταχύτητα και η κάλυψη, όχι η βεβαιότητα. Βοηθούν να αποκαλυφθεί γρήγορα η γενική κατάσταση, αλλά τα ενδιαφέροντα ευρήματα χρειάζονται χειροκίνητη ερμηνεία σε σχέση με το πραγματικό runtime, namespace, capability και μοντέλο mount.

## Προτεραιότητες Σκληρυνσης

Οι πιο σημαντικές αρχές σκληρυνσης είναι εννοιολογικά απλές, αν και η υλοποίησή τους διαφέρει ανά πλατφόρμα. Αποφύγετε privileged containers. Αποφύγετε mounted runtime sockets. Μην δίνετε containers writable host paths εκτός αν υπάρχει πολύ συγκεκριμένος λόγος. Χρησιμοποιήστε user namespaces ή rootless execution όπου είναι εφικτό. Αφαιρέστε όλες τις capabilities και προσθέστε μόνο αυτές που χρειάζεται πραγματικά το workload. Κρατήστε ενεργά τα `seccomp`, `AppArmor` και `SELinux` αντί να τα απενεργοποιείτε για να λύσετε προβλήματα συμβατότητας εφαρμογών. Περιορίστε πόρους ώστε ένα παραβιασμένο container να μην μπορεί απλά να αρνηθεί υπηρεσία στον host.

Η υγιεινή image και build έχει την ίδια σημασία με τη runtime στάση. Χρησιμοποιήστε minimal images, επαναχτίζετε συχνά, σαρώστε τις, απαιτείτε provenance όπου είναι πρακτικό, και μην κρατάτε secrets μέσα σε layers. Ένα container που τρέχει ως non-root με μικρή image και στενό syscall και capability surface είναι πολύ πιο εύκολο να υπερασπιστεί κανείς από μια μεγάλη convenience image που τρέχει ως host-equivalent root με προεγκατεστημένα debugging εργαλεία.

## Παραδείγματα Εξάντλησης Πόρων

Οι έλεγχοι πόρων δεν είναι εντυπωσιακοί, αλλά αποτελούν μέρος της ασφάλειας container επειδή περιορίζουν την έκταση των επιπτώσεων μιας παραβίασης. Χωρίς όρια στη μνήμη, CPU ή PID, ένα απλό shell μπορεί να είναι αρκετό για να υποβαθμίσει τον host ή γειτονικά workloads.

Παραδείγματα δοκιμών που επηρεάζουν τον host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Αυτά τα παραδείγματα είναι χρήσιμα επειδή δείχνουν ότι όχι κάθε επικίνδυνο αποτέλεσμα container είναι ένα καθαρό "escape". Αδύναμα όρια cgroup μπορούν ακόμα να μετατρέψουν το code execution σε πραγματικό επιχειρησιακό αντίκτυπο.

## Hardening Tooling

Για Docker-centric περιβάλλοντα, `docker-bench-security` παραμένει μια χρήσιμη βάση ελέγχου στην πλευρά του host, επειδή ελέγχει κοινά ζητήματα διαμόρφωσης σε σχέση με ευρέως αναγνωρισμένες οδηγίες benchmark:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Το εργαλείο δεν αντικαθιστά το threat modeling, αλλά είναι ακόμη χρήσιμο για τον εντοπισμό απρόσεκτων daemon, mount, network και runtime defaults που συσσωρεύονται με την πάροδο του χρόνου.

## Έλεγχοι

Χρησιμοποιήστε τα παρακάτω ως γρήγορες εντολές πρώτου ελέγχου κατά την αξιολόγηση:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Ένας root process με broad capabilities και `Seccomp: 0` απαιτεί άμεση προσοχή.
- Οι ύποπτες mounts και τα runtime sockets συχνά παρέχουν ταχύτερο μονοπάτι προς impact από οποιοδήποτε kernel exploit.
- Ο συνδυασμός weak runtime posture και weak resource limits συνήθως υποδηλώνει ένα γενικά permissive container environment παρά ένα μεμονωμένο, απομονωμένο λάθος.
{{#include ../../../banners/hacktricks-training.md}}
