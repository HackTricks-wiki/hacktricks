# Αξιολόγηση και Σκληραγώγηση

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Μια καλή αξιολόγηση container πρέπει να απαντήσει σε δύο παράλληρα ερωτήματα. Πρώτον, τι μπορεί να κάνει ένας attacker από το τρέχον workload; Δεύτερον, ποιες επιλογές του operator το κατέστησαν δυνατό; Τα enumeration εργαλεία βοηθούν στο πρώτο ερώτημα, και οι οδηγίες hardening βοηθούν στο δεύτερο. Η συγκέντρωση και των δύο σε μία σελίδα κάνει την ενότητα πιο χρήσιμη ως πεδικό reference παρά μόνο ως κατάλογος escape tricks.

## Εργαλεία Εντοπισμού

Μια σειρά εργαλείων παραμένει χρήσιμη για γρήγορο χαρακτηρισμό ενός container περιβάλλοντος:

- `linpeas` μπορεί να εντοπίσει πολλούς container indicators, mounted sockets, capability sets, επικίνδυνα filesystems, και breakout hints.
- `CDK` εστιάζει συγκεκριμένα σε container περιβάλλοντα και περιλαμβάνει enumeration συν μερικούς αυτοματοποιημένους escape checks.
- `amicontained` είναι lightweight και χρήσιμο για τον εντοπισμό container restrictions, capabilities, namespace exposure, και πιθανών breakout classes.
- `deepce` είναι ένας ακόμη container-focused enumerator με checks προσανατολισμένα σε breakout.
- `grype` είναι χρήσιμο όταν η αξιολόγηση περιλαμβάνει image-package vulnerability review αντί μόνο runtime escape analysis.

Η αξία αυτών των εργαλείων είναι η ταχύτητα και η κάλυψη, όχι η βεβαιότητα. Βοηθούν να αποκαλυφθεί η γενική posture γρήγορα, αλλά τα ενδιαφέροντα ευρήματα χρειάζονται ακόμη χειροκίνητη ερμηνεία σε σχέση με το πραγματικό runtime, namespace, capability, και mount model.

## Προτεραιότητες Σκληραγώγησης

Οι πιο σημαντικές αρχές hardening είναι εννοιολογικά απλές, αν και η υλοποίησή τους διαφέρει ανά πλατφόρμα. Αποφύγετε privileged containers. Αποφύγετε mounted runtime sockets. Μην δίνετε containers writable host paths εκτός αν υπάρχει πολύ συγκεκριμένος λόγος. Χρησιμοποιήστε user namespaces ή rootless execution όπου είναι εφικτό. Dropάρετε όλες τις capabilities και προσθέστε πίσω μόνο αυτές που το workload πραγματικά χρειάζεται. Κρατήστε seccomp, AppArmor, και SELinux ενεργοποιημένα αντί να τα απενεργοποιείτε για να διορθώσετε προβλήματα συμβατότητας εφαρμογών. Περιορίστε πόρους έτσι ώστε ένα compromised container να μην μπορεί εύκολα να προκαλέσει denial of service στο host.

Το hygiene των image και του build έχει την ίδια σημασία με τη runtime στάση. Χρησιμοποιήστε minimal images, rebuild τα συχνά, scanάρετέ τα, απαιτήστε provenance όπου είναι πρακτικό, και κρατήστε secrets εκτός των layers. Ένα container που τρέχει ως non-root με ένα μικρό image και έναν στενό syscall και capability surface είναι πολύ πιο εύκολο να υπερασπιστεί από ένα μεγάλο convenience image που τρέχει ως host-equivalent root με προεγκατεστημένα debugging tools.

## Παραδείγματα Εξάντλησης Πόρων

Οι resource controls δεν είναι εντυπωσιακοί, αλλά είναι μέρος της ασφάλειας container επειδή περιορίζουν την έκταση της ζημιάς σε περίπτωση compromise. Χωρίς όρια μνήμης, CPU ή PID, ένα απλό shell μπορεί να είναι αρκετό για να υποβαθμίσει το host ή τα γειτονικά workloads.

Παραδείγματα host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Αυτά τα παραδείγματα είναι χρήσιμα επειδή δείχνουν ότι δεν είναι κάθε επικίνδυνο αποτέλεσμα ενός container μια καθαρή "escape". Αδύναμα όρια cgroup μπορούν ακόμα να μετατρέψουν την code execution σε πραγματικό επιχειρησιακό αντίκτυπο.

## Εργαλεία σκληρυνσης

Για περιβάλλοντα με έμφαση στο Docker, το `docker-bench-security` παραμένει μια χρήσιμη βάση αναφοράς ελέγχου στην πλευρά του host επειδή ελέγχει κοινά ζητήματα διαμόρφωσης σε σχέση με ευρέως αναγνωρισμένες οδηγίες benchmark:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Το εργαλείο δεν αντικαθιστά το threat modeling, αλλά παραμένει χρήσιμο για τον εντοπισμό αμελών προεπιλογών daemon, mount, network και runtime που συσσωρεύονται με την πάροδο του χρόνου.

## Έλεγχοι

Χρησιμοποιήστε τα ως γρήγορες εντολές πρώτου ελέγχου κατά την αξιολόγηση:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Μια root διαδικασία με broad capabilities και `Seccomp: 0` απαιτεί άμεση προσοχή.
- Οι suspicious mounts και runtime sockets συχνά παρέχουν γρηγορότερο μονοπάτι προς impact από οποιοδήποτε kernel exploit.
- Ο συνδυασμός weak runtime posture και weak resource limits συνήθως υποδηλώνει ένα γενικά permissive container environment αντί για ένα μεμονωμένο σφάλμα.
