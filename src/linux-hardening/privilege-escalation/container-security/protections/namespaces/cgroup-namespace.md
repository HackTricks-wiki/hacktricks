# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το cgroup namespace δεν αντικαθιστά τα cgroups και δεν επιβάλλει αυτό καθαυτό όρια πόρων. Αντίθετα, τροποποιεί **τον τρόπο που εμφανίζεται η ιεραρχία των cgroup** στη διεργασία. Με άλλα λόγια, εικονικοποιεί τις ορατές πληροφορίες διαδρομής cgroup έτσι ώστε το workload να βλέπει μια προβολή περιορισμένη στο container αντί για την πλήρη ιεραρχία του host.

Πρόκειται κυρίως για μια λειτουργία μείωσης ορατότητας και πληροφοριών. Βοηθά ώστε το περιβάλλον να φαίνεται αυτοτελές και αποκαλύπτει λιγότερα σχετικά με τη διάταξη cgroup του host. Αυτό μπορεί να φαίνεται μικρό, αλλά έχει σημασία, γιατί η περιττή ορατότητα στη δομή του host μπορεί να διευκολύνει reconnaissance και να απλοποιήσει environment-dependent exploit chains.

## Λειτουργία

Χωρίς ένα ιδιωτικό cgroup namespace, μια διεργασία μπορεί να βλέπει host-relative cgroup paths που αποκαλύπτουν μεγαλύτερο μέρος της ιεραρχίας της μηχανής από όσο είναι χρήσιμο. Με ένα ιδιωτικό cgroup namespace, `/proc/self/cgroup` και σχετικές παρατηρήσεις γίνονται πιο τοπικές στην ίδια την προβολή του container. Αυτό είναι ιδιαίτερα χρήσιμο σε σύγχρονα runtime stacks που θέλουν το workload να βλέπει ένα πιο καθαρό, λιγότερο αποκαλυπτικό προς τον host περιβάλλον.

## Εργαστήριο

Μπορείτε να εξετάσετε ένα cgroup namespace με:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
Και σύγκρινε τη runtime συμπεριφορά με:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Η αλλαγή αφορά κυρίως το τι μπορεί να δει η διεργασία, όχι το αν υπάρχει επιβολή των cgroup.

## Επιπτώσεις Ασφαλείας

Το cgroup namespace κατανοείται καλύτερα ως ένα **στρώμα σκλήρυνσης ορατότητας**. Από μόνο του δεν θα σταματήσει ένα breakout αν το container έχει εγγράψιμα cgroup mounts, ευρείες capabilities, ή ένα επικίνδυνο περιβάλλον cgroup v1. Ωστόσο, αν το host cgroup namespace είναι shared, η διεργασία μαθαίνει περισσότερα για το πώς είναι οργανωμένο το σύστημα και μπορεί να της είναι πιο εύκολο να ευθυγραμμίσει host-relative cgroup paths με άλλες παρατηρήσεις.

Έτσι, ενώ αυτό το namespace δεν είναι συνήθως το κύριο στοιχείο στις αναφορές container breakout, εξακολουθεί να συμβάλλει στον ευρύτερο στόχο της ελαχιστοποίησης της host information leakage.

## Κατάχρηση

Η άμεση αξία κατάχρησης είναι κυρίως reconnaissance. Εάν το host cgroup namespace είναι shared, συγκρίνετε τα ορατά paths και αναζητήστε λεπτομέρειες της ιεραρχίας που αποκαλύπτουν τον host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Εάν εκτίθενται επίσης εγγράψιμα μονοπάτια cgroup, συνδυάστε αυτή την ορατότητα με αναζήτηση για επικίνδυνες παρωχημένες διεπαφές:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Το namespace από μόνο του σπάνια δίνει άμεσο escape, αλλά συχνά κάνει το περιβάλλον πιο εύκολο στο να χαρτογραφηθεί πριν από τη δοκιμή των cgroup-based abuse primitives.

### Πλήρες Παράδειγμα: Shared cgroup Namespace + Writable cgroup v1

Το cgroup namespace από μόνο του συνήθως δεν είναι αρκετό για escape. Η πρακτική escalation συμβαίνει όταν host-revealing cgroup paths συνδυάζονται με writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Εάν αυτά τα αρχεία είναι προσβάσιμα και εγγράψιμα, pivot αμέσως στην πλήρη ροή εκμετάλλευσης του `release_agent` από [cgroups.md](../cgroups.md). Η επίπτωση είναι εκτέλεση κώδικα στο host από το εσωτερικό του container.

Χωρίς εγγράψιμες cgroup διεπαφές, η επίπτωση συνήθως περιορίζεται σε αναγνώριση.

## Έλεγχοι

Ο σκοπός αυτών των εντολών είναι να διαπιστωθεί εάν η διαδικασία έχει ιδιωτική προβολή cgroup namespace ή μαθαίνει περισσότερα για την ιεραρχία του host απ' ό,τι πραγματικά χρειάζεται.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Τι είναι ενδιαφέρον εδώ:

- Αν το namespace identifier ταιριάζει με μια host process που σας ενδιαφέρει, το cgroup namespace μπορεί να είναι κοινό.
- Host-revealing paths στο `/proc/self/cgroup` είναι χρήσιμο reconnaissance ακόμα κι αν δεν είναι άμεσα exploitable.
- Αν τα cgroup mounts είναι επίσης writable, το ζήτημα της visibility γίνεται πολύ πιο σημαντικό.

Το cgroup namespace θα πρέπει να αντιμετωπίζεται ως visibility-hardening layer παρά ως πρωταρχικός escape-prevention μηχανισμός. Η έκθεση της host cgroup δομής χωρίς λόγο προσθέτει reconnaissance value για τον attacker.
{{#include ../../../../../banners/hacktricks-training.md}}
