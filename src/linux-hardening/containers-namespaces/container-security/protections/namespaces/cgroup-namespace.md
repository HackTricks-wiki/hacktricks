# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το cgroup namespace δεν αντικαθιστά τα cgroups και δεν επιβάλλει από μόνο του όρια πόρων. Αντίθετα, αλλάζει **τον τρόπο με τον οποίο εμφανίζεται η ιεραρχία των cgroups** στη διεργασία. Με άλλα λόγια, εικονικοποιεί τις ορατές πληροφορίες διαδρομής των cgroups, ώστε το workload να βλέπει μια προβολή περιορισμένη στο container αντί για ολόκληρη την ιεραρχία του host.

Πρόκειται κυρίως για δυνατότητα περιορισμού της ορατότητας και των πληροφοριών. Βοηθά ώστε το περιβάλλον να φαίνεται αυτοτελές και αποκαλύπτει λιγότερα σχετικά με τη διάταξη των cgroups του host. Αυτό μπορεί να φαίνεται περιορισμένης σημασίας, αλλά εξακολουθεί να είναι σημαντικό, επειδή η περιττή ορατότητα στη δομή του host μπορεί να διευκολύνει το reconnaissance και να απλοποιήσει environment-dependent exploit chains.

## Λειτουργία

Χωρίς private cgroup namespace, μια διεργασία μπορεί να βλέπει διαδρομές cgroups σχετικές με τον host, οι οποίες αποκαλύπτουν μεγαλύτερο μέρος της ιεραρχίας του συστήματος από όσο είναι χρήσιμο. Με private cgroup namespace, το `/proc/self/cgroup` και οι σχετικές παρατηρήσεις γίνονται πιο τοπικές στην προβολή του ίδιου του container. Αυτό είναι ιδιαίτερα χρήσιμο σε σύγχρονες runtime stacks που θέλουν το workload να βλέπει ένα καθαρότερο περιβάλλον, το οποίο αποκαλύπτει λιγότερα στοιχεία του host.

Η εικονικοποίηση επηρεάζει επίσης το `/proc/<pid>/mountinfo>`, όχι μόνο το `/proc/<pid>/cgroup`. Όταν διαβάζετε μια άλλη διεργασία από διαφορετική οπτική cgroup-namespace, οι διαδρομές εκτός του namespace root εμφανίζονται με αρχικά στοιχεία `../`, κάτι που αποτελεί χρήσιμη ένδειξη ότι κοιτάτε πάνω από το delegated subtree σας. Μια χρήσιμη λεπτομέρεια για labs και post-exploitation είναι ότι ένα freshly created cgroup namespace συχνά χρειάζεται **cgroupfs remount από μέσα σε αυτό το namespace** πριν το `mountinfo` αντικατοπτρίσει καθαρά το νέο root. Διαφορετικά, μπορεί να εξακολουθείτε να βλέπετε ένα mount root όπως το `/..`, γεγονός που σημαίνει ότι το inherited mount εξακολουθεί να εκθέτει μια προβολή με root σε ancestor, παρόλο που το namespace έχει ήδη αλλάξει.

## Εργαστήριο

Μπορείτε να επιθεωρήσετε ένα cgroup namespace με:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Αν θέλετε το `mountinfo` να εμφανίζει πιο ξεκάθαρα το νέο root του cgroup-namespace, κάντε remount στο cgroup filesystem μέσα από το νέο namespace και συγκρίνετε ξανά:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Και συγκρίνετε τη συμπεριφορά κατά το runtime με:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Η αλλαγή αφορά κυρίως το τι μπορεί να βλέπει το process και όχι το αν υπάρχει cgroup enforcement.

## Επίδραση στην ασφάλεια

Το cgroup namespace πρέπει να θεωρείται κυρίως ένα **visibility-hardening layer**. Από μόνο του δεν θα σταματήσει ένα breakout αν το container έχει writable cgroup mounts, broad capabilities ή ένα επικίνδυνο περιβάλλον cgroup v1. Ωστόσο, αν το host cgroup namespace είναι shared, το process μαθαίνει περισσότερα για την οργάνωση του συστήματος και μπορεί να βρει ευκολότερα αντιστοιχίες μεταξύ host-relative cgroup paths και άλλων παρατηρήσεων.

Στο **cgroup v2**, το namespace αρχίζει να έχει μεγαλύτερη σημασία, επειδή οι κανόνες delegation είναι αυστηρότεροι. Αν η hierarchy είναι mounted με `nsdelegate`, ο kernel αντιμετωπίζει τα cgroup namespaces ως delegation boundaries: τα ancestor control files υποτίθεται ότι παραμένουν εκτός της reach του delegatee και τα writes στο namespace root περιορίζονται σε delegation-safe files, όπως τα `cgroup.procs`, `cgroup.threads` και `cgroup.subtree_control`. Αυτό και πάλι δεν μετατρέπει το namespace από μόνο του σε escape primitive, αλλά αλλάζει το τι μπορεί να επιθεωρήσει ένα compromised workload και σε ποιο σημείο μπορεί με ασφάλεια να δημιουργήσει sub-cgroups.

Επομένως, παρότι αυτό το namespace συνήθως δεν είναι ο πρωταγωνιστής σε container breakout writeups, εξακολουθεί να συμβάλλει στον ευρύτερο στόχο του περιορισμού του host information leak και του περιορισμού του cgroup delegation.

## Abuse

Η άμεση αξία του abuse αφορά κυρίως το reconnaissance. Αν το host cgroup namespace είναι shared, συγκρίνετε τα ορατά paths και αναζητήστε λεπτομέρειες της hierarchy που αποκαλύπτουν τον host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Εάν εκτίθενται επίσης εγγράψιμες διαδρομές cgroup, συνδυάστε αυτή την ορατότητα με αναζήτηση επικίνδυνων legacy interfaces:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Το ίδιο το namespace σπάνια παρέχει άμεσο escape, αλλά συχνά κάνει το περιβάλλον ευκολότερο στην αποτύπωση πριν από τη δοκιμή primitives για abuse βασισμένο σε cgroup.

Ένας γρήγορος έλεγχος της πραγματικότητας του runtime βοηθά επίσης στην ιεράρχηση του attack path. Το Docker εκθέτει `--cgroupns=host|private`, ενώ το Podman υποστηρίζει `host`, `private`, `container:<id>` και `ns:<path>`. Ειδικά στο Podman, η προεπιλογή είναι συνήθως **`host` στο cgroup v1** και **`private` στο cgroup v2**, επομένως ο απλός εντοπισμός της έκδοσης του cgroup σας δείχνει ήδη ποια στάση namespace είναι πιθανότερη, πριν καν επιθεωρήσετε ολόκληρο το OCI config.

### Modern v2 Recon: Είναι αυτό ένα Delegated Subtree;

Σε σύγχρονους hosts, το ενδιαφέρον ερώτημα συχνά δεν είναι το `release_agent`, αλλά αν η τρέχουσα διεργασία βρίσκεται μέσα σε ένα delegated **cgroup v2** subtree με επαρκή ορατότητα ή write access για τη δημιουργία nested groups:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Χρήσιμη ερμηνεία:

- Το `cgroup2fs` σημαίνει ότι βρίσκεστε στην ενοποιημένη ιεραρχία v2, επομένως οι κλασικές αλυσίδες `release_agent` που λειτουργούν μόνο σε v1 δεν θα πρέπει να είναι η πρώτη σας υπόθεση.
- Το `cgroup.controllers` δείχνει ποιοι controllers είναι διαθέσιμοι από το parent και, συνεπώς, σε τι θα μπορούσε δυνητικά να διακλαδωθεί το τρέχον subtree προς children.
- Το `cgroup.subtree_control` δείχνει ποιοι controllers είναι πραγματικά ενεργοποιημένοι για τους descendants.
- Το `cgroup.events` εκθέτει το `populated=0/1`, κάτι χρήσιμο για την παρακολούθηση του αν ένα subtree έχει αδειάσει, αλλά **δεν** αποτελεί primitive εκτέλεσης κώδικα στο host όπως το v1 `release_agent`.

Αν έχετε ήδη αρκετά privileges για να επιθεωρήσετε απευθείας το namespace μιας άλλης διεργασίας, συγκρίνετε τις προβολές με:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Πλήρες Παράδειγμα: Κοινόχρηστο cgroup Namespace + Writable cgroup v1

Το cgroup namespace από μόνο του συνήθως δεν επαρκεί για escape. Η πρακτική κλιμάκωση συμβαίνει όταν τα cgroup paths που αποκαλύπτουν το host συνδυάζονται με Writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Εάν αυτά τα αρχεία είναι προσβάσιμα και εγγράψιμα, μεταβείτε αμέσως στην πλήρη ροή εκμετάλλευσης του `release_agent` από το [cgroups.md](../cgroups.md). Ο αντίκτυπος είναι εκτέλεση κώδικα στο host μέσα από το container.

Χωρίς εγγράψιμες διεπαφές cgroup, ο αντίκτυπος συνήθως περιορίζεται στην αναγνώριση.

## Έλεγχοι

Σκοπός αυτών των εντολών είναι να διαπιστωθεί εάν η διεργασία έχει ιδιωτική προβολή του cgroup namespace ή εάν μαθαίνει περισσότερα για την ιεραρχία του host από όσα πραγματικά χρειάζεται.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Τι είναι ενδιαφέρον εδώ:

- Αν το αναγνωριστικό του namespace αντιστοιχεί σε μια διεργασία του host που σας ενδιαφέρει, το cgroup namespace μπορεί να είναι κοινόχρηστο.
- Οι διαδρομές που αποκαλύπτουν τον host στο `/proc/self/cgroup` ή οι καταχωρίσεις στο `mountinfo` με ρίζα σε ancestor είναι χρήσιμες για reconnaissance, ακόμη και όταν δεν είναι άμεσα exploitable.
- Αν χρησιμοποιείται το `cgroup2fs`, επικεντρωθείτε στο delegation, στους ορατούς controllers και στα writable subtrees, αντί να θεωρείτε ότι εξακολουθούν να υπάρχουν τα παλιά v1 primitives.
- Αν τα cgroup mounts είναι επίσης writable, το ζήτημα της ορατότητας γίνεται πολύ σημαντικότερο.

Το cgroup namespace θα πρέπει να αντιμετωπίζεται ως επίπεδο hardening της ορατότητας και όχι ως βασικός μηχανισμός αποτροπής escape. Η περιττή έκθεση της δομής των cgroup του host προσθέτει reconnaissance value για τον attacker.

## Αναφορές

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Τεκμηρίωση του Linux kernel για το cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
