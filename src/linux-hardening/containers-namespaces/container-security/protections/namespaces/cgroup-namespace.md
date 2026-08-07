# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το cgroup namespace δεν αντικαθιστά τα cgroups και δεν επιβάλλει από μόνο του όρια πόρων. Αντίθετα, αλλάζει **τον τρόπο με τον οποίο εμφανίζεται η ιεραρχία των cgroups** στη διεργασία. Με άλλα λόγια, εικονικοποιεί τις ορατές πληροφορίες διαδρομής των cgroups, ώστε το workload να βλέπει μια προβολή περιορισμένη στο container αντί για ολόκληρη την ιεραρχία του host.

Αυτό είναι κυρίως μια λειτουργία ορατότητας και μείωσης πληροφοριών. Βοηθά το περιβάλλον να φαίνεται αυτοτελές και αποκαλύπτει λιγότερα σχετικά με τη διάταξη των cgroups του host. Αυτό μπορεί να ακούγεται περιορισμένο, αλλά εξακολουθεί να έχει σημασία, επειδή η περιττή ορατότητα στη δομή του host μπορεί να διευκολύνει την αναγνώριση και να απλοποιήσει exploit chains που εξαρτώνται από το περιβάλλον.

## Λειτουργία

Χωρίς private cgroup namespace, μια διεργασία μπορεί να βλέπει διαδρομές cgroups σχετικές με τον host, οι οποίες αποκαλύπτουν μεγαλύτερο μέρος της ιεραρχίας του συστήματος από όσο είναι χρήσιμο. Με ένα private cgroup namespace, το `/proc/self/cgroup` και άλλες σχετικές παρατηρήσεις περιορίζονται περισσότερο στην προβολή του ίδιου του container. Αυτό είναι ιδιαίτερα χρήσιμο σε σύγχρονα runtime stacks που θέλουν το workload να βλέπει ένα καθαρότερο περιβάλλον, το οποίο αποκαλύπτει λιγότερες πληροφορίες για τον host.

Η εικονικοποίηση επηρεάζει επίσης το `/proc/<pid>/mountinfo>`, όχι μόνο το `/proc/<pid>/cgroup`. Όταν διαβάζετε μια άλλη διεργασία από διαφορετική οπτική cgroup-namespace, οι διαδρομές εκτός του namespace root εμφανίζονται με αρχικά στοιχεία `../`, γεγονός που αποτελεί χρήσιμη ένδειξη ότι εξετάζετε ανώτερο επίπεδο από το delegated subtree σας. Μια χρήσιμη λεπτομέρεια για labs και post-exploitation είναι ότι ένα cgroup namespace που μόλις δημιουργήθηκε συχνά χρειάζεται **cgroupfs remount από το εσωτερικό αυτού του namespace** πριν το `mountinfo` αντικατοπτρίσει καθαρά το νέο root. Διαφορετικά, μπορεί να εξακολουθείτε να βλέπετε ένα mount root όπως `/..`, πράγμα που σημαίνει ότι το inherited mount εξακολουθεί να εκθέτει μια προβολή με root σε ancestor, παρόλο που το ίδιο το namespace έχει ήδη αλλάξει.<sup>[[1]](#references)</sup>

## Εργαστήριο

Μπορείτε να επιθεωρήσετε ένα cgroup namespace με:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Αν θέλετε το `mountinfo` να εμφανίζει πιο καθαρά τη νέα ρίζα του cgroup namespace, κάντε remount στο cgroup filesystem μέσα από το νέο namespace και συγκρίνετε ξανά:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Και συγκρίνετε τη συμπεριφορά κατά την εκτέλεση με:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Η αλλαγή αφορά κυρίως το τι μπορεί να δει η διεργασία και όχι το αν υπάρχει επιβολή cgroup.

## Security Impact

Το cgroup namespace είναι καλύτερο να θεωρείται **layer ενίσχυσης της ορατότητας**. Από μόνο του δεν θα αποτρέψει ένα breakout αν το container έχει εγγράψιμα cgroup mounts, ευρείες capabilities ή ένα επικίνδυνο περιβάλλον cgroup v1. Ωστόσο, αν το cgroup namespace του host είναι κοινόχρηστο, η διεργασία μαθαίνει περισσότερα για τον τρόπο οργάνωσης του συστήματος και μπορεί να βρει ευκολότερα αντιστοιχίες μεταξύ των host-relative cgroup paths και άλλων παρατηρήσεων.

Στο **cgroup v2**, το namespace αποκτά κάπως μεγαλύτερη σημασία, επειδή οι κανόνες delegation είναι αυστηρότεροι. Αν η ιεραρχία είναι mounted με `nsdelegate`, ο kernel αντιμετωπίζει τα cgroup namespaces ως όρια delegation: τα control files των ancestors υποτίθεται ότι παραμένουν εκτός της εμβέλειας του delegatee, ενώ τα writes στο namespace root περιορίζονται σε delegation-safe files, όπως τα `cgroup.procs`, `cgroup.threads` και `cgroup.subtree_control`.<sup>[[2]](#references)</sup> Αυτό και πάλι δεν καθιστά το namespace escape primitive από μόνο του, αλλά αλλάζει το τι μπορεί να επιθεωρήσει ένα compromised workload και πού μπορεί να δημιουργήσει με ασφάλεια sub-cgroups.

Επομένως, παρότι αυτό το namespace συνήθως δεν αποτελεί το επίκεντρο των writeups για container breakout, εξακολουθεί να συμβάλλει στον ευρύτερο στόχο του περιορισμού του host information leakage και του περιορισμού του cgroup delegation.

## Abuse

Η άμεση αξία για abuse αφορά κυρίως το reconnaissance. Αν το cgroup namespace του host είναι κοινόχρηστο, συγκρίνετε τα ορατά paths και αναζητήστε λεπτομέρειες της ιεραρχίας που αποκαλύπτουν τον host:
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
Το ίδιο το namespace σπάνια παρέχει άμεσο escape, αλλά συχνά διευκολύνει τη χαρτογράφηση του περιβάλλοντος πριν από τον έλεγχο primitives για abuse που βασίζονται σε cgroup.

Ένας γρήγορος έλεγχος της πραγματικής συμπεριφοράς του runtime βοηθά επίσης στην ιεράρχηση του attack path. Το Docker εκθέτει τις επιλογές `--cgroupns=host|private`, ενώ το Podman υποστηρίζει `host`, `private`, `container:<id>` και `ns:<path>`. Ειδικά στο Podman, η προεπιλογή είναι συνήθως **`host` στο cgroup v1** και **`private` στο cgroup v2**, επομένως ο απλός εντοπισμός της έκδοσης του cgroup σάς ενημερώνει ήδη για το ποιο namespace posture είναι πιθανότερο, πριν καν επιθεωρήσετε ολόκληρο το OCI config.

### Modern v2 Recon: Είναι αυτό ένα Delegated Subtree;

Σε σύγχρονους hosts, το ενδιαφέρον ερώτημα συχνά δεν είναι το `release_agent`, αλλά αν η τρέχουσα διεργασία βρίσκεται μέσα σε ένα delegated **cgroup v2** subtree με αρκετή ορατότητα ή write access για τη δημιουργία nested groups:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Χρήσιμη ερμηνεία:

- Το `cgroup2fs` σημαίνει ότι βρίσκεστε στην ενοποιημένη ιεραρχία v2, επομένως οι κλασικές αλυσίδες `release_agent` που λειτουργούν μόνο σε v1 δεν θα πρέπει να είναι η πρώτη σας υπόθεση.
- Το `cgroup.controllers` εμφανίζει ποιοι controllers είναι διαθέσιμοι από το parent και, επομένως, σε ποιους children θα μπορούσε δυνητικά να επεκταθεί το τρέχον subtree.
- Το `cgroup.subtree_control` εμφανίζει ποιοι controllers είναι πράγματι ενεργοποιημένοι για τους descendants.
- Το `cgroup.events` εκθέτει την τιμή `populated=0/1`, η οποία είναι χρήσιμη για την παρακολούθηση του αν ένα subtree έχει αδειάσει, αλλά **δεν** αποτελεί primitive για host-code-execution όπως το v1 `release_agent`.

Αν έχετε ήδη επαρκή προνόμια για να επιθεωρήσετε απευθείας το namespace μιας άλλης διεργασίας, συγκρίνετε τις προβολές με:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Πλήρες Παράδειγμα: Shared cgroup Namespace + Writable cgroup v1

Το cgroup namespace από μόνο του συνήθως δεν επαρκεί για escape. Η πρακτική κλιμάκωση συμβαίνει όταν τα host-revealing cgroup paths συνδυάζονται με writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Αν αυτά τα αρχεία είναι προσβάσιμα και εγγράψιμα, κάντε αμέσως pivot στο πλήρες `release_agent` exploitation flow από το [cgroups.md](../cgroups.md). Ο αντίκτυπος είναι εκτέλεση κώδικα στον host από το εσωτερικό του container.

Χωρίς εγγράψιμα cgroup interfaces, ο αντίκτυπος περιορίζεται συνήθως σε reconnaissance.

## Έλεγχοι

Ο σκοπός αυτών των εντολών είναι να διαπιστωθεί αν η διεργασία έχει ιδιωτική προβολή του cgroup namespace ή αν μαθαίνει περισσότερα για την ιεραρχία του host από όσα πραγματικά χρειάζεται.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Τι είναι ενδιαφέρον εδώ:

- Αν το αναγνωριστικό του namespace αντιστοιχεί σε μια host process που σας ενδιαφέρει, το cgroup namespace ενδέχεται να είναι shared.
- Paths που αποκαλύπτουν το host στο `/proc/self/cgroup` ή entries στο `mountinfo` που βασίζονται στο ancestor root είναι χρήσιμα για reconnaissance, ακόμη και όταν δεν είναι άμεσα exploitable.
- Αν χρησιμοποιείται το `cgroup2fs`, εστιάστε στο delegation, στους visible controllers και στα writable subtrees, αντί να θεωρείτε δεδομένο ότι εξακολουθούν να υπάρχουν τα παλαιότερα v1 primitives.
- Αν τα cgroup mounts είναι επίσης writable, το ζήτημα της visibility γίνεται πολύ σημαντικότερο.

Το cgroup namespace θα πρέπει να αντιμετωπίζεται ως layer ενίσχυσης της visibility και όχι ως κύριος μηχανισμός αποτροπής escape. Η περιττή έκθεση της δομής των cgroup του host προσθέτει reconnaissance value για τον attacker.

## Αναφορές

- [1] [cgroup_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
