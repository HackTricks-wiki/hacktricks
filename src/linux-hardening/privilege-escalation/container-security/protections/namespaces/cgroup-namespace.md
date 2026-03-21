# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το cgroup namespace δεν αντικαθιστά τα cgroups και από μόνο του δεν επιβάλλει όρια πόρων. Αντίθετα, αλλάζει **πώς εμφανίζεται η ιεραρχία cgroup** στη διεργασία. Με άλλα λόγια, εικονικοποιεί τις ορατές πληροφορίες μονοπατιού cgroup ώστε το workload να βλέπει μια προβολή περιορισμένη στο container αντί για ολόκληρη την ιεραρχία του host.

Αυτό είναι κυρίως ένα χαρακτηριστικό ορατότητας και μείωσης πληροφοριών. Βοηθά το περιβάλλον να φαίνεται αυτο-περιορισμένο και αποκαλύπτει λιγότερα σχετικά με τη διάταξη cgroup του host. Αυτό μπορεί να φαίνεται ασήμαντο, αλλά έχει σημασία, επειδή περιττή ορατότητα στη δομή του host μπορεί να διευκολύνει το reconnaissance και να απλοποιήσει exploit chains που εξαρτώνται από το περιβάλλον.

## Λειτουργία

Χωρίς ένα ιδιωτικό cgroup namespace, μια διεργασία μπορεί να δει cgroup μονοπάτια σχετιζόμενα με το host που εκθέτουν μεγαλύτερο μέρος της ιεραρχίας της μηχανής απ' ό,τι είναι χρήσιμο. Με ένα ιδιωτικό cgroup namespace, `/proc/self/cgroup` και σχετικές παρατηρήσεις γίνονται πιο τοπικές στην ίδια την προβολή του container. Αυτό είναι ιδιαίτερα χρήσιμο σε σύγχρονες runtime stacks που θέλουν το workload να βλέπει ένα πιο καθαρό, λιγότερο αποκαλυπτικό για το host περιβάλλον.

## Εργαστήριο

Μπορείτε να επιθεωρήσετε ένα cgroup namespace με:
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
Η αλλαγή αφορά κυρίως το τι μπορεί να δει η διεργασία, όχι το αν υπάρχει cgroup enforcement.

## Επιπτώσεις Ασφαλείας

Η cgroup namespace κατανοείται καλύτερα ως ένα **επίπεδο ενίσχυσης της ορατότητας**. Από μόνη της δεν θα σταματήσει ένα breakout αν το container έχει εγγράψιμα cgroup mounts, ευρείες capabilities, ή ένα επικίνδυνο περιβάλλον cgroup v1. Ωστόσο, αν το host cgroup namespace είναι κοινόχρηστο, η διεργασία μαθαίνει περισσότερα για το πώς οργανώνεται το σύστημα και ίσως βρει πιο εύκολο να ευθυγραμμίσει host-relative cgroup paths με άλλες παρατηρήσεις.

Έτσι, ενώ αυτό το namespace συνήθως δεν είναι ο πρωταγωνιστής σε container breakout writeups, εξακολουθεί να συνεισφέρει στον ευρύτερο στόχο της ελαχιστοποίησης του host information leakage.

## Κατάχρηση

Η άμεση αξία κατάχρησης είναι κυρίως reconnaissance. Αν το host cgroup namespace είναι κοινόχρηστο, σύγκρινε τα ορατά paths και αναζήτησε λεπτομέρειες ιεραρχίας που αποκαλύπτουν το host:
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
Το namespace από μόνο του σπάνια δίνει άμεσο escape, αλλά συχνά κάνει το περιβάλλον πιο εύκολο στη χαρτογράφηση πριν τη δοκιμή cgroup-based abuse primitives.

### Πλήρες Παράδειγμα: Shared cgroup Namespace + Writable cgroup v1

Το cgroup namespace από μόνο του συνήθως δεν αρκεί για escape. Η πρακτική κλιμάκωση συμβαίνει όταν host-revealing cgroup paths συνδυάζονται με writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Αν αυτά τα αρχεία είναι προσβάσιμα και εγγράψιμα, μεταβείτε άμεσα στην πλήρη ροή εκμετάλλευσης `release_agent` από [cgroups.md](../cgroups.md). Το αποτέλεσμα είναι εκτέλεση κώδικα στο host από μέσα στο container.

Χωρίς εγγράψιμες διεπαφές cgroup, ο αντίκτυπος συνήθως περιορίζεται σε reconnaissance.

## Έλεγχοι

Ο σκοπός αυτών των εντολών είναι να διαπιστωθεί αν η διαδικασία έχει ιδιωτική προβολή του cgroup namespace ή αν μαθαίνει περισσότερα για την ιεραρχία του host απ' ό,τι πραγματικά χρειάζεται.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Τι είναι ενδιαφέρον εδώ:

- Εάν ο αναγνωριστής του namespace ταιριάζει με μια host διαδικασία που σας ενδιαφέρει, το cgroup namespace ενδέχεται να είναι κοινό.
- Τα μονοπάτια που αποκαλύπτουν τον host στο `/proc/self/cgroup` είναι χρήσιμη αναγνώριση ακόμη και όταν δεν είναι άμεσα εκμεταλλεύσιμα.
- Εάν τα cgroup mounts είναι επίσης εγγράψιμα, το ζήτημα της ορατότητας γίνεται πολύ πιο σημαντικό.

Το cgroup namespace πρέπει να αντιμετωπίζεται ως ένα επίπεδο σκληροποίησης της ορατότητας παρά ως κύριος μηχανισμός αποτροπής διαφυγής. Η αχρείαστη αποκάλυψη της host cgroup δομής προσθέτει αξία αναγνώρισης για τον επιτιθέμενο.
