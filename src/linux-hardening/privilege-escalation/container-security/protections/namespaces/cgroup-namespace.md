# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Το cgroup namespace δεν αντικαθιστά τα cgroups και δεν επιβάλλει το ίδιο όρια πόρων. Αντίθετα, αλλάζει το **πώς εμφανίζεται η ιεραρχία cgroup** στη διεργασία. Με άλλα λόγια, εικονικοποιεί τις ορατές πληροφορίες του cgroup path ώστε το workload να βλέπει μια προβολή περιορισμένη στο container αντί για την πλήρη ιεραρχία του host.

Αυτό είναι κυρίως μια δυνατότητα ορατότητας και μείωσης πληροφοριών. Βοηθά να φαίνεται ότι το περιβάλλον είναι αυτοτελές και αποκαλύπτει λιγότερα για τη διάταξη cgroup του host. Αυτό μπορεί να ακούγεται μικρό, αλλά εξακολουθεί να έχει σημασία επειδή η περιττή ορατότητα στη δομή του host μπορεί να βοηθήσει το reconnaissance και να απλοποιήσει exploit chains που εξαρτώνται από το περιβάλλον.

## Operation

Χωρίς private cgroup namespace, μια διεργασία μπορεί να βλέπει host-relative cgroup paths που αποκαλύπτουν περισσότερη από την ιεραρχία του μηχανήματος απ’ ό,τι είναι χρήσιμο. Με private cgroup namespace, τα `/proc/self/cgroup` και οι σχετικές παρατηρήσεις γίνονται πιο τοπικές στην προβολή του container. Αυτό είναι ιδιαίτερα χρήσιμο σε σύγχρονα runtime stacks που θέλουν το workload να βλέπει ένα πιο καθαρό, λιγότερο αποκαλυπτικό για τον host περιβάλλον.

Η εικονικοποίηση επηρεάζει επίσης το `/proc/<pid>/mountinfo`, όχι μόνο το `/proc/<pid>/cgroup`. Όταν διαβάζεις άλλη διεργασία από διαφορετική cgroup-namespace οπτική, οι paths έξω από το root του namespace σου εμφανίζονται με leading `../` components, κάτι που είναι μια χρήσιμη ένδειξη ότι κοιτάς πάνω από το delegated subtree σου. Μια χρήσιμη λεπτομέρεια για labs και post-exploitation είναι ότι ένα πρόσφατα δημιουργημένο cgroup namespace συχνά χρειάζεται ένα **cgroupfs remount from inside that namespace** πριν το `mountinfo` αντικατοπτρίζει καθαρά το νέο root. Αλλιώς μπορεί να εξακολουθείς να βλέπεις ένα mount root όπως `/..`, που σημαίνει ότι το inherited mount εξακολουθεί να εκθέτει μια προβολή με root σε ancestor, παρότι το ίδιο το namespace έχει ήδη αλλάξει.

## Lab

Μπορείς να επιθεωρήσεις ένα cgroup namespace με:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Αν θέλεις το `mountinfo` να δείχνει πιο καθαρά τη νέα ρίζα του cgroup-namespace, κάνε remount το cgroup filesystem από μέσα στο νέο namespace και σύγκρινε ξανά:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Και σύγκρινε τη συμπεριφορά εκτέλεσης με:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Η αλλαγή αφορά κυρίως το τι μπορεί να δει το process, όχι το αν υπάρχει επιβολή cgroup.

## Security Impact

Το cgroup namespace κατανοείται καλύτερα ως ένα **visibility-hardening layer**. Από μόνο του δεν θα σταματήσει ένα breakout αν το container έχει writable cgroup mounts, broad capabilities, ή ένα dangerous cgroup v1 environment. Ωστόσο, αν το host cgroup namespace είναι shared, το process μαθαίνει περισσότερα για το πώς είναι οργανωμένο το system και μπορεί να βρει πιο εύκολα να αντιστοιχίσει host-relative cgroup paths με άλλες παρατηρήσεις.

Στο **cgroup v2**, το namespace αρχίζει να έχει λίγο μεγαλύτερη σημασία επειδή οι delegation rules είναι πιο αυστηρές. Αν η hierarchy είναι mounted με `nsdelegate`, το kernel αντιμετωπίζει τα cgroup namespaces ως delegation boundaries: τα ancestor control files υποτίθεται ότι παραμένουν έξω από το reach του delegatee, και τα writes στο namespace root περιορίζονται σε delegation-safe files όπως `cgroup.procs`, `cgroup.threads`, και `cgroup.subtree_control`. Αυτό εξακολουθεί να μην κάνει το namespace escape primitive από μόνο του, αλλά αλλάζει τι μπορεί να inspect ένα compromised workload και πού μπορεί να δημιουργήσει με ασφάλεια sub-cgroups.

Άρα, παρότι αυτό το namespace συνήθως δεν είναι το star των container breakout writeups, εξακολουθεί να συμβάλλει στον ευρύτερο στόχο του περιορισμού host information leakage και του περιορισμού της cgroup delegation.

## Abuse

Η άμεση αξία abuse είναι κυρίως reconnaissance. Αν το host cgroup namespace είναι shared, σύγκρινε τα visible paths και ψάξε για hierarchy details που αποκαλύπτουν host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Αν εκτίθενται επίσης writable cgroup paths, συνδύασε αυτή την ορατότητα με αναζήτηση για επικίνδυνα legacy interfaces:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Το ίδιο το namespace σπάνια δίνει άμεση escape, αλλά συχνά κάνει το environment πιο εύκολο να χαρτογραφηθεί πριν το testing των cgroup-based abuse primitives.

Ένας γρήγορος runtime reality check βοηθά επίσης να ιεραρχήσεις το attack path. Το Docker εκθέτει `--cgroupns=host|private`, ενώ το Podman υποστηρίζει `host`, `private`, `container:<id>`, και `ns:<path>`. Συγκεκριμένα στο Podman, το default είναι συνήθως **`host` στο cgroup v1** και **`private` στο cgroup v2**, οπότε απλώς εντοπίζοντας το cgroup version ήδη σου λέει ποια namespace posture είναι πιο πιθανή πριν καν εξετάσεις το πλήρες OCI config.

### Modern v2 Recon: Is This A Delegated Subtree?

Σε modern hosts το ενδιαφέρον ερώτημα συχνά δεν είναι το `release_agent`, αλλά αν η τρέχουσα process βρίσκεται μέσα σε ένα delegated **cgroup v2** subtree με αρκετή visibility ή write access για να δημιουργήσει nested groups:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Χρήσιμη ερμηνεία:

- Το `cgroup2fs` σημαίνει ότι βρίσκεσαι στην ενοποιημένη v2 ιεραρχία, οπότε τα κλασικά chains `release_agent` μόνο για v1 θα πρέπει να πάψουν να είναι η πρώτη σου υπόθεση.
- Το `cgroup.controllers` δείχνει ποιοι controllers είναι διαθέσιμοι από τον parent και, άρα, σε τι θα μπορούσε δυνητικά να διακλαδωθεί το τρέχον subtree προς τα children.
- Το `cgroup.subtree_control` δείχνει ποιοι controllers είναι πραγματικά ενεργοποιημένοι για descendants.
- Το `cgroup.events` εκθέτει `populated=0/1`, κάτι χρήσιμο για να παρακολουθείς αν ένα subtree έχει αδειάσει, αλλά **δεν** είναι primitive εκτέλεσης host-code σαν το v1 `release_agent`.

Αν έχεις ήδη αρκετό privilege για να επιθεωρήσεις απευθείας το namespace άλλης διεργασίας, σύγκρινε views με:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Πλήρες Παράδειγμα: Shared cgroup Namespace + Writable cgroup v1

Το cgroup namespace μόνο του συνήθως δεν αρκεί για escape. Η πρακτική escalation συμβαίνει όταν τα host-revealing cgroup paths συνδυάζονται με writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Εάν αυτά τα αρχεία είναι προσβάσιμα και εγγράψιμα, κάνε pivot αμέσως στο πλήρες `release_agent` exploitation flow από [cgroups.md](../cgroups.md). Το impact είναι host code execution από μέσα στο container.

Χωρίς writable cgroup interfaces, το impact συνήθως περιορίζεται σε reconnaissance.

## Checks

Ο σκοπός αυτών των εντολών είναι να δεις αν η διεργασία έχει private cgroup namespace view ή αν μαθαίνει περισσότερα για την host hierarchy απ’ όσα πραγματικά χρειάζεται.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Τι είναι ενδιαφέρον εδώ:

- Εάν το namespace identifier ταιριάζει με μια host process που σε ενδιαφέρει, το cgroup namespace μπορεί να είναι shared.
- Host-revealing paths στο `/proc/self/cgroup` ή ancestor-rooted entries στο `mountinfo` είναι χρήσιμα reconnaissance ακόμα και όταν δεν είναι άμεσα exploitable.
- Αν χρησιμοποιείται `cgroup2fs`, εστίασε στη delegation, στους visible controllers και στα writable subtrees αντί να υποθέτεις ότι τα παλιά v1 primitives εξακολουθούν να υπάρχουν.
- Αν τα cgroup mounts είναι επίσης writable, το visibility question γίνεται πολύ πιο σημαντικό.

Το cgroup namespace πρέπει να αντιμετωπίζεται ως visibility-hardening layer και όχι ως primary escape-prevention mechanism. Η unnecessary έκθεση της host cgroup structure προσθέτει reconnaissance value για τον attacker.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
