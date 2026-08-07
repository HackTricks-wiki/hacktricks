# Χώρος ονομάτων χρήστη

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ο χώρος ονομάτων χρήστη αλλάζει τη σημασία των user και group IDs, επιτρέποντας στον kernel να αντιστοιχίζει τα IDs που εμφανίζονται μέσα στον χώρο ονομάτων σε διαφορετικά IDs εκτός αυτού. Αυτή είναι μία από τις σημαντικότερες σύγχρονες προστασίες των containers, επειδή αντιμετωπίζει άμεσα το μεγαλύτερο ιστορικό πρόβλημα των κλασικών containers: **το root μέσα στο container βρισκόταν παλαιότερα επικίνδυνα κοντά στο root του host**.

Με τους user namespaces, μια διεργασία μπορεί να εκτελείται ως UID 0 μέσα στο container και παράλληλα να αντιστοιχεί σε ένα εύρος μη προνομιούχων UID στον host. Αυτό σημαίνει ότι η διεργασία μπορεί να συμπεριφέρεται σαν root για πολλές εργασίες μέσα στο container, ενώ από την οπτική γωνία του host έχει πολύ λιγότερες δυνατότητες. Αυτό δεν επιλύει κάθε πρόβλημα ασφάλειας των containers, αλλά αλλάζει σημαντικά τις συνέπειες ενός compromise του container.

## Λειτουργία

Ένας user namespace διαθέτει αρχεία mapping, όπως τα `/proc/self/uid_map` και `/proc/self/gid_map`, τα οποία περιγράφουν πώς τα IDs του namespace μεταφράζονται σε IDs του parent. Αν το root μέσα στον namespace αντιστοιχίζεται σε ένα μη προνομιούχο UID του host, τότε οι λειτουργίες που θα απαιτούσαν πραγματικό root στον host απλώς δεν έχουν την ίδια ισχύ. Για αυτό οι user namespaces είναι κεντρικοί στα **rootless containers** και αποτελούν μία από τις σημαντικότερες διαφορές μεταξύ των παλαιότερων rootful προεπιλεγμένων ρυθμίσεων containers και των πιο σύγχρονων σχεδιασμών least-privilege.

Το σημείο είναι λεπτό αλλά κρίσιμο: το root μέσα στο container δεν καταργείται, αλλά **μεταφράζεται**. Η διεργασία εξακολουθεί να βιώνει τοπικά ένα περιβάλλον παρόμοιο με root, όμως ο host δεν θα πρέπει να την αντιμετωπίζει ως πλήρες root.

## Εργαστήριο

Μια χειροκίνητη δοκιμή είναι:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Αυτό κάνει τον τρέχοντα χρήστη να εμφανίζεται ως root μέσα στο namespace, ενώ εξακολουθεί να μην είναι root του host εκτός αυτού. Είναι ένα από τα καλύτερα απλά παραδείγματα για την κατανόηση του γιατί τα user namespaces είναι τόσο πολύτιμα.

Στα containers, μπορείτε να συγκρίνετε το ορατό mapping με:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Η ακριβής έξοδος εξαρτάται από το αν το engine χρησιμοποιεί user namespace remapping ή μια πιο παραδοσιακή rootful διαμόρφωση.

Μπορείτε επίσης να διαβάσετε το mapping από την πλευρά του host με:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Χρήση κατά το Runtime

Το Rootless Podman είναι ένα από τα πιο σαφή παραδείγματα αντιμετώπισης των user namespaces ως μηχανισμού ασφάλειας πρώτης τάξης. Το Rootless Docker εξαρτάται επίσης από αυτά. Η υποστήριξη userns-remap του Docker βελτιώνει την ασφάλεια και σε deployments με rootful daemon, παρότι ιστορικά πολλά deployments την άφηναν απενεργοποιημένη για λόγους συμβατότητας. Η υποστήριξη των Kubernetes για user namespaces έχει βελτιωθεί, όμως η υιοθέτηση και οι προεπιλογές διαφέρουν ανάλογα με το runtime, το distro και την policy του cluster. Τα συστήματα Incus/LXC βασίζονται επίσης σε μεγάλο βαθμό σε ιδέες μετατόπισης UID/GID και idmapping.

Η γενική τάση είναι σαφής: τα environments που χρησιμοποιούν σοβαρά τα user namespaces συνήθως δίνουν καλύτερη απάντηση στο ερώτημα «τι σημαίνει πραγματικά το container root;» από ό,τι τα environments που δεν τα χρησιμοποιούν.

## Προχωρημένες λεπτομέρειες Mapping

Όταν μια unprivileged process γράφει στα `uid_map` ή `gid_map`, ο kernel εφαρμόζει αυστηρότερους κανόνες από αυτούς που εφαρμόζει όταν γράφει ένα privileged parent namespace. Επιτρέπονται μόνο περιορισμένα mappings και, για το `gid_map`, ο writer συνήθως πρέπει πρώτα να απενεργοποιήσει το `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Αυτή η λεπτομέρεια έχει σημασία, επειδή εξηγεί γιατί η ρύθμιση του user namespace αποτυγχάνει μερικές φορές σε rootless πειράματα και γιατί τα runtimes χρειάζονται προσεκτική βοηθητική λογική γύρω από την εκχώρηση UID/GID.

Ένα ακόμη advanced feature είναι το **ID-mapped mount**. Αντί να αλλάζει την ownership στον δίσκο, ένα ID-mapped mount εφαρμόζει ένα user-namespace mapping σε ένα mount, ώστε η ownership να εμφανίζεται μεταφρασμένη μέσα από αυτή την προβολή του mount. Αυτό είναι ιδιαίτερα σημαντικό σε rootless και σύγχρονες runtime εγκαταστάσεις, επειδή επιτρέπει τη χρήση κοινόχρηστων host paths χωρίς recursive λειτουργίες `chown`. Από άποψη security, το feature αλλάζει το πόσο writable εμφανίζεται ένα bind mount από μέσα στο namespace, παρόλο που δεν επανεγγράφει τα underlying filesystem metadata.

Τέλος, θυμήσου ότι όταν μια process δημιουργεί ή εισέρχεται σε ένα νέο user namespace, λαμβάνει ένα πλήρες σύνολο capabilities **μέσα σε αυτό το namespace**. Αυτό δεν σημαίνει ότι απέκτησε ξαφνικά host-global ισχύ. Σημαίνει ότι αυτές οι capabilities μπορούν να χρησιμοποιηθούν μόνο όπου το namespace model και οι υπόλοιπες protections το επιτρέπουν. Αυτός είναι ο λόγος για τον οποίο το `unshare -U` μπορεί ξαφνικά να καταστήσει δυνατές λειτουργίες mounting ή namespace-local privileged operations, χωρίς να εξαφανίζει άμεσα το host root boundary.

## Λανθασμένες ρυθμίσεις

Η σημαντικότερη αδυναμία είναι απλώς η μη χρήση user namespaces σε environments όπου αυτό θα ήταν εφικτό. Αν το container root αντιστοιχίζεται υπερβολικά άμεσα στο host root, τα writable host mounts και οι privileged kernel operations γίνονται πολύ πιο επικίνδυνα. Ένα ακόμη πρόβλημα είναι η επιβολή host user namespace sharing ή η απενεργοποίηση του remapping για λόγους compatibility, χωρίς να αναγνωρίζεται πόσο αλλάζει αυτό το trust boundary.

Τα user namespaces πρέπει επίσης να εξετάζονται μαζί με το υπόλοιπο model. Ακόμη και όταν είναι ενεργά, μια ευρεία έκθεση του runtime API ή μια πολύ αδύναμη runtime configuration μπορεί να επιτρέψει privilege escalation μέσω άλλων paths. Ωστόσο, χωρίς αυτά, πολλές παλιές κατηγορίες breakout γίνονται πολύ ευκολότερες στην εκμετάλλευση.

## Κατάχρηση

Αν το container είναι rootful χωρίς user namespace separation, ένα writable host bind mount γίνεται κατά πολύ πιο επικίνδυνο, επειδή η process μπορεί πράγματι να γράφει ως host root. Οι dangerous capabilities αποκτούν επίσης μεγαλύτερη σημασία. Ο attacker δεν χρειάζεται πλέον να αντιμετωπίσει τόσο έντονα το translation boundary, επειδή το translation boundary σχεδόν δεν υπάρχει.

Η παρουσία ή η απουσία user namespace πρέπει να ελέγχεται νωρίς κατά την αξιολόγηση ενός container breakout path. Δεν απαντά σε κάθε ερώτηση, αλλά δείχνει αμέσως αν το "root in container" έχει άμεση σημασία για το host.

Το πιο πρακτικό abuse pattern είναι να επιβεβαιωθεί το mapping και στη συνέχεια να ελεγχθεί άμεσα αν το host-mounted content είναι writable με privileges που σχετίζονται με το host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Εάν το αρχείο δημιουργηθεί ως πραγματικός root του host, η απομόνωση του user namespace ουσιαστικά απουσιάζει για τη συγκεκριμένη διαδρομή. Σε αυτό το σημείο, οι κλασικές καταχρήσεις αρχείων του host γίνονται ρεαλιστικές:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Μια ασφαλέστερη επιβεβαίωση κατά τη διάρκεια ενός live assessment είναι η εγγραφή ενός benign marker αντί για την τροποποίηση κρίσιμων αρχείων:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Αυτοί οι έλεγχοι έχουν σημασία επειδή απαντούν γρήγορα στο πραγματικό ερώτημα: το root σε αυτό το container αντιστοιχίζεται αρκετά στενά με το root του host, ώστε ένα writable host mount να μετατρέπεται άμεσα σε μονοπάτι compromise του host;

### Πλήρες Παράδειγμα: Ανάκτηση Capabilities Τοπικά στο Namespace

Αν το seccomp επιτρέπει το `unshare` και το περιβάλλον επιτρέπει τη δημιουργία ενός νέου user namespace, η διεργασία μπορεί να ανακτήσει ένα πλήρες σύνολο capabilities μέσα σε αυτό το νέο namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Αυτό από μόνο του δεν αποτελεί host escape. Ο λόγος που έχει σημασία είναι ότι τα user namespaces μπορούν να επανενεργοποιήσουν προνομιακές ενέργειες τοπικές στο namespace, οι οποίες στη συνέχεια συνδυάζονται με αδύναμα mounts, ευάλωτους kernels ή ανεπαρκώς προστατευμένες runtime επιφάνειες.

## Έλεγχοι

Αυτές οι εντολές αποσκοπούν στο να απαντήσουν στο σημαντικότερο ερώτημα αυτής της σελίδας: σε ποιον χρήστη στο host αντιστοιχεί ο root μέσα σε αυτό το container;
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Τι είναι ενδιαφέρον εδώ:

- Αν η διεργασία έχει UID 0 και τα maps δείχνουν απευθείας ή πολύ κοντινή αντιστοίχιση με το host root, το container είναι πολύ πιο επικίνδυνο.
- Αν το root αντιστοιχίζεται σε μια μη προνομιούχα περιοχή του host, αυτό αποτελεί πολύ ασφαλέστερη βάση και συνήθως υποδεικνύει πραγματική απομόνωση user namespace.
- Τα αρχεία αντιστοίχισης είναι πιο χρήσιμα από το `id` από μόνο του, επειδή το `id` εμφανίζει μόνο την ταυτότητα που ισχύει τοπικά στο namespace.

Αν το workload εκτελείται ως UID 0 και η αντιστοίχιση δείχνει ότι αυτό αντιστοιχεί σχεδόν στο host root, θα πρέπει να αξιολογήσεις τις υπόλοιπες δυνατότητες του container με πολύ αυστηρότερα κριτήρια.

{{#include ../../../../../banners/hacktricks-training.md}}
