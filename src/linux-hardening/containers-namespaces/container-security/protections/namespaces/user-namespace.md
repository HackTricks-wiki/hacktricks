# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το user namespace αλλάζει τη σημασία των user και group IDs, επιτρέποντας στον kernel να αντιστοιχίζει τα IDs που εμφανίζονται μέσα στο namespace σε διαφορετικά IDs εκτός αυτού. Αυτή είναι μία από τις σημαντικότερες σύγχρονες προστασίες των containers, επειδή αντιμετωπίζει άμεσα το μεγαλύτερο ιστορικό πρόβλημα των κλασικών containers: **το root μέσα στο container ήταν υπερβολικά κοντά στο root του host**.

Με τα user namespaces, μια διεργασία μπορεί να εκτελείται ως UID 0 μέσα στο container και παρ' όλα αυτά να αντιστοιχεί σε ένα μη προνομιούχο εύρος UID στον host. Αυτό σημαίνει ότι η διεργασία μπορεί να συμπεριφέρεται σαν root για πολλές εργασίες μέσα στο container, ενώ από την οπτική γωνία του host έχει πολύ λιγότερη ισχύ. Αυτό δεν επιλύει κάθε πρόβλημα ασφάλειας των containers, αλλά αλλάζει σημαντικά τις συνέπειες ενός container compromise.

## Λειτουργία

Ένα user namespace διαθέτει mapping files, όπως τα `/proc/self/uid_map` και `/proc/self/gid_map`, τα οποία περιγράφουν πώς τα IDs του namespace μεταφράζονται σε IDs του parent. Αν το root μέσα στο namespace αντιστοιχεί σε ένα μη προνομιούχο UID του host, τότε οι ενέργειες που θα απαιτούσαν πραγματικό root στον host απλώς δεν έχουν την ίδια ισχύ. Γι' αυτό τα user namespaces είναι βασικό στοιχείο των **rootless containers** και αποτελούν μία από τις μεγαλύτερες διαφορές μεταξύ των παλαιότερων rootful container defaults και των πιο σύγχρονων σχεδίων least-privilege.

Το σημείο αυτό είναι λεπτό αλλά κρίσιμο: το root μέσα στο container δεν καταργείται, αλλά **μεταφράζεται**. Η διεργασία εξακολουθεί να βιώνει ένα τοπικό περιβάλλον που μοιάζει με root, όμως ο host δεν θα πρέπει να την αντιμετωπίζει ως πλήρες root.

## Εργαστήριο

Ένα manual test είναι:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Αυτό κάνει τον τρέχοντα χρήστη να εμφανίζεται ως root μέσα στο namespace, ενώ εκτός αυτού εξακολουθεί να μην είναι host root. Είναι ένα από τα καλύτερα απλά παραδείγματα για την κατανόηση του λόγου για τον οποίο τα user namespaces είναι τόσο σημαντικά.

Στα containers, μπορείτε να συγκρίνετε την ορατή αντιστοίχιση με:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Η ακριβής έξοδος εξαρτάται από το αν το engine χρησιμοποιεί user namespace remapping ή μια πιο παραδοσιακή rootful διαμόρφωση.

Μπορείτε επίσης να διαβάσετε την αντιστοίχιση από την πλευρά του host με:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Χρήση κατά την εκτέλεση

Το Rootless Podman είναι ένα από τα σαφέστερα παραδείγματα user namespaces που αντιμετωπίζονται ως πρωταρχικός μηχανισμός ασφάλειας. Το Rootless Docker βασίζεται επίσης σε αυτά. Η υποστήριξη userns-remap του Docker βελτιώνει την ασφάλεια και σε αναπτύξεις daemon με root, αν και ιστορικά πολλές αναπτύξεις την άφηναν απενεργοποιημένη για λόγους συμβατότητας. Η υποστήριξη των Kubernetes για user namespaces έχει βελτιωθεί, όμως η υιοθέτηση και οι προεπιλογές διαφέρουν ανάλογα με το runtime, το distro και την πολιτική του cluster. Τα συστήματα Incus/LXC βασίζονται επίσης σε μεγάλο βαθμό σε ιδέες μετατόπισης UID/GID και idmapping.

Η γενική τάση είναι σαφής: τα περιβάλλοντα που χρησιμοποιούν σοβαρά user namespaces συνήθως παρέχουν καλύτερη απάντηση στο ερώτημα «τι σημαίνει στην πραγματικότητα το root του container;» σε σχέση με τα περιβάλλοντα που δεν τα χρησιμοποιούν.

## Προηγμένες λεπτομέρειες αντιστοίχισης

Όταν μια μη προνομιούχα διεργασία γράφει στα `uid_map` ή `gid_map`, ο kernel εφαρμόζει αυστηρότερους κανόνες από αυτούς που εφαρμόζει σε έναν εγγράφο από προνομιούχο parent namespace. Επιτρέπονται μόνο περιορισμένες αντιστοιχίσεις και, για το `gid_map`, ο εγγράφος συνήθως πρέπει πρώτα να απενεργοποιήσει το `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Αυτή η λεπτομέρεια έχει σημασία, επειδή εξηγεί γιατί η ρύθμιση του user namespace μερικές φορές αποτυγχάνει σε rootless πειράματα και γιατί τα runtimes χρειάζονται προσεκτική helper logic γύρω από την delegation των UID/GID.

Ένα ακόμη advanced feature είναι το **ID-mapped mount**. Αντί να αλλάζει την ownership στον δίσκο, ένα ID-mapped mount εφαρμόζει ένα user-namespace mapping σε ένα mount, ώστε η ownership να εμφανίζεται μεταφρασμένη μέσω αυτής της προβολής του mount. Αυτό είναι ιδιαίτερα σημαντικό σε rootless και σύγχρονες runtime εγκαταστάσεις, επειδή επιτρέπει τη χρήση shared host paths χωρίς recursive `chown` operations. Από άποψη ασφάλειας, το feature αλλάζει το πόσο writable εμφανίζεται ένα bind mount μέσα από το namespace, παρόλο που δεν επανεγγράφει τα υποκείμενα filesystem metadata.

Τέλος, θυμήσου ότι όταν μια process δημιουργεί ή εισέρχεται σε ένα νέο user namespace, λαμβάνει ένα πλήρες capability set **μέσα σε αυτό το namespace**. Αυτό δεν σημαίνει ότι απέκτησε ξαφνικά host-global power. Σημαίνει ότι αυτά τα capabilities μπορούν να χρησιμοποιηθούν μόνο όπου το namespace model και οι υπόλοιπες protections το επιτρέπουν. Αυτός είναι ο λόγος για τον οποίο το `unshare -U` μπορεί ξαφνικά να καταστήσει δυνατές λειτουργίες mounting ή privileged operations τοπικές στο namespace, χωρίς να εξαφανίσει άμεσα το host root boundary.

## Εσφαλμένες ρυθμίσεις

Η βασική αδυναμία είναι απλώς η μη χρήση user namespaces σε περιβάλλοντα όπου αυτό θα ήταν εφικτό. Αν το container root αντιστοιχίζεται υπερβολικά άμεσα στο host root, τα writable host mounts και οι privileged kernel operations γίνονται πολύ πιο επικίνδυνα. Ένα ακόμη πρόβλημα είναι η επιβολή host user namespace sharing ή η απενεργοποίηση του remapping για λόγους compatibility, χωρίς να αναγνωρίζεται πόσο αλλάζει αυτό το trust boundary.

Τα user namespaces πρέπει επίσης να εξετάζονται μαζί με το υπόλοιπο model. Ακόμη και όταν είναι ενεργά, ένα broad runtime API exposure ή μια πολύ αδύναμη runtime configuration μπορεί να επιτρέψει privilege escalation μέσω άλλων paths. Όμως χωρίς αυτά, πολλές παλιές breakout classes γίνονται πολύ ευκολότερες στην εκμετάλλευση.

## Κατάχρηση

Αν το container είναι rootful χωρίς user namespace separation, ένα writable host bind mount γίνεται κατά πολύ πιο επικίνδυνο, επειδή η process μπορεί πραγματικά να γράφει ως host root. Τα dangerous capabilities αποκτούν επίσης μεγαλύτερη σημασία. Ο attacker δεν χρειάζεται πλέον να αντιμετωπίσει τόσο έντονα το translation boundary, επειδή το translation boundary σχεδόν δεν υπάρχει.

Η παρουσία ή η απουσία user namespace πρέπει να ελέγχεται νωρίς κατά την αξιολόγηση ενός container breakout path. Δεν απαντά σε κάθε ερώτηση, αλλά δείχνει αμέσως αν το "root in container" έχει άμεση σχέση με το host.

Το πιο πρακτικό abuse pattern είναι να επιβεβαιώσεις το mapping και στη συνέχεια να ελέγξεις αμέσως αν το host-mounted content είναι writable με host-relevant privileges:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Εάν το αρχείο δημιουργηθεί ως ο πραγματικός root του host, η απομόνωση του user namespace ουσιαστικά απουσιάζει για αυτήν τη διαδρομή. Σε αυτό το σημείο, οι κλασικές καταχρήσεις αρχείων του host γίνονται ρεαλιστικές:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Μια ασφαλέστερη επιβεβαίωση σε μια live assessment είναι να γράψετε ένα benign marker αντί να τροποποιήσετε κρίσιμα αρχεία:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Αυτοί οι έλεγχοι έχουν σημασία επειδή απαντούν γρήγορα στο πραγματικό ερώτημα: το root σε αυτό το container αντιστοιχεί αρκετά στενά στο root του host, ώστε ένα writable host mount να γίνει άμεσα μονοπάτι για compromise του host;

### Πλήρες Παράδειγμα: Ανάκτηση Capabilities Τοπικών στο Namespace

Αν το seccomp επιτρέπει το `unshare` και το περιβάλλον επιτρέπει τη δημιουργία ενός νέου user namespace, η διεργασία μπορεί να ανακτήσει ένα πλήρες σύνολο capabilities μέσα σε αυτό το νέο namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Αυτό από μόνο του δεν αποτελεί host escape. Ο λόγος που έχει σημασία είναι ότι τα user namespaces μπορούν να επανενεργοποιήσουν προνομιακές ενέργειες τοπικές στο namespace, οι οποίες αργότερα συνδυάζονται με weak mounts, ευάλωτους kernels ή ανεπαρκώς προστατευμένες runtime surfaces.

## Έλεγχοι

Αυτές οι εντολές έχουν ως στόχο να απαντήσουν στο σημαντικότερο ερώτημα αυτής της σελίδας: σε τι αντιστοιχεί το root μέσα σε αυτό το container στο host;
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Τι είναι ενδιαφέρον εδώ:

- Αν η διεργασία είναι UID 0 και τα maps δείχνουν άμεση ή πολύ κοντινή αντιστοίχιση με το host root, το container είναι πολύ πιο επικίνδυνο.
- Αν το root αντιστοιχίζεται σε unprivileged εύρος του host, αυτό αποτελεί πολύ ασφαλέστερη baseline και συνήθως υποδεικνύει πραγματική απομόνωση user namespace.
- Τα αρχεία αντιστοίχισης είναι πιο χρήσιμα από το `id` μόνο του, επειδή το `id` εμφανίζει μόνο την ταυτότητα που ισχύει τοπικά στο namespace.

Αν το workload εκτελείται ως UID 0 και η αντιστοίχιση δείχνει ότι αυτό αντιστοιχεί σχεδόν άμεσα στο host root, θα πρέπει να αξιολογήσετε τα υπόλοιπα privileges του container με πολύ αυστηρότερα κριτήρια.
{{#include ../../../../../banners/hacktricks-training.md}}
