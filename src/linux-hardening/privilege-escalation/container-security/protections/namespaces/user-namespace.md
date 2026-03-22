# Χώρος Ονομάτων Χρήστη

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ο user namespace αλλάζει τη σημασία των user και group IDs επιτρέποντας στον kernel να αντιστοιχίσει τα IDs που φαίνονται μέσα στο namespace σε διαφορετικά IDs έξω από αυτό. Αυτή είναι μία από τις πιο σημαντικές σύγχρονες προστασίες για container γιατί αντιμετωπίζει άμεσα το μεγαλύτερο ιστορικό πρόβλημα στα κλασικά containers: **root inside the container used to be uncomfortably close to root on the host**.

Με user namespaces, μια διεργασία μπορεί να τρέχει ως UID 0 μέσα στο container και παρ’ όλα αυτά να αντιστοιχεί σε ένα μη-προνομιούχο εύρος UID στον host. Αυτό σημαίνει ότι η διεργασία μπορεί να συμπεριφέρεται σαν root για πολλές εργασίες εντός του container ενώ είναι πολύ λιγότερο ισχυρή από την σκοπιά του host. Αυτό δεν λύνει κάθε πρόβλημα ασφάλειας container, αλλά αλλάζει σημαντικά τις συνέπειες μιας παραβίασης του container.

## Λειτουργία

Ένας user namespace έχει αρχεία αντιστοίχισης όπως τα `/proc/self/uid_map` και `/proc/self/gid_map` που περιγράφουν πως τα IDs του namespace μεταφράζονται σε parent IDs. Αν το root μέσα στο namespace αντιστοιχίζεται σε ένα μη-προνομιούχο host UID, τότε επιχειρήσεις που θα απαιτούσαν πραγματικό host root απλώς δεν έχουν το ίδιο βάρος. Γι’ αυτό οι user namespaces είναι κεντρικοί για τα **rootless containers** και γι’ αυτό αποτελούν μία από τις μεγαλύτερες διαφορές ανάμεσα σε παλαιότερες default ρυθμίσεις με root σε containers και σε πιο σύγχρονα σχέδια με least-privilege.

Το σημείο είναι λεπτό αλλά κρίσιμο: root inside the container δεν εξαλείφεται, αλλά είναι **μεταφρασμένο**. Η διεργασία εξακολουθεί να βιώνει ένα τοπικό περιβάλλον σαν του root, αλλά ο host δεν θα πρέπει να το αντιμετωπίζει ως πλήρες root.

## Εργαστήριο

Μια χειροκίνητη δοκιμή είναι:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Αυτό κάνει τον τρέχοντα χρήστη να εμφανίζεται ως root μέσα στο namespace, ενώ έξω από αυτό δεν είναι root του host. Είναι ένα από τα καλύτερα απλά demos για να καταλάβεις γιατί τα user namespaces είναι τόσο πολύτιμα.

Σε containers, μπορείς να συγκρίνεις την ορατή αντιστοίχιση με:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Η ακριβής έξοδος εξαρτάται από το αν το engine χρησιμοποιεί user namespace remapping ή μια πιο παραδοσιακή rootful configuration.

Μπορείτε επίσης να διαβάσετε το mapping από την πλευρά του host με:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Χρήση κατά την εκτέλεση

Το Rootless Podman είναι ένα από τα πιο ξεκάθαρα παραδείγματα όπου τα user namespaces αντιμετωπίζονται ως μηχανισμός ασφαλείας πρώτης τάξης. Το Rootless Docker εξαρτάται επίσης από αυτά. Η υποστήριξη userns-remap του Docker βελτιώνει την ασφάλεια σε rootful daemon αναπτύξεις επίσης, αν και ιστορικά πολλές αναπτύξεις το άφηναν απενεργοποιημένο για λόγους συμβατότητας. Η υποστήριξη του Kubernetes για user namespaces έχει βελτιωθεί, αλλά η υιοθέτηση και οι προεπιλογές διαφέρουν ανά runtime, distro και πολιτική του cluster. Τα συστήματα Incus/LXC βασίζονται επίσης σε μεγάλο βαθμό σε ιδέες μετατόπισης UID/GID και idmapping.

Η γενική τάση είναι σαφής: τα περιβάλλοντα που χρησιμοποιούν σοβαρά τα user namespaces συνήθως προσφέρουν καλύτερη απάντηση στο «τι σημαίνει πραγματικά το root ενός container;» από όσα δεν το κάνουν.

## Προηγμένες λεπτομέρειες αντιστοίχισης

Όταν μια μη προνομιούχα διεργασία γράφει σε `uid_map` ή `gid_map`, ο kernel εφαρμόζει πιο αυστηρούς κανόνες απ' ό,τι για έναν προνομιούχο που γράφει στο γονικό namespace. Επιτρέπονται μόνο περιορισμένες αντιστοιχίσεις, και για το `gid_map` ο γράφων συνήθως πρέπει πρώτα να απενεργοποιήσει το `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
This detail matters because it explains why user-namespace setup sometimes fails in rootless experiments and why runtimes need careful helper logic around UID/GID delegation.

Another advanced feature is the **ID-mapped mount**. Instead of changing on-disk ownership, an ID-mapped mount applies a user-namespace mapping to a mount so that ownership appears translated through that mount view. This is especially relevant in rootless and modern runtime setups because it allows shared host paths to be used without recursive `chown` operations. Security-wise, the feature changes how writable a bind mount appears from inside the namespace, even though it does not rewrite the underlying filesystem metadata.

Finally, remember that when a process creates or enters a new user namespace, it receives a full capability set **inside that namespace**. That does not mean it suddenly gained host-global power. It means those capabilities can be used only where the namespace model and other protections allow them. This is the reason `unshare -U` can suddenly make mounting or namespace-local privileged operations possible without directly making the host root boundary disappear.

## Misconfigurations

Η κύρια αδυναμία είναι απλώς το να μην χρησιμοποιούνται user namespaces σε περιβάλλοντα όπου θα ήταν εφικτά. Αν το container root αντιστοιχεί πολύ άμεσα στο host root, writable host mounts και προνομιούχες kernel operations γίνονται πολύ πιο επικίνδυνες. Ένα άλλο πρόβλημα είναι ο εξαναγκασμός κοινής χρήσης του host user namespace ή η απενεργοποίηση της remapping για συμβατότητα χωρίς να αναγνωρίζεται πόσο αυτό αλλάζει το όριο εμπιστοσύνης.

Τα user namespaces πρέπει επίσης να ληφθούν υπόψη μαζί με το υπόλοιπο μοντέλο. Ακόμα και όταν είναι ενεργά, μια ευρεία έκθεση του runtime API ή μια πολύ αδύναμη runtime ρύθμιση μπορεί να επιτρέψει privilege escalation μέσω άλλων διαδρομών. Χωρίς αυτά, όμως, πολλές παλιές κλάσεις breakout γίνονται πολύ πιο εύκολες στην εκμετάλλευση.

## Abuse

Εάν το container είναι rootful χωρίς διαχωρισμό user namespace, ένα writable host bind mount γίνεται πολύ πιο επικίνδυνο επειδή η διεργασία μπορεί όντως να γράφει ως host root. Επιβλαβείς capabilities επίσης αποκτούν μεγαλύτερη σημασία. Ο επιτιθέμενος δεν χρειάζεται να παλεύει τόσο πολύ με το translation boundary γιατί το translation boundary σχεδόν δεν υφίσταται.

Η παρουσία ή απουσία user namespace πρέπει να ελέγχεται νωρίς όταν αξιολογείται ένα container breakout path. Δεν απαντά σε κάθε ερώτηση, αλλά δείχνει αμέσως αν το "root in container" έχει άμεση σχετικότητα με το host.

Το πιο πρακτικό μοτίβο κατάχρησης είναι να επιβεβαιώσετε την αντιστοίχιση και στη συνέχεια να δοκιμάσετε αμέσως αν το host-mounted περιεχόμενο είναι εγγράψιμο με προνόμια σχετικά με το host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Εάν το αρχείο δημιουργηθεί ως πραγματικός host root, η απομόνωση του user namespace είναι ουσιαστικά ανύπαρκτη για αυτήν τη διαδρομή. Σε εκείνο το σημείο, οι κλασικές host-file καταχρήσεις γίνονται ρεαλιστικές:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Μια ασφαλέστερη επιβεβαίωση σε μια ζωντανή αξιολόγηση είναι να γράψετε έναν ακίνδυνο δείκτη αντί να τροποποιήσετε κρίσιμα αρχεία:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Οι έλεγχοι αυτοί έχουν σημασία επειδή απαντούν γρήγορα στην ουσιαστική ερώτηση: αντιστοιχεί το root σε αυτό το container αρκετά κοντά στο host root ώστε ένα writable host mount να γίνεται αμέσως host compromise path;

### Πλήρες Παράδειγμα: Επανακτώντας Namespace-Local Capabilities

Αν το seccomp επιτρέπει το `unshare` και το περιβάλλον επιτρέπει ένα νέο user namespace, η διεργασία μπορεί να ανακτήσει ένα πλήρες capability set μέσα σε αυτό το νέο namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Αυτό από μόνο του δεν αποτελεί host escape. Ο λόγος που έχει σημασία είναι ότι τα user namespaces μπορούν να επανενεργοποιήσουν privileged namespace-local ενέργειες που αργότερα συνδυάζονται με weak mounts, vulnerable kernels ή ανεπαρκώς εκτεθειμένα runtime surfaces.

## Έλεγχοι

Οι παρακάτω εντολές έχουν σκοπό να απαντήσουν την πιο σημαντική ερώτηση αυτής της σελίδας: σε τι αντιστοιχεί το root μέσα σε αυτό το container στον host;
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Τι είναι ενδιαφέρον εδώ:

- Αν η διεργασία είναι UID 0 και τα maps δείχνουν ένα άμεσο ή πολύ κοντινό host-root mapping, το container είναι πολύ πιο επικίνδυνο.
- Αν το root αντιστοιχίζεται σε ένα unprivileged host range, αυτό αποτελεί μια πολύ πιο ασφαλή βάση και συνήθως υποδηλώνει πραγματική user namespace isolation.
- Τα mapping files είναι πιο πολύτιμα από το `id` μόνο, επειδή το `id` δείχνει μόνο την namespace-local identity.

Αν το workload τρέχει ως UID 0 και το mapping δείχνει ότι αυτό αντιστοιχεί στενά στο host root, θα πρέπει να ερμηνεύσετε τα υπόλοιπα προνόμια του container πολύ πιο αυστηρά.
{{#include ../../../../../banners/hacktricks-training.md}}
