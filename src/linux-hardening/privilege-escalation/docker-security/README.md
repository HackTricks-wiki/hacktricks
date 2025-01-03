# Docker Security

{{#include ../../../banners/hacktricks-training.md}}

## **Βασική Ασφάλεια Μηχανής Docker**

Η **μηχανή Docker** χρησιμοποιεί τα **Namespaces** και **Cgroups** του πυρήνα Linux για να απομονώσει τα κοντέινερ, προσφέροντας μια βασική στρώση ασφάλειας. Επιπλέον προστασία παρέχεται μέσω της **πτώσης Δυνατοτήτων**, **Seccomp** και **SELinux/AppArmor**, ενισχύοντας την απομόνωση των κοντέινερ. Ένα **auth plugin** μπορεί να περιορίσει περαιτέρω τις ενέργειες των χρηστών.

![Docker Security](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Ασφαλής Πρόσβαση στη Μηχανή Docker

Η μηχανή Docker μπορεί να προσπελαστεί είτε τοπικά μέσω ενός Unix socket είτε απομακρυσμένα χρησιμοποιώντας HTTP. Για απομακρυσμένη πρόσβαση, είναι απαραίτητο να χρησιμοποιούνται HTTPS και **TLS** για να διασφαλιστούν η εμπιστευτικότητα, η ακεραιότητα και η ταυτοποίηση.

Η μηχανή Docker, από προεπιλογή, ακούει στο Unix socket στο `unix:///var/run/docker.sock`. Στα συστήματα Ubuntu, οι επιλογές εκκίνησης του Docker ορίζονται στο `/etc/default/docker`. Για να επιτρέψετε απομακρυσμένη πρόσβαση στο Docker API και τον πελάτη, εκθέστε τον Docker daemon μέσω ενός HTTP socket προσθέτοντας τις παρακάτω ρυθμίσεις:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Ωστόσο, η έκθεση του Docker daemon μέσω HTTP δεν συνιστάται λόγω ανησυχιών σχετικά με την ασφάλεια. Είναι σκόπιμο να ασφαλίσετε τις συνδέσεις χρησιμοποιώντας HTTPS. Υπάρχουν δύο κύριες προσεγγίσεις για την ασφάλιση της σύνδεσης:

1. Ο πελάτης επαληθεύει την ταυτότητα του διακομιστή.
2. Και ο πελάτης και ο διακομιστής αλληλοεπιβεβαιώνουν την ταυτότητα ο ένας του άλλου.

Τα πιστοποιητικά χρησιμοποιούνται για να επιβεβαιώσουν την ταυτότητα ενός διακομιστή. Για λεπτομερείς παραδείγματα και των δύο μεθόδων, ανατρέξτε σε [**αυτήν την οδηγία**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Ασφάλεια Εικόνων Κοντέινερ

Οι εικόνες κοντέινερ μπορούν να αποθηκευτούν σε ιδιωτικά ή δημόσια αποθετήρια. Το Docker προσφέρει πολλές επιλογές αποθήκευσης για εικόνες κοντέινερ:

- [**Docker Hub**](https://hub.docker.com): Μια δημόσια υπηρεσία μητρώου από το Docker.
- [**Docker Registry**](https://github.com/docker/distribution): Ένα έργο ανοιχτού κώδικα που επιτρέπει στους χρήστες να φιλοξενούν το δικό τους μητρώο.
- [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Η εμπορική προσφορά μητρώου του Docker, που διαθέτει αυθεντικοποίηση χρηστών με βάση ρόλους και ενσωμάτωση με υπηρεσίες καταλόγου LDAP.

### Σάρωση Εικόνας

Τα κοντέινερ μπορεί να έχουν **ευπάθειες ασφαλείας** είτε λόγω της βασικής εικόνας είτε λόγω του λογισμικού που είναι εγκατεστημένο πάνω από τη βασική εικόνα. Το Docker εργάζεται σε ένα έργο που ονομάζεται **Nautilus** που εκτελεί σάρωση ασφαλείας των Κοντέινερ και καταγράφει τις ευπάθειες. Το Nautilus λειτουργεί συγκρίνοντας κάθε επίπεδο εικόνας Κοντέινερ με το αποθετήριο ευπαθειών για να εντοπίσει κενά ασφαλείας.

Για περισσότερες [**πληροφορίες διαβάστε αυτό**](https://docs.docker.com/engine/scan/).

- **`docker scan`**

Η εντολή **`docker scan`** σας επιτρέπει να σαρώσετε υπάρχουσες εικόνες Docker χρησιμοποιώντας το όνομα ή το ID της εικόνας. Για παράδειγμα, εκτελέστε την παρακάτω εντολή για να σαρώσετε την εικόνα hello-world:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
- [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <container_name>:<tag>
```
- [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
- [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Υπογραφή Εικόνας Docker

Η υπογραφή εικόνας Docker διασφαλίζει την ασφάλεια και την ακεραιότητα των εικόνων που χρησιμοποιούνται σε κοντέινερ. Ακολουθεί μια συνοπτική εξήγηση:

- **Docker Content Trust** χρησιμοποιεί το έργο Notary, βασισμένο στο The Update Framework (TUF), για τη διαχείριση της υπογραφής εικόνας. Για περισσότερες πληροφορίες, δείτε το [Notary](https://github.com/docker/notary) και το [TUF](https://theupdateframework.github.io).
- Για να ενεργοποιήσετε την εμπιστοσύνη περιεχομένου Docker, ρυθμίστε `export DOCKER_CONTENT_TRUST=1`. Αυτή η δυνατότητα είναι απενεργοποιημένη από προεπιλογή στην έκδοση Docker 1.10 και μεταγενέστερες.
- Με αυτή τη δυνατότητα ενεργοποιημένη, μόνο υπογεγραμμένες εικόνες μπορούν να ληφθούν. Η αρχική μεταφόρτωση εικόνας απαιτεί ρύθμιση κωδικών πρόσβασης για τα κλειδιά root και tagging, με το Docker να υποστηρίζει επίσης Yubikey για ενισχυμένη ασφάλεια. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [εδώ](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Η προσπάθεια λήψης μιας μη υπογεγραμμένης εικόνας με ενεργοποιημένη την εμπιστοσύνη περιεχομένου έχει ως αποτέλεσμα ένα σφάλμα "No trust data for latest".
- Για τις μεταφορτώσεις εικόνας μετά την πρώτη, το Docker ζητά τον κωδικό πρόσβασης του κλειδιού αποθετηρίου για να υπογράψει την εικόνα.

Για να δημιουργήσετε αντίγραφα ασφαλείας των ιδιωτικών σας κλειδιών, χρησιμοποιήστε την εντολή:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Όταν αλλάζετε Docker hosts, είναι απαραίτητο να μεταφέρετε τα κλειδιά root και repository για να διατηρήσετε τη λειτουργία.

## Χαρακτηριστικά Ασφαλείας Κοντέινερ

<details>

<summary>Περίληψη Χαρακτηριστικών Ασφαλείας Κοντέινερ</summary>

**Κύρια Χαρακτηριστικά Απομόνωσης Διαδικασιών**

Σε κοντεϊνεροποιημένα περιβάλλοντα, η απομόνωση έργων και των διαδικασιών τους είναι πρωταρχικής σημασίας για την ασφάλεια και τη διαχείριση πόρων. Ακολουθεί μια απλοποιημένη εξήγηση βασικών εννοιών:

**Namespaces**

- **Σκοπός**: Διασφαλίζει την απομόνωση πόρων όπως διαδικασίες, δίκτυο και συστήματα αρχείων. Ιδιαίτερα στο Docker, τα namespaces διατηρούν τις διαδικασίες ενός κοντέινερ ξεχωριστές από τον host και άλλα κοντέινερ.
- **Χρήση του `unshare`**: Η εντολή `unshare` (ή η υποκείμενη syscall) χρησιμοποιείται για τη δημιουργία νέων namespaces, παρέχοντας ένα επιπλέον επίπεδο απομόνωσης. Ωστόσο, ενώ το Kubernetes δεν μπλοκάρει εγγενώς αυτό, το Docker το κάνει.
- **Περιορισμός**: Η δημιουργία νέων namespaces δεν επιτρέπει σε μια διαδικασία να επιστρέψει στα προεπιλεγμένα namespaces του host. Για να διεισδύσει στα namespaces του host, συνήθως απαιτείται πρόσβαση στον κατάλογο `/proc` του host, χρησιμοποιώντας το `nsenter` για είσοδο.

**Control Groups (CGroups)**

- **Λειτουργία**: Χρησιμοποιούνται κυρίως για την κατανομή πόρων μεταξύ διαδικασιών.
- **Πτυχή Ασφαλείας**: Τα CGroups από μόνα τους δεν προσφέρουν ασφάλεια απομόνωσης, εκτός από τη δυνατότητα `release_agent`, η οποία, αν είναι κακώς ρυθμισμένη, θα μπορούσε ενδεχομένως να εκμεταλλευτεί για μη εξουσιοδοτημένη πρόσβαση.

**Capability Drop**

- **Σημασία**: Είναι ένα κρίσιμο χαρακτηριστικό ασφαλείας για την απομόνωση διαδικασιών.
- **Λειτουργικότητα**: Περιορίζει τις ενέργειες που μπορεί να εκτελέσει μια διαδικασία root απορρίπτοντας ορισμένες ικανότητες. Ακόμη και αν μια διαδικασία εκτελείται με δικαιώματα root, η έλλειψη των απαραίτητων ικανοτήτων την εμποδίζει να εκτελεί προνομιακές ενέργειες, καθώς οι syscalls θα αποτύχουν λόγω ανεπαρκών δικαιωμάτων.

Αυτές είναι οι **υπόλοιπες ικανότητες** μετά την απόρριψη των άλλων:
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
**Seccomp**

Είναι ενεργοποιημένο από προεπιλογή στο Docker. Βοηθά να **περιορίσει ακόμη περισσότερο τις syscalls** που μπορεί να καλέσει η διαδικασία.\
Το **προφίλ Seccomp Docker προεπιλογής** μπορεί να βρεθεί στο [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Το Docker έχει ένα πρότυπο που μπορείτε να ενεργοποιήσετε: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Αυτό θα επιτρέψει τη μείωση των δυνατοτήτων, των syscalls, της πρόσβασης σε αρχεία και φακέλους...

</details>

### Namespaces

**Namespaces** είναι μια δυνατότητα του πυρήνα Linux που **διαχωρίζει τους πόρους του πυρήνα** έτσι ώστε ένα σύνολο **διαδικασιών** να **βλέπει** ένα σύνολο **πόρων** ενώ ένα **άλλο** σύνολο **διαδικασιών** βλέπει ένα **διαφορετικό** σύνολο πόρων. Η δυνατότητα λειτουργεί με το να έχει τον ίδιο namespace για ένα σύνολο πόρων και διαδικασιών, αλλά αυτοί οι namespaces αναφέρονται σε διακριτούς πόρους. Οι πόροι μπορεί να υπάρχουν σε πολλαπλούς χώρους.

Το Docker χρησιμοποιεί τους παρακάτω Namespaces του πυρήνα Linux για να επιτύχει την απομόνωση των Container:

- pid namespace
- mount namespace
- network namespace
- ipc namespace
- UTS namespace

Για **περισσότερες πληροφορίες σχετικά με τους namespaces** ελέγξτε την παρακάτω σελίδα:

{{#ref}}
namespaces/
{{#endref}}

### cgroups

Η δυνατότητα του πυρήνα Linux **cgroups** παρέχει τη δυνατότητα να **περιορίσει τους πόρους όπως cpu, μνήμη, io, εύρος ζώνης δικτύου μεταξύ** ενός συνόλου διαδικασιών. Το Docker επιτρέπει τη δημιουργία Containers χρησιμοποιώντας τη δυνατότητα cgroup που επιτρέπει τον έλεγχο των πόρων για το συγκεκριμένο Container.\
Ακολουθεί ένα Container που δημιουργήθηκε με περιορισμένη μνήμη χώρου χρήστη στα 500m, περιορισμένη μνήμη πυρήνα στα 50m, μερίδιο cpu στα 512, blkioweight στα 400. Το μερίδιο CPU είναι μια αναλογία που ελέγχει τη χρήση CPU του Container. Έχει προεπιλεγμένη τιμή 1024 και εύρος μεταξύ 0 και 1024. Εάν τρία Containers έχουν το ίδιο μερίδιο CPU 1024, κάθε Container μπορεί να καταναλώσει έως και 33% της CPU σε περίπτωση διαμάχης πόρων CPU. Το blkio-weight είναι μια αναλογία που ελέγχει το IO του Container. Έχει προεπιλεγμένη τιμή 500 και εύρος μεταξύ 10 και 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Για να αποκτήσετε το cgroup ενός κοντέινερ, μπορείτε να κάνετε:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Για περισσότερες πληροφορίες ελέγξτε:

{{#ref}}
cgroups.md
{{#endref}}

### Δυνατότητες

Οι δυνατότητες επιτρέπουν **πιο λεπτομερή έλεγχο για τις δυνατότητες που μπορούν να επιτραπούν** για τον χρήστη root. Το Docker χρησιμοποιεί τη δυνατότητα του πυρήνα Linux για να **περιορίσει τις λειτουργίες που μπορούν να γίνουν μέσα σε ένα Container** ανεξαρτήτως του τύπου του χρήστη.

Όταν εκτελείται ένα docker container, η **διαδικασία απορρίπτει ευαίσθητες δυνατότητες που θα μπορούσε να χρησιμοποιήσει για να ξεφύγει από την απομόνωση**. Αυτό προσπαθεί να διασφαλίσει ότι η διαδικασία δεν θα είναι σε θέση να εκτελέσει ευαίσθητες ενέργειες και να ξεφύγει:

{{#ref}}
../linux-capabilities.md
{{#endref}}

### Seccomp στο Docker

Αυτή είναι μια λειτουργία ασφαλείας που επιτρέπει στο Docker να **περιορίσει τις syscalls** που μπορούν να χρησιμοποιηθούν μέσα στο container:

{{#ref}}
seccomp.md
{{#endref}}

### AppArmor στο Docker

**AppArmor** είναι μια βελτίωση του πυρήνα για να περιορίσει **containers** σε ένα **περιορισμένο** σύνολο **πόρων** με **προφίλ ανά πρόγραμμα**.:

{{#ref}}
apparmor.md
{{#endref}}

### SELinux στο Docker

- **Σύστημα Ετικετών**: Το SELinux ανα assigns μια μοναδική ετικέτα σε κάθε διαδικασία και αντικείμενο συστήματος αρχείων.
- **Επιβολή Πολιτικής**: Επιβάλλει πολιτικές ασφαλείας που καθορίζουν ποιες ενέργειες μπορεί να εκτελέσει μια ετικέτα διαδικασίας σε άλλες ετικέτες εντός του συστήματος.
- **Ετικέτες Διαδικασίας Container**: Όταν οι μηχανές container ξεκινούν διαδικασίες container, συνήθως τους ανατίθεται μια περιορισμένη ετικέτα SELinux, συνήθως `container_t`.
- **Ετικετοποίηση Αρχείων μέσα σε Containers**: Τα αρχεία μέσα στο container συνήθως ετικετοποιούνται ως `container_file_t`.
- **Κανόνες Πολιτικής**: Η πολιτική SELinux διασφαλίζει κυρίως ότι οι διαδικασίες με την ετικέτα `container_t` μπορούν να αλληλεπιδρούν μόνο (να διαβάζουν, να γράφουν, να εκτελούν) με αρχεία που ετικετοποιούνται ως `container_file_t`.

Αυτός ο μηχανισμός διασφαλίζει ότι ακόμη και αν μια διαδικασία μέσα σε ένα container παραβιαστεί, περιορίζεται να αλληλεπιδρά μόνο με αντικείμενα που έχουν τις αντίστοιχες ετικέτες, περιορίζοντας σημαντικά τη δυνητική ζημιά από τέτοιες παραβιάσεις.

{{#ref}}
../selinux.md
{{#endref}}

### AuthZ & AuthN

Στο Docker, ένα πρόσθετο εξουσιοδότησης παίζει κρίσιμο ρόλο στην ασφάλεια αποφασίζοντας αν θα επιτρέψει ή θα αποκλείσει αιτήματα προς τον daemon του Docker. Αυτή η απόφαση λαμβάνεται εξετάζοντας δύο βασικά συμφραζόμενα:

- **Συμφραζόμενα Αυθεντικοποίησης**: Αυτό περιλαμβάνει λεπτομερείς πληροφορίες σχετικά με τον χρήστη, όπως ποιος είναι και πώς έχει αυθεντικοποιηθεί.
- **Συμφραζόμενα Εντολής**: Αυτό περιλαμβάνει όλα τα σχετικά δεδομένα που σχετίζονται με το αίτημα που υποβάλλεται.

Αυτά τα συμφραζόμενα βοηθούν να διασφαλιστεί ότι μόνο νόμιμα αιτήματα από αυθεντικοποιημένους χρήστες επεξεργάζονται, ενισχύοντας την ασφάλεια των λειτουργιών του Docker.

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## DoS από ένα container

Εάν δεν περιορίζετε σωστά τους πόρους που μπορεί να χρησιμοποιήσει ένα container, ένα παραβιασμένο container θα μπορούσε να προκαλέσει DoS στον κεντρικό υπολογιστή όπου εκτελείται.

- CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
- DoS εύρους ζώνης
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Ενδιαφέροντα Flags Docker

### --privileged flag

Στην παρακάτω σελίδα μπορείτε να μάθετε **τι υποδηλώνει το flag `--privileged`**:

{{#ref}}
docker-privileged.md
{{#endref}}

### --security-opt

#### no-new-privileges

Εάν εκτελείτε ένα κοντέινερ όπου ένας επιτιθέμενος καταφέρνει να αποκτήσει πρόσβαση ως χρήστης χαμηλών δικαιωμάτων. Εάν έχετε ένα **κακώς ρυθμισμένο suid binary**, ο επιτιθέμενος μπορεί να το εκμεταλλευτεί και να **κλιμακώσει τα δικαιώματα μέσα** στο κοντέινερ. Αυτό μπορεί να του επιτρέψει να διαφύγει από αυτό.

Η εκτέλεση του κοντέινερ με την επιλογή **`no-new-privileges`** ενεργοποιημένη θα **αποτρέψει αυτόν τον τύπο κλιμάκωσης δικαιωμάτων**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Άλλα
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Για περισσότερες επιλογές **`--security-opt`** ελέγξτε: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Άλλες Σημαντικές Σκέψεις Ασφαλείας

### Διαχείριση Μυστικών: Καλές Πρακτικές

Είναι κρίσιμο να αποφεύγεται η ενσωμάτωση μυστικών απευθείας σε εικόνες Docker ή η χρήση μεταβλητών περιβάλλοντος, καθώς αυτές οι μέθοδοι εκθέτουν τις ευαίσθητες πληροφορίες σας σε οποιονδήποτε έχει πρόσβαση στο κοντέινερ μέσω εντολών όπως `docker inspect` ή `exec`.

**Docker volumes** είναι μια πιο ασφαλής εναλλακτική, που συνιστάται για την πρόσβαση σε ευαίσθητες πληροφορίες. Μπορούν να χρησιμοποιηθούν ως προσωρινό σύστημα αρχείων στη μνήμη, μειώνοντας τους κινδύνους που σχετίζονται με το `docker inspect` και την καταγραφή. Ωστόσο, οι χρήστες root και αυτοί με πρόσβαση `exec` στο κοντέινερ μπορεί να έχουν ακόμα πρόσβαση στα μυστικά.

**Docker secrets** προσφέρουν μια ακόμη πιο ασφαλή μέθοδο για τη διαχείριση ευαίσθητων πληροφοριών. Για περιπτώσεις που απαιτούν μυστικά κατά τη διάρκεια της φάσης κατασκευής της εικόνας, **BuildKit** προσφέρει μια αποδοτική λύση με υποστήριξη για μυστικά κατά την κατασκευή, βελτιώνοντας την ταχύτητα κατασκευής και παρέχοντας επιπλέον δυνατότητες.

Για να αξιοποιήσετε το BuildKit, μπορεί να ενεργοποιηθεί με τρεις τρόπους:

1. Μέσω μιας μεταβλητής περιβάλλοντος: `export DOCKER_BUILDKIT=1`
2. Προσθέτοντας πρόθεμα στις εντολές: `DOCKER_BUILDKIT=1 docker build .`
3. Ενεργοποιώντας το από προεπιλογή στη ρύθμιση Docker: `{ "features": { "buildkit": true } }`, ακολουθούμενο από μια επανεκκίνηση του Docker.

Το BuildKit επιτρέπει τη χρήση μυστικών κατά την κατασκευή με την επιλογή `--secret`, διασφαλίζοντας ότι αυτά τα μυστικά δεν περιλαμβάνονται στην κρυφή μνήμη κατασκευής της εικόνας ή στην τελική εικόνα, χρησιμοποιώντας μια εντολή όπως:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Για τα μυστικά που απαιτούνται σε ένα τρέχον κοντέινερ, **Docker Compose και Kubernetes** προσφέρουν ισχυρές λύσεις. Το Docker Compose χρησιμοποιεί ένα κλειδί `secrets` στην ορισμό υπηρεσίας για να καθορίσει τα αρχεία μυστικών, όπως φαίνεται σε ένα παράδειγμα `docker-compose.yml`:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Αυτή η ρύθμιση επιτρέπει τη χρήση μυστικών κατά την εκκίνηση υπηρεσιών με το Docker Compose.

Σε περιβάλλοντα Kubernetes, τα μυστικά υποστηρίζονται εγγενώς και μπορούν να διαχειριστούν περαιτέρω με εργαλεία όπως το [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Οι Ρόλοι Βασισμένοι σε Ελέγχους Πρόσβασης (RBAC) του Kubernetes ενισχύουν την ασφάλεια της διαχείρισης μυστικών, παρόμοια με το Docker Enterprise.

### gVisor

**gVisor** είναι ένας πυρήνας εφαρμογής, γραμμένος σε Go, που υλοποιεί ένα σημαντικό μέρος της επιφάνειας του συστήματος Linux. Περιλαμβάνει ένα [Open Container Initiative (OCI)](https://www.opencontainers.org) runtime που ονομάζεται `runsc` και παρέχει ένα **όριο απομόνωσης μεταξύ της εφαρμογής και του πυρήνα του host**. Το runtime `runsc` ενσωματώνεται με το Docker και το Kubernetes, διευκολύνοντας την εκτέλεση sandboxed containers.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** είναι μια κοινότητα ανοιχτού κώδικα που εργάζεται για την κατασκευή ενός ασφαλούς runtime κοντέινερ με ελαφριές εικονικές μηχανές που αισθάνονται και αποδίδουν όπως τα κοντέινερ, αλλά παρέχουν **ισχυρότερη απομόνωση φορτίου εργασίας χρησιμοποιώντας τεχνολογία εικονικοποίησης υλικού** ως δεύτερη γραμμή άμυνας.

{% embed url="https://katacontainers.io/" %}

### Συμβουλές Περίληψης

- **Μην χρησιμοποιείτε τη σημαία `--privileged` ή να τοποθετείτε ένα** [**Docker socket μέσα στο κοντέινερ**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Το docker socket επιτρέπει τη δημιουργία κοντέινερ, οπότε είναι ένας εύκολος τρόπος να αποκτήσετε πλήρη έλεγχο του host, για παράδειγμα, εκτελώντας ένα άλλο κοντέινερ με τη σημαία `--privileged`.
- **Μην εκτελείτε ως root μέσα στο κοντέινερ. Χρησιμοποιήστε έναν** [**διαφορετικό χρήστη**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **και** [**user namespaces**](https://docs.docker.com/engine/security/userns-remap/)**.** Ο root στο κοντέινερ είναι ο ίδιος με αυτόν στον host εκτός αν ανακατανεμηθεί με user namespaces. Είναι μόνο ελαφρώς περιορισμένος από, κυρίως, Linux namespaces, δυνατότητες και cgroups.
- [**Αφαιρέστε όλες τις δυνατότητες**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) και ενεργοποιήστε μόνο αυτές που απαιτούνται** (`--cap-add=...`). Πολλά φορτία εργασίας δεν χρειάζονται καμία δυνατότητα και η προσθήκη τους αυξάνει την έκταση μιας πιθανής επίθεσης.
- [**Χρησιμοποιήστε την επιλογή ασφαλείας “no-new-privileges”**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) για να αποτρέψετε τις διαδικασίες από το να αποκτούν περισσότερες δυνατότητες, για παράδειγμα μέσω suid binaries.
- [**Περιορίστε τους πόρους που είναι διαθέσιμοι στο κοντέινερ**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Οι περιορισμοί πόρων μπορούν να προστατεύσουν τη μηχανή από επιθέσεις άρνησης υπηρεσίας.
- **Ρυθμίστε** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(ή SELinux)** προφίλ για να περιορίσετε τις ενέργειες και τις syscalls που είναι διαθέσιμες για το κοντέινερ στο ελάχιστο που απαιτείται.
- **Χρησιμοποιήστε** [**επίσημες εικόνες docker**](https://docs.docker.com/docker-hub/official_images/) **και απαιτήστε υπογραφές** ή κατασκευάστε τις δικές σας βασισμένες σε αυτές. Μην κληρονομείτε ή χρησιμοποιείτε [backdoored](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) εικόνες. Αποθηκεύστε επίσης τα κλειδιά root, τη φράση πρόσβασης σε ασφαλές μέρος. Το Docker έχει σχέδια να διαχειρίζεται τα κλειδιά με το UCP.
- **Ανακατασκευάστε τακτικά** τις εικόνες σας για να **εφαρμόσετε διορθώσεις ασφαλείας στον host και τις εικόνες.**
- Διαχειριστείτε τα **μυστικά σας με σύνεση** ώστε να είναι δύσκολο για τον επιτιθέμενο να τα αποκτήσει.
- Εάν **εκθέτετε τον docker daemon χρησιμοποιήστε HTTPS** με πιστοποίηση πελάτη και διακομιστή.
- Στο Dockerfile σας, **προτιμήστε το COPY αντί για το ADD**. Το ADD εξάγει αυτόματα αρχεία zip και μπορεί να αντιγράψει αρχεία από URLs. Το COPY δεν έχει αυτές τις δυνατότητες. Όποτε είναι δυνατόν, αποφύγετε τη χρήση του ADD ώστε να μην είστε ευάλωτοι σε επιθέσεις μέσω απομακρυσμένων URLs και αρχείων Zip.
- Έχετε **χωριστά κοντέινερ για κάθε μικρο-υπηρεσία**
- **Μην τοποθετείτε ssh** μέσα στο κοντέινερ, το “docker exec” μπορεί να χρησιμοποιηθεί για ssh στο Κοντέινερ.
- Έχετε **μικρότερες** εικόνες κοντέινερ

## Docker Breakout / Privilege Escalation

Εάν είστε **μέσα σε ένα κοντέινερ docker** ή έχετε πρόσβαση σε έναν χρήστη στην **ομάδα docker**, μπορείτε να προσπαθήσετε να **διαφύγετε και να κλιμακώσετε τα προνόμια**:

{{#ref}}
docker-breakout-privilege-escalation/
{{#endref}}

## Docker Authentication Plugin Bypass

Εάν έχετε πρόσβαση στο docker socket ή έχετε πρόσβαση σε έναν χρήστη στην **ομάδα docker αλλά οι ενέργειές σας περιορίζονται από ένα docker auth plugin**, ελέγξτε αν μπορείτε να **παρακάμψετε αυτό:**

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## Hardening Docker

- Το εργαλείο [**docker-bench-security**](https://github.com/docker/docker-bench-security) είναι ένα σενάριο που ελέγχει δεκάδες κοινές βέλτιστες πρακτικές γύρω από την ανάπτυξη κοντέινερ Docker σε παραγωγή. Οι δοκιμές είναι όλες αυτοματοποιημένες και βασίζονται στο [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Πρέπει να εκτελέσετε το εργαλείο από τον host που εκτελεί το docker ή από ένα κοντέινερ με αρκετά προνόμια. Βρείτε **πώς να το εκτελέσετε στο README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Αναφορές

- [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
- [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
- [https://en.wikipedia.org/wiki/Linux_namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
- [https://docs.docker.com/engine/extend/plugins_authorization](https://docs.docker.com/engine/extend/plugins_authorization)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)


{{#include ../../../banners/hacktricks-training.md}}
