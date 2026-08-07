# Ασφάλεια Image, Signing Και Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Η ασφάλεια των Containers ξεκινά πριν από την εκκίνηση του workload. Το image καθορίζει ποια binaries, interpreters, libraries, startup scripts και ενσωματωμένες ρυθμίσεις φτάνουν στο production. Αν το image περιέχει backdoor, είναι παρωχημένο ή έχει δημιουργηθεί με secrets ενσωματωμένα σε αυτό, το runtime hardening που ακολουθεί λειτουργεί ήδη πάνω σε ένα compromised artifact.

Γι’ αυτό το image provenance, το vulnerability scanning, η signature verification και ο χειρισμός των secrets ανήκουν στην ίδια συζήτηση με τα namespaces και το seccomp. Προστατεύουν διαφορετική φάση του lifecycle, αλλά οι αποτυχίες εδώ συχνά καθορίζουν το attack surface που το runtime πρέπει αργότερα να περιορίσει.

## Image Registries Και Trust

Τα images μπορεί να προέρχονται από public registries, όπως το Docker Hub, ή από private registries που διαχειρίζεται ένας οργανισμός. Το ζήτημα ασφάλειας δεν είναι απλώς το πού βρίσκεται το image, αλλά το αν η ομάδα μπορεί να επιβεβαιώσει το provenance και την ακεραιότητά του. Η λήψη unsigned ή ανεπαρκώς tracked images από public sources αυξάνει τον κίνδυνο εισαγωγής malicious ή tampered content στο production. Ακόμη και τα internally hosted registries χρειάζονται σαφή ownership, review και trust policy.

Το Docker Content Trust χρησιμοποιούσε ιστορικά τις έννοιες των Notary και TUF για να απαιτεί signed images. Το ακριβές οικοσύστημα έχει εξελιχθεί, αλλά το διαχρονικό συμπέρασμα παραμένει χρήσιμο: η ταυτότητα και η ακεραιότητα του image θα πρέπει να μπορούν να επαληθευτούν και όχι να θεωρούνται δεδομένες.

Παράδειγμα ιστορικού Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Το νόημα του παραδείγματος δεν είναι ότι κάθε team πρέπει να συνεχίσει να χρησιμοποιεί τα ίδια tooling, αλλά ότι το signing και το key management είναι operational tasks και όχι αφηρημένη θεωρία.

## Vulnerability Scanning

Το image scanning βοηθά να απαντηθούν δύο διαφορετικά ερωτήματα. Πρώτον, περιέχει το image γνωστά vulnerable packages ή libraries; Δεύτερον, περιλαμβάνει το image περιττό software που διευρύνει το attack surface; Ένα image γεμάτο debugging tools, shells, interpreters και stale packages είναι τόσο ευκολότερο να γίνει exploit όσο και δυσκολότερο να αξιολογηθεί.

Παραδείγματα commonly used scanners περιλαμβάνουν:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Τα αποτελέσματα από αυτά τα tools πρέπει να ερμηνεύονται προσεκτικά. Ένα vulnerability σε ένα αχρησιμοποίητο package δεν έχει τον ίδιο κίνδυνο με ένα exposed RCE path, όμως και τα δύο παραμένουν σχετικά με τις αποφάσεις για το hardening.

## Build-Time Secrets

Ένα από τα παλαιότερα λάθη στα container build pipelines είναι η απευθείας ενσωμάτωση secrets στο image ή η μεταβίβασή τους μέσω environment variables, τα οποία αργότερα γίνονται ορατά μέσω του `docker inspect`, των build logs ή των layers που έχουν ανακτηθεί. Τα build-time secrets πρέπει να γίνονται mount προσωρινά κατά τη διάρκεια του build, αντί να αντιγράφονται στο filesystem του image.

Το BuildKit βελτίωσε αυτό το μοντέλο επιτρέποντας dedicated χειρισμό build-time secrets. Αντί να εγγράφεται ένα secret σε ένα layer, το build step μπορεί να το χρησιμοποιεί προσωρινά:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Αυτό έχει σημασία επειδή τα image layers είναι durable artifacts. Μόλις ένα secret εισαχθεί σε ένα committed layer, η μεταγενέστερη διαγραφή του αρχείου σε άλλο layer δεν αφαιρεί πραγματικά την αρχική disclosure από το image history.

## Runtime Secrets

Τα secrets που χρειάζεται ένα running workload θα πρέπει επίσης να αποφεύγουν ad hoc patterns, όπως τα plain environment variables, whenever possible. Τα volumes, τα dedicated secret-management integrations, τα Docker secrets και τα Kubernetes Secrets είναι συνήθεις μηχανισμοί. Κανένας από αυτούς δεν εξαλείφει κάθε κίνδυνο, ειδικά αν ο attacker έχει ήδη code execution στο workload, αλλά εξακολουθούν να είναι προτιμότεροι από τη μόνιμη αποθήκευση credentials στο image ή την απρόσεκτη έκθεσή τους μέσω inspection tooling.

Μια απλή δήλωση secret σε στυλ Docker Compose μοιάζει ως εξής:
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
Στο Kubernetes, τα αντικείμενα Secret, τα projected volumes, τα service-account tokens και τα cloud workload identities δημιουργούν ένα ευρύτερο και ισχυρότερο μοντέλο, αλλά παράλληλα δημιουργούν περισσότερες ευκαιρίες για accidental exposure μέσω host mounts, ευρέος RBAC ή αδύναμου σχεδιασμού Pod.

## Κατάχρηση

Κατά την αξιολόγηση ενός target, ο στόχος είναι να ανακαλυφθεί αν τα secrets είχαν ενσωματωθεί στο image, είχαν γίνει leak στα layers ή είχαν γίνει mount σε προβλέψιμες runtime τοποθεσίες:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Αυτές οι εντολές βοηθούν να διακρίνουμε τρία διαφορετικά προβλήματα: leaks από το configuration της εφαρμογής, leaks στα image layers και αρχεία secrets που εισάγονται κατά το runtime. Αν ένα secret εμφανίζεται στο `/run/secrets`, σε ένα projected volume ή σε ένα cloud identity token path, το επόμενο βήμα είναι να κατανοήσουμε αν παρέχει πρόσβαση μόνο στο τρέχον workload ή σε ένα πολύ μεγαλύτερο control plane.

### Πλήρες Παράδειγμα: Ενσωματωμένο Secret Στο Filesystem Του Image

Αν ένα build pipeline αντέγραψε αρχεία `.env` ή credentials στο τελικό image, το post-exploitation γίνεται απλό:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Ο αντίκτυπος εξαρτάται από την εφαρμογή, αλλά ενσωματωμένα signing keys, JWT secrets ή cloud credentials μπορούν εύκολα να μετατρέψουν την παραβίαση ενός container σε παραβίαση API, lateral movement ή πλαστογράφηση trusted application tokens.

### Πλήρες παράδειγμα: Έλεγχος για Secret Leak κατά το Build

Αν η ανησυχία είναι ότι το image history κατέγραψε ένα layer που περιείχε secret:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Αυτός ο έλεγχος είναι χρήσιμος, επειδή ένα secret μπορεί να έχει διαγραφεί από την τελική view του filesystem, ενώ εξακολουθεί να υπάρχει σε προηγούμενο layer ή στα build metadata.

## Έλεγχοι

Αυτοί οι έλεγχοι αποσκοπούν στο να διαπιστωθεί αν το pipeline διαχείρισης του image και των secret είναι πιθανό να έχει αυξήσει το attack surface πριν από το runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Τι είναι ενδιαφέρον εδώ:

- Ένα ύποπτο ιστορικό build μπορεί να αποκαλύψει αντιγραμμένα διαπιστευτήρια, υλικό SSH ή μη ασφαλή βήματα build.
- Τα secrets κάτω από διαδρομές projected volume μπορεί να οδηγήσουν σε πρόσβαση στο cluster ή στο cloud, όχι μόνο σε τοπική πρόσβαση στην εφαρμογή.
- Μεγάλος αριθμός αρχείων διαμόρφωσης με διαπιστευτήρια σε plaintext συνήθως υποδεικνύει ότι το image ή το μοντέλο deployment μεταφέρει περισσότερο υλικό εμπιστοσύνης από όσο είναι απαραίτητο.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker / BuildKit | Υποστηρίζει ασφαλή secret mounts κατά το build, αλλά όχι αυτόματα | Τα secrets μπορούν να προσαρτώνται εφήμερα κατά το `build`· το image signing και το scanning απαιτούν ρητές επιλογές στη ροή εργασίας | αντιγραφή secrets στο image, μεταβίβαση secrets μέσω `ARG` ή `ENV`, απενεργοποίηση ελέγχων provenance |
| Podman / Buildah | Υποστηρίζει OCI-native builds και workflows με επίγνωση των secrets | Διατίθενται ισχυρά workflows για build, αλλά οι operators πρέπει να τα επιλέξουν σκόπιμα | ενσωμάτωση secrets σε Containerfiles, ευρεία build contexts, permissive bind mounts κατά τα builds |
| Kubernetes | Native αντικείμενα Secret και projected volumes | Η παράδοση secrets κατά το runtime είναι first-class, αλλά η έκθεση εξαρτάται από το RBAC, τον σχεδιασμό των pods και τα host mounts | υπερβολικά ευρεία Secret mounts, κακή χρήση service-account tokens, πρόσβαση `hostPath` σε volumes που διαχειρίζεται το kubelet |
| Registries | Η ακεραιότητα είναι προαιρετική, εκτός αν επιβάλλεται | Τόσο τα public όσο και τα private registries εξαρτώνται από πολιτικές, signing και αποφάσεις admission | ελεύθερο pulling unsigned images, αδύναμος έλεγχος admission, κακή διαχείριση κλειδιών |

{{#include ../../../banners/hacktricks-training.md}}
