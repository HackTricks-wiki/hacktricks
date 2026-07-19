# Ασφάλεια Image, Υπογραφή και Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Η ασφάλεια των containers ξεκινά πριν από την εκκίνηση του workload. Το image καθορίζει ποια binaries, interpreters, libraries, startup scripts και embedded configuration φτάνουν στο production. Αν το image περιέχει backdoor, είναι παρωχημένο ή έχει δημιουργηθεί με secrets ενσωματωμένα σε αυτό, το runtime hardening που ακολουθεί λειτουργεί ήδη πάνω σε ένα compromised artifact.

Γι' αυτό το image provenance, το vulnerability scanning, η signature verification και ο χειρισμός των secrets ανήκουν στην ίδια συζήτηση με τα namespaces και το seccomp. Προστατεύουν διαφορετική φάση του lifecycle, όμως οι αστοχίες σε αυτό το σημείο συχνά καθορίζουν το attack surface που το runtime πρέπει αργότερα να περιορίσει.

## Image Registries και Trust

Τα images μπορεί να προέρχονται από public registries, όπως το Docker Hub, ή από private registries που λειτουργούν από έναν οργανισμό. Το ζήτημα ασφάλειας δεν είναι απλώς πού βρίσκεται το image, αλλά αν η ομάδα μπορεί να επιβεβαιώσει το provenance και την integrity του. Η λήψη unsigned ή ανεπαρκώς καταγεγραμμένων images από public sources αυξάνει τον κίνδυνο εισαγωγής malicious ή tampered content στο production. Ακόμη και τα internally hosted registries χρειάζονται σαφή ownership, review και trust policy.

Το Docker Content Trust χρησιμοποιούσε ιστορικά τις έννοιες του Notary και του TUF για να απαιτεί signed images. Το ακριβές ecosystem έχει εξελιχθεί, όμως το διαχρονικό δίδαγμα παραμένει χρήσιμο: η ταυτότητα και η integrity του image θα πρέπει να είναι επαληθεύσιμες και όχι να θεωρούνται δεδομένες.

Παράδειγμα ιστορικού Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Το νόημα του παραδείγματος δεν είναι ότι κάθε ομάδα πρέπει να συνεχίσει να χρησιμοποιεί τα ίδια εργαλεία, αλλά ότι το signing και η διαχείριση κλειδιών είναι λειτουργικές εργασίες και όχι αφηρημένη θεωρία.

## Vulnerability Scanning

Το image scanning βοηθά να απαντηθούν δύο διαφορετικά ερωτήματα. Πρώτον, περιέχει το image γνωστά ευάλωτα packages ή libraries; Δεύτερον, περιλαμβάνει το image περιττό software που διευρύνει το attack surface; Ένα image γεμάτο με debugging tools, shells, interpreters και παρωχημένα packages είναι τόσο ευκολότερο να γίνει exploit όσο και δυσκολότερο να αξιολογηθεί.

Παραδείγματα commonly used scanners περιλαμβάνουν:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Τα αποτελέσματα από αυτά τα tools πρέπει να ερμηνεύονται προσεκτικά. Ένα vulnerability σε ένα unused package δεν έχει τον ίδιο κίνδυνο με ένα exposed RCE path, αλλά και τα δύο παραμένουν σχετικά με τις αποφάσεις hardening.

## Build-Time Secrets

Ένα από τα παλαιότερα λάθη στα container build pipelines είναι η ενσωμάτωση secrets απευθείας στο image ή η μεταβίβασή τους μέσω environment variables, τα οποία αργότερα γίνονται ορατά μέσω των `docker inspect`, build logs ή layers που έχουν ανακτηθεί. Τα build-time secrets πρέπει να γίνονται mount ephemeral κατά τη διάρκεια του build, αντί να αντιγράφονται στο filesystem του image.

Το BuildKit βελτίωσε αυτό το μοντέλο, επιτρέποντας dedicated build-time secret handling. Αντί να γράφεται ένα secret σε layer, το build step μπορεί να το καταναλώνει transiently:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Αυτό έχει σημασία επειδή τα image layers είναι durable artifacts. Μόλις ένα secret εισαχθεί σε ένα committed layer, η μεταγενέστερη διαγραφή του αρχείου σε άλλο layer δεν αφαιρεί πραγματικά την αρχική disclosure από το image history.

## Runtime Secrets

Τα secrets που χρειάζεται ένα workload κατά την εκτέλεσή του θα πρέπει επίσης να αποφεύγουν ad hoc patterns, όπως τα plain environment variables, όποτε αυτό είναι δυνατό. Τα volumes, οι dedicated secret-management integrations, τα Docker secrets και τα Kubernetes Secrets είναι συνήθεις μηχανισμοί. Κανένας από αυτούς δεν εξαλείφει όλους τους κινδύνους, ειδικά αν ο attacker έχει ήδη code execution στο workload, αλλά εξακολουθούν να προτιμώνται έναντι της μόνιμης αποθήκευσης credentials στο image ή της απρόσεκτης έκθεσής τους μέσω inspection tooling.

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
Στο Kubernetes, τα Secret objects, τα projected volumes, τα service-account tokens και τα cloud workload identities δημιουργούν ένα ευρύτερο και ισχυρότερο μοντέλο, αλλά δημιουργούν επίσης περισσότερες ευκαιρίες για accidental exposure μέσω host mounts, ευρέος RBAC ή αδύναμου σχεδιασμού Pod.

## Κατάχρηση

Κατά την αξιολόγηση ενός target, ο στόχος είναι να διαπιστωθεί αν τα secrets είχαν ενσωματωθεί στο image, διέρρευσαν σε layers ή προσαρτήθηκαν σε προβλέψιμες runtime locations:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Αυτές οι εντολές βοηθούν στη διάκριση μεταξύ τριών διαφορετικών προβλημάτων: configuration leaks της εφαρμογής, image-layer leaks και αρχεία μυστικών που εισάγονται κατά το runtime. Αν ένα secret εμφανίζεται κάτω από το `/run/secrets`, σε ένα projected volume ή σε ένα cloud identity token path, το επόμενο βήμα είναι να κατανοήσετε αν παρέχει πρόσβαση μόνο στο τρέχον workload ή σε ένα πολύ ευρύτερο control plane.

### Πλήρες Παράδειγμα: Embedded Secret In Image Filesystem

Αν ένα build pipeline αντέγραψε αρχεία `.env` ή credentials στο final image, το post-exploitation γίνεται απλό:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Ο αντίκτυπος εξαρτάται από την εφαρμογή, αλλά ενσωματωμένα signing keys, JWT secrets ή cloud credentials μπορούν εύκολα να μετατρέψουν το container compromise σε API compromise, lateral movement ή πλαστογράφηση trusted application tokens.

### Full Example: Έλεγχος Secret Leak κατά το Build

Αν το ζήτημα είναι ότι το image history κατέγραψε ένα layer που περιείχε secret:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Αυτό το είδος ανασκόπησης είναι χρήσιμο, επειδή ένα secret μπορεί να έχει διαγραφεί από την τελική προβολή του filesystem, ενώ εξακολουθεί να παραμένει σε παλαιότερο layer ή στα build metadata.

## Έλεγχοι

Αυτοί οι έλεγχοι αποσκοπούν στο να διαπιστωθεί αν το pipeline διαχείρισης του image και των secret είναι πιθανό να έχει αυξήσει το attack surface πριν από το runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Τι είναι ενδιαφέρον εδώ:

- Ένα ύποπτο ιστορικό build μπορεί να αποκαλύψει αντιγραμμένα credentials, υλικό SSH ή μη ασφαλή build steps.
- Τα Secrets κάτω από projected volume paths μπορεί να οδηγήσουν σε πρόσβαση στο cluster ή στο cloud, όχι μόνο σε τοπική πρόσβαση στην εφαρμογή.
- Μεγάλος αριθμός configuration files με plaintext credentials συνήθως υποδεικνύει ότι το image ή το μοντέλο deployment μεταφέρει περισσότερο trust material από όσο είναι απαραίτητο.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνηθισμένη χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker / BuildKit | Υποστηρίζει ασφαλή build-time secret mounts, αλλά όχι αυτόματα | Τα Secrets μπορούν να γίνουν mount εφήμερα κατά το `build`· το image signing και το scanning απαιτούν ρητές επιλογές workflow | αντιγραφή Secrets στο image, μεταβίβαση Secrets μέσω `ARG` ή `ENV`, απενεργοποίηση provenance checks |
| Podman / Buildah | Υποστηρίζει OCI-native builds και secret-aware workflows | Διατίθενται ισχυρά build workflows, αλλά οι operators πρέπει και πάλι να τα επιλέξουν σκόπιμα | ενσωμάτωση Secrets σε Containerfiles, ευρεία build contexts, permissive bind mounts κατά τη διάρκεια των builds |
| Kubernetes | Native Secret objects και projected volumes | Η παράδοση Secrets κατά το runtime είναι first-class, αλλά η έκθεση εξαρτάται από τα RBAC, τον σχεδιασμό των pods και τα host mounts | υπερβολικά ευρεία Secret mounts, κακή χρήση service-account tokens, πρόσβαση `hostPath` σε volumes που διαχειρίζεται το kubelet |
| Registries | Η ακεραιότητα είναι προαιρετική, εκτός αν επιβάλλεται | Τόσο τα public όσο και τα private registries εξαρτώνται από policy, signing και admission decisions | ελεύθερο pulling unsigned images, αδύναμος admission control, κακή διαχείριση κλειδιών |
{{#include ../../../banners/hacktricks-training.md}}
