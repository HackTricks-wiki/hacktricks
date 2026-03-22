# Ασφάλεια εικόνων, υπογραφή και μυστικά

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Η ασφάλεια των Container ξεκινά πριν εκκινήσει το workload. Η εικόνα καθορίζει ποια binaries, interpreters, libraries, startup scripts και ενσωματωμένες ρυθμίσεις φτάνουν στην παραγωγή. Αν η εικόνα έχει backdoor, είναι stale ή κατασκευάστηκε με secrets ενσωματωμένα σε αυτήν, οι runtime hardening που ακολουθούν λειτουργούν ήδη πάνω σε ένα kompromised artifact.

Γι' αυτό η provenance της εικόνας, το vulnerability scanning, η signature verification και ο χειρισμός των secrets ανήκουν στην ίδια συζήτηση με τα namespaces και seccomp. Προστατεύουν διαφορετική φάση του lifecycle, αλλά αποτυχίες εδώ συχνά καθορίζουν την attack surface που το runtime αργότερα θα πρέπει να περιορίσει.

## Image Registries And Trust

Οι εικόνες μπορεί να προέρχονται από δημόσια registries όπως το Docker Hub ή από ιδιωτικά registries που λειτουργούν από έναν οργανισμό. Το ερώτημα ασφάλειας δεν είναι απλώς πού βρίσκεται η εικόνα, αλλά αν η ομάδα μπορεί να αποδείξει provenance και integrity. Το pulling unsigned ή κακώς ιχνηλατούμενων εικόνων από δημόσιες πηγές αυξάνει τον κίνδυνο κακόβουλου ή παραποιημένου περιεχομένου να φτάσει στην παραγωγή. Ακόμα και οι εσωτερικά φιλοξενούμενες registries χρειάζονται σαφή ιδιοκτησία, ανασκόπηση και πολιτική εμπιστοσύνης.

Το Docker Content Trust ιστορικά χρησιμοποίησε τις έννοιες Notary και TUF για να απαιτήσει υπογεγραμμένες εικόνες. Το ακριβές οικοσύστημα έχει εξελιχθεί, αλλά το διαχρονικό μάθημα παραμένει χρήσιμο: η ταυτότητα και η ακεραιότητα της εικόνας θα πρέπει να μπορούν να επαληθευτούν αντί να θεωρούνται δεδομένες.

Παράδειγμα ιστορικής Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Το σημείο του παραδείγματος δεν είναι ότι κάθε ομάδα πρέπει να χρησιμοποιεί τα ίδια tooling, αλλά ότι το signing και η διαχείριση κλειδιών είναι λειτουργικά καθήκοντα, όχι αφηρημένη θεωρία.

## Σάρωση Ευπαθειών

Η σάρωση image βοηθά να απαντηθούν δύο διαφορετικές ερωτήσεις. Πρώτον, περιέχει το image γνωστά ευπαθή πακέτα ή βιβλιοθήκες; Δεύτερον, μεταφέρει το image περιττό λογισμικό που αυξάνει την επιφάνεια επίθεσης; Ένα image γεμάτο debugging tools, shells, interpreters και ξεπερασμένα πακέτα είναι ευκολότερο να εκμεταλλευτεί και πιο δύσκολο να αναλυθεί.

Παραδείγματα συνήθως χρησιμοποιούμενων scanners περιλαμβάνουν:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Τα αποτελέσματα από αυτά τα εργαλεία πρέπει να ερμηνεύονται προσεκτικά. Μια ευπάθεια σε ένα μη χρησιμοποιούμενο πακέτο δεν έχει το ίδιο επίπεδο κινδύνου με ένα εκτεθειμένο RCE path, αλλά και τα δύο εξακολουθούν να είναι σχετικά για τις αποφάσεις ενίσχυσης της ασφάλειας.

## Μυστικά κατά το χρόνο build

Ένα από τα παλαιότερα λάθη στις pipeline κατασκευής container είναι η ενσωμάτωση μυστικών απευθείας στην εικόνα ή η μεταβίβασή τους μέσω μεταβλητών περιβάλλοντος που αργότερα γίνονται ορατές μέσω του `docker inspect`, των build logs ή των ανακτημένων layers. Τα μυστικά κατά το build πρέπει να προσαρτώνται προσωρινά κατά τη διάρκεια της κατασκευής αντί να αντιγράφονται στο filesystem της εικόνας.

Το BuildKit βελτίωσε αυτό το μοντέλο επιτρέποντας ειδική διαχείριση μυστικών κατά το build. Αντί να γράφεται ένα μυστικό σε ένα layer, το βήμα build μπορεί να το καταναλώσει παροδικά:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Αυτό έχει σημασία επειδή τα image layers είναι ανθεκτικά artifacts. Μόλις ένα secret εισέλθει σε ένα committed layer, το να διαγράψεις αργότερα το αρχείο σε άλλο layer δεν αφαιρεί πραγματικά την αρχική αποκάλυψη από το image history.

## Runtime Secrets

Τα secrets που χρειάζεται ένα running workload θα πρέπει επίσης να αποφεύγουν ad hoc πρότυπα όπως απλά environment variables όποτε είναι δυνατόν. Volumes, dedicated secret-management integrations, Docker secrets, και Kubernetes Secrets είναι συνηθισμένοι μηχανισμοί. Κανένας από αυτούς δεν αφαιρεί όλους τους κινδύνους, ειδικά αν ο attacker έχει ήδη code execution στο workload, αλλά παρ' όλα αυτά είναι προτιμότεροι από το να αποθηκεύονται credentials μόνιμα στην image ή να εκτίθενται ανεπίσημα μέσω inspection tooling.

Μια απλή Docker Compose style secret declaration looks like:
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
Στο Kubernetes, τα Secret objects, τα projected volumes, τα service-account tokens και οι cloud workload identities δημιουργούν ένα ευρύτερο και πιο ισχυρό μοντέλο, αλλά επίσης δημιουργούν περισσότερες ευκαιρίες για τυχαία έκθεση μέσω host mounts, ευρείας RBAC ή αδύναμου σχεδιασμού Pod.

## Κατάχρηση

Κατά την αξιολόγηση ενός στόχου, ο σκοπός είναι να εντοπιστεί εάν τα secrets είχαν ενσωματωθεί στο image, leaked στα layers, ή είχαν mounted σε προβλέψιμες runtime locations:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Αυτές οι εντολές βοηθούν να διακριθούν τρία διαφορετικά προβλήματα: application configuration leaks, image-layer leaks, και runtime-injected secret files. Εάν ένα μυστικό εμφανίζεται κάτω από το `/run/secrets`, σε ένα projected volume, ή σε ένα cloud identity token path, το επόμενο βήμα είναι να κατανοήσετε αν παρέχει πρόσβαση μόνο στο τρέχον workload ή σε ένα πολύ μεγαλύτερο control plane.

### Πλήρες Παράδειγμα: Ενσωματωμένο Μυστικό στο Σύστημα Αρχείων της Εικόνας

Εάν ένα build pipeline αντέγραψε τα αρχεία `.env` ή διαπιστευτήρια στην τελική εικόνα, το post-exploitation γίνεται απλό:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Ο αντίκτυπος εξαρτάται από την εφαρμογή, αλλά ενσωματωμένα signing keys, JWT secrets ή cloud credentials μπορούν εύκολα να μετατρέψουν τον συμβιβασμό ενός container σε API compromise, lateral movement ή πλαστογράφηση trusted application tokens.

### Πλήρες Παράδειγμα: Build-Time Secret Leakage Check

Εάν η ανησυχία είναι ότι το image history κατέγραψε ένα layer που περιέχει μυστικό:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Αυτός ο τύπος ανασκόπησης είναι χρήσιμος επειδή ένα secret μπορεί να έχει διαγραφεί από την τελική προβολή του filesystem ενώ εξακολουθεί να παραμένει σε προγενέστερο layer ή στα build metadata.

## Checks

Οι έλεγχοι αυτοί έχουν ως στόχο να διαπιστώσουν εάν το image και η secret-handling pipeline είναι πιθανόν να έχουν αυξήσει την attack surface πριν από το runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Τι είναι ενδιαφέρον εδώ:

- Ένα ύποπτο ιστορικό build μπορεί να αποκαλύψει αντιγραμμένα διαπιστευτήρια, υλικό SSH ή μη ασφαλή βήματα build.
- Secrets κάτω από projected volume paths μπορεί να οδηγήσουν σε πρόσβαση στο cluster ή στο cloud, και όχι μόνο σε τοπική πρόσβαση εφαρμογής.
- Μεγάλος αριθμός αρχείων ρυθμίσεων με διαπιστευτήρια σε απλό κείμενο συνήθως υποδηλώνει ότι το image ή το μοντέλο deployment φέρει περισσότερο υλικό εμπιστοσύνης από το απαραίτητο.

## Προεπιλογές χρόνου εκτέλεσης

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Υποστηρίζει secure build-time secret mounts, αλλά όχι αυτόματα | Secrets μπορούν να γίνουν mounted ephemerally κατά τη διάρκεια του `build`; image signing και scanning απαιτούν ρητές επιλογές workflow | αντιγραφή secrets μέσα στο image, πέρασμα secrets μέσω `ARG` ή `ENV`, απενεργοποίηση των provenance checks |
| Podman / Buildah | Υποστηρίζει OCI-native builds και secret-aware workflows | Διαθέσιμα ισχυρά build workflows, αλλά οι operators πρέπει να τα επιλέξουν σκόπιμα | ενσωμάτωση secrets σε Containerfiles, ευρείες build contexts, επιτρεπτικοί bind mounts κατά τα builds |
| Kubernetes | Native Secret objects και projected volumes | Η παράδοση Secrets σε runtime είναι first-class, αλλά η έκθεση εξαρτάται από RBAC, σχεδιασμό pod και host mounts | overbroad Secret mounts, κακή χρήση service-account token, `hostPath` πρόσβαση σε kubelet-managed volumes |
| Registries | Η ακεραιότητα είναι προαιρετική εκτός αν επιβληθεί | Public και private registries εξαρτώνται από policy, signing και admission αποφάσεις | pulling unsigned images ελεύθερα, αδύναμος admission control, κακή διαχείριση κλειδιών |
{{#include ../../../banners/hacktricks-training.md}}
