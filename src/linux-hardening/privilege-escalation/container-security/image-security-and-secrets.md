# Ασφάλεια Εικόνων, Υπογραφή και Μυστικά

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Η ασφάλεια των containers ξεκινά πριν το workload ξεκινήσει. Η εικόνα καθορίζει ποια binaries, interpreters, βιβλιοθήκες, startup scripts και ενσωματωμένες ρυθμίσεις φτάνουν στην παραγωγή. Αν η εικόνα είναι backdoored, παρωχημένη ή κατασκευασμένη με μυστικά ενσωματωμένα σε αυτή, η σκληροποίηση του runtime που ακολουθεί λειτουργεί ήδη πάνω σε ένα συμβιβασμένο artifact.

Γι' αυτό η προέλευση εικόνας (image provenance), το vulnerability scanning, η επαλήθευση υπογραφής και ο χειρισμός μυστικών ανήκουν στην ίδια συζήτηση με namespaces και seccomp. Προστατεύουν μια διαφορετική φάση του lifecycle, αλλά οι αποτυχίες εδώ συχνά ορίζουν την attack surface που το runtime μετά πρέπει να περιέχει.

## Μητρώα Εικόνων και Εμπιστοσύνη

Οι εικόνες μπορεί να προέρχονται από δημόσια registries όπως το Docker Hub ή από ιδιωτικά registries που διαχειρίζεται ένας οργανισμός. Το ζήτημα ασφάλειας δεν είναι απλώς πού φιλοξενείται η εικόνα, αλλά κατά πόσον η ομάδα μπορεί να αποδείξει provenance και integrity. Το pulling unsigned ή ανεπαρκώς παρακολουθούμενων εικόνων από δημόσιες πηγές αυξάνει τον κίνδυνο κακόβουλου ή παραποιημένου περιεχομένου να φτάσει στην παραγωγή. Ακόμα και τα εσωτερικά hosted registries χρειάζονται σαφή ιδιοκτησία, review και πολιτική εμπιστοσύνης.

Docker Content Trust ιστορικά χρησιμοποιούσε τις έννοιες του Notary και του TUF για να απαιτεί υπογεγραμμένες εικόνες. Το ακριβές οικοσύστημα έχει εξελιχθεί, αλλά το διαχρονικό μάθημα παραμένει χρήσιμο: η ταυτότητα και η ακεραιότητα της εικόνας πρέπει να είναι επαληθεύσιμες και όχι να θεωρούνται δεδομένες.

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Το νόημα του παραδείγματος δεν είναι ότι κάθε ομάδα πρέπει αναγκαστικά να χρησιμοποιεί τα ίδια εργαλεία, αλλά ότι το signing και το key management είναι επιχειρησιακές εργασίες, όχι αφηρημένη θεωρία.

## Σάρωση Ευπαθειών

Η σάρωση image βοηθά να απαντηθούν δύο διαφορετικά ερωτήματα. Πρώτον, περιέχει το image γνωστά ευάλωτα packages ή libraries; Δεύτερον, περιλαμβάνει το image περιττό software που διευρύνει την attack surface; Ένα image γεμάτο debugging tools, shells, interpreters και stale packages είναι τόσο πιο εύκολο στην εκμετάλλευση όσο και πιο δύσκολο στην αξιολόγηση.

Παραδείγματα συνήθως χρησιμοποιούμενων scanners περιλαμβάνουν:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Τα αποτελέσματα από αυτά τα εργαλεία πρέπει να ερμηνεύονται προσεκτικά. Μια ευπάθεια σε ένα αχρησιμοποίητο πακέτο δεν ισοδυναμεί με τον ίδιο κίνδυνο όπως μια εκτεθειμένη RCE διαδρομή, αλλά και τα δύο παραμένουν σχετικά για τις αποφάσεις ενίσχυσης της ασφάλειας.

## Μυστικά κατά το χρόνο build

Ένα από τα παλαιότερα λάθη στις pipelines κατασκευής container είναι η ενσωμάτωση μυστικών απευθείας στην image ή η μεταβίβασή τους μέσω μεταβλητών περιβάλλοντος που αργότερα γίνονται ορατές μέσω του `docker inspect`, των build logs ή των ανακτημένων layers. Τα μυστικά κατά το build πρέπει να προσαρτώνται προσωρινά κατά τη διάρκεια του build παρά να αντιγράφονται στο filesystem της image.

Το BuildKit βελτίωσε αυτό το μοντέλο επιτρέποντας αποκλειστική διαχείριση μυστικών κατά το build. Αντί να γράφεται ένα μυστικό σε ένα layer, το βήμα build μπορεί να το καταναλώσει παροδικά:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Αυτό έχει σημασία επειδή τα image layers είναι ανθεκτικά artifacts. Μόλις ένα secret εισέλθει σε ένα committed layer, η μετέπειτα διαγραφή του αρχείου σε άλλο layer δεν αφαιρεί πραγματικά την αρχική αποκάλυψη από το ιστορικό του image.

## Runtime Secrets

Τα Secrets που χρειάζεται ένα τρέχον workload πρέπει επίσης να αποφεύγουν ad hoc μοτίβα όπως οι απλές environment variables όποτε είναι δυνατόν. Volumes, εξειδικευμένες ενσωματώσεις διαχείρισης μυστικών, Docker secrets, και Kubernetes Secrets είναι κοινά μηχανισμοί. Κανένα από αυτά δεν αφαιρεί όλους τους κινδύνους, ειδικά αν ο attacker έχει ήδη code execution στο workload, αλλά παραμένουν προτιμητέες επιλογές σε σχέση με την μόνιμη αποθήκευση credentials στο image ή την πρόχειρη έκθεσή τους μέσω εργαλείων επιθεώρησης.

Μια απλή δήλωση secret σε στυλ Docker Compose μοιάζει με:
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
Στο Kubernetes, τα Secret objects, τα projected volumes, τα service-account tokens και οι cloud workload identities δημιουργούν ένα ευρύτερο και πιο ισχυρό μοντέλο, αλλά δημιουργούν επίσης περισσότερες ευκαιρίες για ακούσια έκθεση μέσω host mounts, ευρείας RBAC ή αδύναμου σχεδιασμού Pod.

## Κατάχρηση

Κατά την ανασκόπηση ενός στόχου, σκοπός είναι να διαπιστωθεί εάν τα secrets είχαν baked into the image, leaked into layers, ή mounted into predictable runtime locations:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Αυτές οι εντολές βοηθούν να διακριθούν τρία διαφορετικά προβλήματα: application configuration leaks, image-layer leaks και runtime-injected secret files. Εάν ένα secret εμφανιστεί κάτω από το `/run/secrets`, σε ένα projected volume, ή σε ένα cloud identity token path, το επόμενο βήμα είναι να κατανοήσετε αν παρέχει πρόσβαση μόνο στο τρέχον workload ή σε ένα πολύ μεγαλύτερο control plane.

### Πλήρες Παράδειγμα: Embedded Secret In Image Filesystem

Εάν ένα build pipeline αντιγράψει αρχεία `.env` ή credentials στο final image, post-exploitation γίνεται απλό:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Ο αντίκτυπος εξαρτάται από την εφαρμογή, αλλά ενσωματωμένα κλειδιά υπογραφής, JWT secrets ή cloud credentials μπορούν εύκολα να μετατρέψουν τον συμβιβασμό ενός container σε API compromise, lateral movement, ή forgery των trusted application tokens.

### Πλήρες Παράδειγμα: Build-Time Secret Leakage Check

Εάν η ανησυχία είναι ότι το image history κατέγραψε ένα layer που περιέχει μυστικό:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Αυτός ο τύπος ανασκόπησης είναι χρήσιμος επειδή ένα secret μπορεί να έχει διαγραφεί από την τελική προβολή του filesystem ενώ εξακολουθεί να παραμένει σε ένα προηγούμενο layer ή στα build metadata.

## Checks

Οι έλεγχοι αυτοί αποσκοπούν στο να καθορίσουν εάν το image και η secret-handling pipeline ενδέχεται να έχουν αυξήσει την attack surface πριν από το runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Τι είναι ενδιαφέρον εδώ:

- Ένα ύποπτο ιστορικό build μπορεί να αποκαλύψει αντιγραμμένα credentials, SSH υλικό ή μη ασφαλή βήματα build.
- Τα Secrets υπό projected volume paths μπορεί να οδηγήσουν σε πρόσβαση σε cluster ή cloud, όχι μόνο σε τοπική πρόσβαση εφαρμογής.
- Μεγάλος αριθμός αρχείων ρυθμίσεων με plaintext credentials συνήθως υποδεικνύει ότι το image ή το deployment model φέρει περισσότερο trust material από όσο απαιτείται.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Υποστηρίζει secure build-time secret mounts, αλλά όχι αυτόματα | Τα Secrets μπορούν να προσαρτηθούν προσωρινά κατά τη διάρκεια του `build`; το image signing και το scanning απαιτούν ρητές επιλογές workflow | αντιγραφή secrets μέσα στο image, passing secrets by `ARG` or `ENV`, απενεργοποίηση provenance checks |
| Podman / Buildah | Υποστηρίζει OCI-native builds και secret-aware workflows | Διαθέσιμα ισχυρά build workflows, αλλά οι operators πρέπει να τα επιλέξουν σκόπιμα | ενσωμάτωση secrets σε Containerfiles, broad build contexts, permissive bind mounts κατά τα builds |
| Kubernetes | Native Secret objects και projected volumes | Η runtime παράδοση secrets είναι first-class, αλλά η έκθεση εξαρτάται από RBAC, το σχεδιασμό pod και τα host mounts | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Η ακεραιότητα είναι προαιρετική εκτός αν επιβληθεί | Public και private registries εξαρτώνται από policy, signing και admission αποφάσεις | pulling unsigned images freely, weak admission control, poor key management |
