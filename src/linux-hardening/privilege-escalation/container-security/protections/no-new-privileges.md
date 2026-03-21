# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` είναι ένα χαρακτηριστικό ενίσχυσης του kernel που εμποδίζει μια διεργασία να αποκτήσει επιπλέον προνόμια μέσω του `execve()`. Σε πρακτικό επίπεδο, μόλις τεθεί η σημαία, η εκτέλεση ενός setuid binary, ενός setgid binary ή ενός αρχείου με Linux file capabilities δεν παρέχει επιπλέον προνόμια πέραν αυτών που ήδη είχε η διεργασία. Σε containerized περιβάλλοντα, αυτό είναι σημαντικό επειδή πολλές privilege-escalation chains βασίζονται στην εύρεση ενός εκτελέσιμου μέσα στην image που αλλάζει τα προνόμια όταν εκτελείται.

Από αμυντική σκοπιά, το `no_new_privs` δεν αποτελεί υποκατάστατο για namespaces, seccomp ή capability dropping. Είναι ένα επίπεδο ενίσχυσης. Εμποδίζει μια συγκεκριμένη κατηγορία επακόλουθης privilege-escalation μετά την επίτευξη εκτέλεσης κώδικα. Αυτό το καθιστά ιδιαίτερα πολύτιμο σε περιβάλλοντα όπου οι images περιέχουν helper binaries, package-manager artifacts ή legacy tools που διαφορετικά θα ήταν επικίνδυνα όταν συνδυαστούν με μερική παραβίαση.

## Operation

Η σημαία του kernel πίσω από αυτή τη συμπεριφορά είναι η `PR_SET_NO_NEW_PRIVS`. Μόλις τεθεί για μια διεργασία, μετέπειτα κλήσεις `execve()` δεν μπορούν να αυξήσουν τα προνόμια. Η σημαντική λεπτομέρεια είναι ότι η διεργασία μπορεί ακόμα να τρέξει binaries· απλώς δεν μπορεί να χρησιμοποιήσει αυτά τα binaries για να διασχίσει ένα όριο προνομίων το οποίο ο kernel θα αναγνώριζε.

Σε Kubernetes-oriented περιβάλλοντα, το `allowPrivilegeEscalation: false` αντιστοιχεί σε αυτή τη συμπεριφορά για τη διεργασία του container. Σε Docker και Podman style runtimes, το αντίστοιχο συνήθως ενεργοποιείται ρητά μέσω μιας security option.

## Lab

Επιθεωρήστε την τρέχουσα κατάσταση της διεργασίας:
```bash
grep NoNewPrivs /proc/self/status
```
Σύγκρινε αυτό με ένα container όπου το runtime ενεργοποιεί το flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Σε ένα σκληρυμένο workload, το αποτέλεσμα θα πρέπει να δείχνει `NoNewPrivs: 1`.

## Επιπτώσεις Ασφάλειας

Εάν το `no_new_privs` απουσιάζει, ένα foothold μέσα στο container μπορεί ακόμα να αναβαθμιστεί μέσω setuid helpers ή binaries με file capabilities. Εάν είναι παρόν, αυτές οι αλλαγές προνομίων μετά το exec αποκόπτονται. Η επίδραση είναι ιδιαίτερα σημαντική σε ευρείες base images που περιέχουν πολλές utilities που η εφαρμογή δεν χρειαζόταν εξαρχής.

## Λανθασμένη διαμόρφωση

Το πιο συνηθισμένο πρόβλημα είναι απλώς να μην ενεργοποιείται ο έλεγχος σε περιβάλλοντα όπου θα ήταν συμβατός. Στο Kubernetes, το να αφήνετε το `allowPrivilegeEscalation` ενεργοποιημένο είναι συχνά το προεπιλεγμένο λειτουργικό λάθος. Στο Docker και στο Podman, η παράλειψη της σχετικής επιλογής ασφαλείας έχει το ίδιο αποτέλεσμα. Ένας άλλος επαναλαμβανόμενος τρόπος αποτυχίας είναι η υπόθεση ότι επειδή ένα container είναι "not privileged", οι exec-time privilege transitions είναι αυτόματα ασήμαντες.

## Κατάχρηση

Αν το `no_new_privs` δεν είναι ρυθμισμένο, το πρώτο ερώτημα είναι αν το image περιέχει binaries που μπορούν ακόμα να αυξήσουν τα privilege:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interesting results include:

- `NoNewPrivs: 0`
- setuid helpers όπως `su`, `mount`, `passwd` ή εργαλεία διαχείρισης ειδικά για τη διανομή
- binaries με file capabilities που παρέχουν δικαιώματα δικτύου ή στο σύστημα αρχείων

Σε μια πραγματική αξιολόγηση, αυτά τα ευρήματα δεν αποδεικνύουν από μόνα τους μια λειτουργική escalation, αλλά προσδιορίζουν ακριβώς τα binaries που αξίζει να δοκιμαστούν στη συνέχεια.

### Πλήρες Παράδειγμα: In-Container Privilege Escalation Through setuid

Αυτός ο έλεγχος συνήθως αποτρέπει **in-container privilege escalation** αντί να αποτρέπει απευθείας host escape. Αν το `NoNewPrivs` είναι `0` και υπάρχει setuid helper, δοκιμάστε τον ρητά:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Αν υπάρχει και λειτουργεί ένα γνωστό setuid binary, δοκιμάστε να το εκκινήσετε με τρόπο που διατηρεί τη μετάβαση προνομίων:
```bash
/bin/su -c id 2>/dev/null
```
Αυτό από μόνο του δεν προκαλεί escape του container, αλλά μπορεί να μετατρέψει ένα low-privilege foothold μέσα στο container σε container-root, το οποίο συχνά γίνεται το προαπαιτούμενο για μετέπειτα host escape μέσω mounts, runtime sockets ή kernel-facing interfaces.

## Έλεγχοι

Ο στόχος αυτών των ελέγχων είναι να καθοριστεί εάν το exec-time privilege gain έχει μπλοκαριστεί και εάν το image εξακολουθεί να περιέχει helpers που θα είχαν σημασία σε περίπτωση που δεν έχει μπλοκαριστεί.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Τι είναι ενδιαφέρον εδώ:

- `NoNewPrivs: 1` είναι συνήθως το ασφαλέστερο αποτέλεσμα.
- `NoNewPrivs: 0` σημαίνει ότι μονοπάτια κλιμάκωσης βασισμένα σε setuid και file-cap παραμένουν εφαρμόσιμα.
- Μια minimal image με λίγα ή καθόλου setuid/file-cap binaries δίνει σε έναν attacker λιγότερες επιλογές post-exploitation, ακόμα και όταν το `no_new_privs` λείπει.

## Προεπιλογές χρόνου εκτέλεσης

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges=true` | παραλείποντας το flag, `--privileged` |
| Podman | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges` or equivalent security configuration | παραλείποντας την επιλογή, `--privileged` |
| Kubernetes | Controlled by workload policy | `allowPrivilegeEscalation: false` enables the effect; many workloads still leave it enabled | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes workload settings | Usually inherited from the Pod security context | same as Kubernetes row |

Αυτή η προστασία συχνά απουσιάζει απλώς επειδή κανείς δεν την ενεργοποίησε, όχι επειδή το runtime δεν υποστηρίζει αυτή τη λειτουργία.
