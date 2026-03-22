# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` είναι μια λειτουργία σκληροποίησης του πυρήνα που αποτρέπει μια διεργασία από το να αποκτήσει περισσότερα προνόμια μέσω του `execve()`. Στην πράξη, μόλις η σημαία οριστεί, η εκτέλεση ενός setuid binary, ενός setgid binary, ή ενός αρχείου με Linux file capabilities δεν παρέχει επιπλέον προνόμια πέρα από αυτά που ήδη είχε η διεργασία. Σε containerized περιβάλλοντα, αυτό είναι σημαντικό επειδή πολλές privilege-escalation αλυσίδες στηρίζονται στην εύρεση ενός εκτελέσιμου μέσα στην image που αλλάζει προνόμια όταν εκτελείται.

Από αμυντική σκοπιά, το `no_new_privs` δεν αντικαθιστά τα namespaces, seccomp ή capability dropping. Είναι ένα επίπεδο ενίσχυσης. Μπλοκάρει μια συγκεκριμένη κλάση επακόλουθης escalation μετά από code execution που έχει ήδη επιτευχθεί. Αυτό το καθιστά ιδιαίτερα πολύτιμο σε περιβάλλοντα όπου οι images περιέχουν helper binaries, package-manager artifacts, ή legacy tools που διαφορετικά θα ήταν επικίνδυνα σε συνδυασμό με μερική compromise.

## Λειτουργία

Η σημαία του πυρήνα πίσω από αυτή τη συμπεριφορά είναι `PR_SET_NO_NEW_PRIVS`. Μόλις οριστεί για μια διεργασία, μετέπειτα κλήσεις `execve()` δεν μπορούν να αυξήσουν προνόμια. Η σημαντική λεπτομέρεια είναι ότι η διεργασία μπορεί ακόμα να τρέξει binaries· απλώς δεν μπορεί να χρησιμοποιήσει αυτά τα binaries για να περάσει ένα όριο προνομίων που ο πυρήνας θα σεβόταν διαφορετικά.

Σε Kubernetes-oriented περιβάλλοντα, `allowPrivilegeEscalation: false` αντιστοιχεί σε αυτή τη συμπεριφορά για τη διεργασία του container. Σε Docker και Podman style runtimes, το αντίστοιχο συνήθως ενεργοποιείται ρητά μέσω μιας security option.

## Εργαστήριο

Επιθεωρήστε την τρέχουσα κατάσταση της διεργασίας:
```bash
grep NoNewPrivs /proc/self/status
```
Σύγκρινε αυτό με ένα container όπου το runtime ενεργοποιεί το flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Σε έναν σκληροποιημένο φόρτο εργασίας, το αποτέλεσμα πρέπει να εμφανίζει `NoNewPrivs: 1`.

## Επίπτωση στην ασφάλεια

Εάν το `no_new_privs` απουσιάζει, ένα foothold μέσα στο container μπορεί να αναβαθμιστεί μέσω setuid helpers ή binaries με file capabilities. Εάν είναι παρόν, αυτές οι post-exec αλλαγές προνομίων αποκόπτονται. Η επίπτωση είναι ιδιαίτερα σημαντική σε broad base images που περιλαμβάνουν πολλές utilities που η εφαρμογή δεν χρειάστηκε ποτέ εξαρχής.

## Λανθασμένες ρυθμίσεις

Το πιο κοινό πρόβλημα είναι απλώς να μην ενεργοποιείται ο έλεγχος σε περιβάλλοντα όπου θα ήταν συμβατός. Σε Kubernetes, το να αφήνεται το `allowPrivilegeEscalation` ενεργοποιημένο είναι συχνά το προεπιλεγμένο λειτουργικό λάθος. Σε Docker και Podman, η παράλειψη της σχετικής επιλογής ασφάλειας έχει το ίδιο αποτέλεσμα. Ένας άλλος επαναλαμβανόμενος τρόπος αποτυχίας είναι η υπόθεση ότι επειδή ένα container είναι "not privileged", οι exec-time μεταβάσεις προνομίων είναι αυτόματα αδιάφορες.

## Κατάχρηση

Εάν το `no_new_privs` δεν έχει οριστεί, το πρώτο ερώτημα είναι αν η image περιέχει binaries που μπορούν ακόμα να αυξήσουν προνόμια:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Ενδιαφέροντα αποτελέσματα περιλαμβάνουν:

- `NoNewPrivs: 0`
- setuid βοηθητικά προγράμματα όπως `su`, `mount`, `passwd`, ή εργαλεία διαχείρισης ειδικά για τη διανομή
- εκτελέσιμα με file capabilities που παρέχουν δικαιώματα δικτύου ή στο σύστημα αρχείων

Σε μια πραγματική αξιολόγηση, αυτά τα ευρήματα από μόνα τους δεν αποδεικνύουν μια λειτουργική κλιμάκωση προνομίων, αλλά εντοπίζουν ακριβώς τα δυαδικά που αξίζει να δοκιμαστούν στη συνέχεια.

### Πλήρες παράδειγμα: In-Container Privilege Escalation Through setuid

Αυτός ο έλεγχος συνήθως αποτρέπει την **in-container privilege escalation** παρά το άμεσο host escape. Εάν το `NoNewPrivs` είναι `0` και υπάρχει setuid helper, δοκιμάστε το ρητά:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Εάν υπάρχει και λειτουργεί ένα γνωστό setuid binary, δοκιμάστε να το εκτελέσετε με τρόπο που διατηρεί τη μετάβαση προνομίων:
```bash
/bin/su -c id 2>/dev/null
```
Αυτό από μόνο του δεν διαφεύγει από το container, αλλά μπορεί να μετατρέψει ένα foothold με χαμηλά προνόμια μέσα στο container σε container-root, που συχνά γίνεται προαπαιτούμενο για μετέπειτα διαφυγή προς τον host μέσω mounts, runtime sockets ή διεπαφών που απευθύνονται στον kernel.

## Checks

Ο στόχος αυτών των ελέγχων είναι να διαπιστωθεί εάν η δυνατότητα απόκτησης προνομίων κατά την εκτέλεση (exec-time privilege gain) είναι μπλοκαρισμένη και εάν το image εξακολουθεί να περιέχει βοηθητικά εργαλεία που θα είχαν σημασία αν δεν ήταν.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Τι είναι ενδιαφέρον εδώ:

- `NoNewPrivs: 1` είναι συνήθως το ασφαλέστερο αποτέλεσμα.
- `NoNewPrivs: 0` σημαίνει ότι οι δρόμοι κλιμάκωσης βασισμένοι σε setuid και file-cap παραμένουν σχετικοί.
- Μια minimal image με λίγα ή καθόλου setuid/file-cap binaries δίνει σε έναν επιτιθέμενο λιγότερες επιλογές post-exploitation ακόμα και όταν `no_new_privs` λείπει.

## Προεπιλεγμένες ρυθμίσεις χρόνου εκτέλεσης

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Δεν ενεργοποιείται από προεπιλογή | Ενεργοποιείται ρητά με `--security-opt no-new-privileges=true` | παράλειψη της σημαίας, `--privileged` |
| Podman | Δεν ενεργοποιείται από προεπιλογή | Ενεργοποιείται ρητά με `--security-opt no-new-privileges` ή ισοδύναμη ρύθμιση ασφάλειας | παράλειψη της επιλογής, `--privileged` |
| Kubernetes | Ελεγχόμενο από την πολιτική του workload | `allowPrivilegeEscalation: false` ενεργοποιεί το αποτέλεσμα· πολλά workloads εξακολουθούν να το αφήνουν ενεργό | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Ακολουθεί τις ρυθμίσεις workload του Kubernetes | Συνήθως κληρονομείται από το Pod security context | ίδιο με τη σειρά Kubernetes |

Αυτή η προστασία συχνά απουσιάζει απλώς επειδή κανείς δεν την ενεργοποίησε, όχι επειδή το runtime δεν την υποστηρίζει.
{{#include ../../../../banners/hacktricks-training.md}}
