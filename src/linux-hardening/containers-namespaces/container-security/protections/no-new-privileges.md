# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

Το `no_new_privs` είναι μια λειτουργία kernel hardening που εμποδίζει ένα process να αποκτήσει περισσότερα privilege μέσω του `execve()`. Πρακτικά, αφού οριστεί το flag, η εκτέλεση ενός setuid binary, ενός setgid binary ή ενός αρχείου με Linux file capabilities δεν παρέχει επιπλέον privilege πέρα από αυτό που είχε ήδη το process. Σε containerized environments, αυτό είναι σημαντικό επειδή πολλά privilege-escalation chains βασίζονται στην εύρεση ενός executable μέσα στο image που αλλάζει privilege όταν εκτελείται.

Από defensive point of view, το `no_new_privs` δεν αποτελεί υποκατάστατο για namespaces, seccomp ή capability dropping. Είναι ένα reinforcement layer. Μπλοκάρει μια συγκεκριμένη κατηγορία follow-up escalation αφού έχει ήδη επιτευχθεί code execution. Αυτό το καθιστά ιδιαίτερα χρήσιμο σε environments όπου τα images περιέχουν helper binaries, package-manager artifacts ή legacy tools που διαφορετικά θα ήταν επικίνδυνα σε συνδυασμό με partial compromise.

## Λειτουργία

Το kernel flag πίσω από αυτή τη συμπεριφορά είναι το `PR_SET_NO_NEW_PRIVS`. Αφού οριστεί για ένα process, οι επόμενες κλήσεις `execve()` δεν μπορούν να αυξήσουν το privilege. Η σημαντική λεπτομέρεια είναι ότι το process μπορεί να συνεχίσει να εκτελεί binaries· απλώς δεν μπορεί να τα χρησιμοποιήσει για να διασχίσει ένα privilege boundary που διαφορετικά θα επέβαλλε ο kernel.<sup>[[1]](#references)</sup>

Η συμπεριφορά του kernel είναι επίσης **κληρονομούμενη και μη αναστρέψιμη**: αφού ένα task ορίσει το `no_new_privs`, το bit κληρονομείται μέσω των `fork()`, `clone()` και `execve()`, και δεν μπορεί να unset-αριστεί αργότερα.<sup>[[1]](#references)</sup> Αυτό είναι χρήσιμο σε assessments, επειδή ένα `NoNewPrivs: 1` στο container process συνήθως σημαίνει ότι και τα descendants θα πρέπει να παραμείνουν σε αυτό το mode, εκτός αν εξετάζετε ένα εντελώς διαφορετικό process tree.

Σε Kubernetes-oriented environments, το `allowPrivilegeEscalation: false` αντιστοιχεί σε αυτή τη συμπεριφορά για το container process.<sup>[[2]](#references)</sup> Σε runtimes τύπου Docker και Podman, το αντίστοιχο συνήθως ενεργοποιείται explicit μέσω ενός security option. Στο OCI layer, η ίδια έννοια εμφανίζεται ως `process.noNewPrivileges`.

## Σημαντικές λεπτομέρειες

Το `no_new_privs` μπλοκάρει την απόκτηση privilege κατά το **exec-time**, όχι κάθε αλλαγή privilege.<sup>[[1]](#references)</sup> Συγκεκριμένα:

- οι setuid και setgid transitions παύουν να λειτουργούν μέσω `execve()`
- τα file capabilities δεν προστίθενται στο permitted set μέσω `execve()`
- τα LSMs, όπως τα AppArmor ή SELinux, δεν χαλαρώνουν τους περιορισμούς μετά το `execve()`
- το privilege που έχει ήδη αποκτηθεί παραμένει ήδη αποκτημένο

Το τελευταίο σημείο είναι σημαντικό operationally. Αν το process εκτελείται ήδη ως root, διαθέτει ήδη ένα επικίνδυνο capability ή έχει ήδη πρόσβαση σε ένα powerful runtime API ή writable host mount, το `no_new_privs` δεν εξουδετερώνει αυτά τα exposures. Απλώς αφαιρεί ένα συνηθισμένο **next step** σε ένα privilege-escalation chain.

Σημειώστε επίσης ότι το flag δεν μπλοκάρει αλλαγές privilege που δεν εξαρτώνται από το `execve()`.<sup>[[1]](#references)</sup> Για παράδειγμα, ένα task που διαθέτει ήδη αρκετό privilege μπορεί να συνεχίσει να καλεί απευθείας το `setuid(2)` ή να λάβει ένα privileged file descriptor μέσω Unix socket. Γι’ αυτό το `no_new_privs` θα πρέπει να εξετάζεται μαζί με το [seccomp](seccomp.md), τα capability sets και το namespace exposure, αντί να αντιμετωπίζεται ως αυτόνομη λύση.

## Εργαστήριο

Επιθεωρήστε την κατάσταση του τρέχοντος process:
```bash
grep NoNewPrivs /proc/self/status
```
Συγκρίνετέ το με ένα container όπου το runtime ενεργοποιεί το flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Σε ένα hardened workload, το αποτέλεσμα θα πρέπει να εμφανίζει `NoNewPrivs: 1`.

Μπορείτε επίσης να επιδείξετε το πραγματικό αποτέλεσμα σε ένα setuid binary:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Το σημείο της σύγκρισης δεν είναι ότι το `su` είναι καθολικά exploitable. Είναι ότι το ίδιο image μπορεί να συμπεριφέρεται πολύ διαφορετικά, ανάλογα με το αν επιτρέπεται ακόμη στο `execve()` να διασχίσει ένα privilege boundary.

## Επιπτώσεις Ασφαλείας

Αν το `no_new_privs` απουσιάζει, ένα foothold μέσα στο container μπορεί ακόμη να αναβαθμιστεί μέσω setuid helpers ή binaries με file capabilities. Αν είναι ενεργοποιημένο, αυτές οι post-exec αλλαγές privilege αποτρέπονται. Η επίδραση είναι ιδιαίτερα σημαντική σε ευρέα base images που περιλαμβάνουν πολλά utilities τα οποία η εφαρμογή δεν χρειάστηκε ποτέ εξαρχής.

Υπάρχει επίσης μια σημαντική αλληλεπίδραση με το seccomp. Τα unprivileged tasks γενικά χρειάζονται να έχει οριστεί το `no_new_privs` πριν μπορέσουν να εγκαταστήσουν ένα seccomp filter σε filter mode.<sup>[[1]](#references)</sup> Αυτός είναι ένας λόγος για τον οποίο τα hardened containers συχνά εμφανίζουν τα `Seccomp` και `NoNewPrivs` ενεργοποιημένα ταυτόχρονα. Από την πλευρά ενός attacker, η εμφάνιση και των δύο συνήθως σημαίνει ότι το περιβάλλον ρυθμίστηκε σκόπιμα και όχι κατά λάθος.

## Λανθασμένες Ρυθμίσεις

Το συνηθέστερο πρόβλημα είναι απλώς η μη ενεργοποίηση του control σε περιβάλλοντα όπου θα ήταν συμβατό. Στο Kubernetes, το να παραμένει ενεργοποιημένο το `allowPrivilegeEscalation` είναι συχνά το προεπιλεγμένο operational mistake. Στα Docker και Podman, η παράλειψη του σχετικού security option έχει το ίδιο αποτέλεσμα. Ένα ακόμη επαναλαμβανόμενο failure mode είναι η υπόθεση ότι, επειδή ένα container είναι «not privileged», οι privilege transitions κατά το exec είναι αυτόματα άσχετες.

Μια πιο subtle παγίδα του Kubernetes είναι ότι το `allowPrivilegeEscalation: false` **δεν** εφαρμόζεται με τον τρόπο που περιμένουν πολλοί όταν το container είναι `privileged` ή όταν διαθέτει `CAP_SYS_ADMIN`. Το Kubernetes API τεκμηριώνει ότι το `allowPrivilegeEscalation` είναι ουσιαστικά πάντα true σε αυτές τις περιπτώσεις.<sup>[[2]](#references)</sup> Στην πράξη, αυτό σημαίνει ότι το field πρέπει να αντιμετωπίζεται ως ένα μόνο signal στο τελικό posture και όχι ως εγγύηση ότι το runtime κατέληξε με `NoNewPrivs: 1`.

## Κατάχρηση

Αν το `no_new_privs` δεν έχει οριστεί, το πρώτο ερώτημα είναι αν το image περιέχει binaries που μπορούν ακόμη να αυξήσουν το privilege:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Ενδιαφέροντα αποτελέσματα περιλαμβάνουν:

- `NoNewPrivs: 0`
- βοηθητικά προγράμματα setuid, όπως `su`, `mount`, `passwd` ή εργαλεία διαχείρισης που εξαρτώνται από τη διανομή
- binaries με file capabilities που παρέχουν network ή filesystem privileges

Σε ένα πραγματικό assessment, αυτά τα ευρήματα δεν αποδεικνύουν από μόνα τους μια λειτουργική escalation, αλλά εντοπίζουν ακριβώς τα binaries που αξίζει να δοκιμαστούν στη συνέχεια.

Στο Kubernetes, επαληθεύστε επίσης ότι η πρόθεση του YAML αντιστοιχεί στην πραγματικότητα του kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Ενδιαφέροντες συνδυασμοί περιλαμβάνουν:

- `allowPrivilegeEscalation: false` στο Pod spec, αλλά `NoNewPrivs: 0` στο container
- παρουσία του `cap_sys_admin`, γεγονός που καθιστά το Kubernetes field πολύ λιγότερο αξιόπιστο
- `Seccomp: 0` και `NoNewPrivs: 0`, κάτι που συνήθως υποδεικνύει μια ευρέως αποδυναμωμένη runtime posture και όχι ένα μεμονωμένο λάθος

### Πλήρες Παράδειγμα: Privilege Escalation μέσα στο container μέσω setuid

Αυτό το control συνήθως αποτρέπει το **privilege escalation μέσα στο container** και όχι άμεσα το host escape. Αν το `NoNewPrivs` είναι `0` και υπάρχει ένας setuid helper, δοκιμάστε το ρητά:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Εάν υπάρχει και λειτουργεί ένα γνωστό δυαδικό αρχείο setuid, δοκιμάστε να το εκκινήσετε με τρόπο που διατηρεί τη μετάβαση προνομίων:
```bash
/bin/su -c id 2>/dev/null
```
Αυτό από μόνο του δεν κάνει escape από το container, αλλά μπορεί να μετατρέψει ένα low-privilege foothold μέσα στο container σε container-root, κάτι που συχνά αποτελεί προϋπόθεση για μεταγενέστερο host escape μέσω mounts, runtime sockets ή interfaces που επικοινωνούν με τον kernel.

## Έλεγχοι

Στόχος αυτών των ελέγχων είναι να διαπιστωθεί αν το privilege gain κατά το exec-time είναι αποκλεισμένο και αν το image εξακολουθεί να περιέχει helpers που θα είχαν σημασία σε περίπτωση που δεν είναι.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Το `NoNewPrivs: 1` είναι συνήθως το ασφαλέστερο αποτέλεσμα.
- Το `NoNewPrivs: 0` σημαίνει ότι τα μονοπάτια escalation μέσω setuid και file-cap παραμένουν σχετικά.
- Ο συνδυασμός `NoNewPrivs: 1` και `Seccomp: 2` αποτελεί συνηθισμένη ένδειξη πιο σκόπιμης προσέγγισης hardening.
- Ένα Kubernetes manifest που δηλώνει `allowPrivilegeEscalation: false` είναι χρήσιμο, αλλά η κατάσταση του kernel είναι η ground truth.
- Ένα minimal image με λίγα ή καθόλου setuid/file-cap binaries παρέχει σε έναν attacker λιγότερες επιλογές post-exploitation, ακόμη και όταν λείπει το `no_new_privs`.

## Προεπιλογές Runtime

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνηθισμένη χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Δεν είναι ενεργοποιημένο από προεπιλογή | Ενεργοποιείται ρητά με `--security-opt no-new-privileges=true`· υπάρχει επίσης προεπιλογή σε επίπεδο daemon μέσω του `dockerd --no-new-privileges` | παράλειψη του flag, `--privileged` |
| Podman | Δεν είναι ενεργοποιημένο από προεπιλογή | Ενεργοποιείται ρητά με `--security-opt no-new-privileges` ή ισοδύναμη ρύθμιση ασφαλείας | παράλειψη της επιλογής, `--privileged` |
| Kubernetes | Ελέγχεται από την πολιτική του workload | Το `allowPrivilegeEscalation: false` ζητά το συγκεκριμένο αποτέλεσμα, αλλά τα `privileged: true` και `CAP_SYS_ADMIN` το διατηρούν ουσιαστικά ενεργό | `allowPrivilegeEscalation: true`, `privileged: true`, προσθήκη του `CAP_SYS_ADMIN` |
| containerd / CRI-O υπό Kubernetes | Ακολουθεί τις ρυθμίσεις του Kubernetes workload / `OCI process.noNewPrivileges` | Συνήθως κληρονομείται από το security context του Pod και μεταφράζεται στη ρύθμιση του OCI runtime | ίδιο με τη γραμμή του Kubernetes |

Αυτή η προστασία συχνά απουσιάζει απλώς επειδή κανείς δεν την ενεργοποίησε, όχι επειδή το runtime δεν την υποστηρίζει.

## Αναφορές

- [1] [Τεκμηρίωση του Linux kernel: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
