# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

Το `no_new_privs` είναι μια λειτουργία hardening του kernel που εμποδίζει μια διεργασία να αποκτήσει περισσότερα privileges μέσω του `execve()`. Πρακτικά, μόλις οριστεί το flag, η εκτέλεση ενός setuid binary, ενός setgid binary ή ενός αρχείου με Linux file capabilities δεν παρέχει επιπλέον privilege πέρα από αυτό που είχε ήδη η διεργασία. Σε containerized environments, αυτό είναι σημαντικό επειδή πολλά privilege-escalation chains βασίζονται στην εύρεση ενός executable μέσα στο image που αλλάζει privilege κατά την εκκίνησή του.

Από αμυντικής πλευράς, το `no_new_privs` δεν αποτελεί υποκατάστατο των namespaces, του seccomp ή του capability dropping. Είναι ένα επίπεδο ενίσχυσης. Μπλοκάρει μια συγκεκριμένη κατηγορία επακόλουθου escalation, αφού έχει ήδη αποκτηθεί code execution. Αυτό το καθιστά ιδιαίτερα χρήσιμο σε environments όπου τα images περιέχουν helper binaries, package-manager artifacts ή legacy tools που διαφορετικά θα ήταν επικίνδυνα σε συνδυασμό με partial compromise.

## Λειτουργία

Το kernel flag που βρίσκεται πίσω από αυτήν τη συμπεριφορά είναι το `PR_SET_NO_NEW_PRIVS`. Μόλις οριστεί για μια διεργασία, οι επόμενες κλήσεις `execve()` δεν μπορούν να αυξήσουν το privilege. Η σημαντική λεπτομέρεια είναι ότι η διεργασία μπορεί να συνεχίσει να εκτελεί binaries· απλώς δεν μπορεί να χρησιμοποιήσει αυτά τα binaries για να διασχίσει ένα privilege boundary που ο kernel θα επέτρεπε διαφορετικά.

Η συμπεριφορά του kernel είναι επίσης **κληρονομήσιμη και μη αναστρέψιμη**: μόλις ένα task ορίσει το `no_new_privs`, το bit κληρονομείται μέσω των `fork()`, `clone()` και `execve()`, και δεν μπορεί να unset-αριστεί αργότερα. Αυτό είναι χρήσιμο σε assessments, επειδή ένα `NoNewPrivs: 1` στη διεργασία του container συνήθως σημαίνει ότι και οι descendants θα πρέπει να παραμείνουν σε αυτήν τη λειτουργία, εκτός αν εξετάζετε ένα εντελώς διαφορετικό process tree.

Σε Kubernetes-oriented environments, το `allowPrivilegeEscalation: false` αντιστοιχεί σε αυτήν τη συμπεριφορά για τη διεργασία του container. Σε runtimes τύπου Docker και Podman, το αντίστοιχο συνήθως ενεργοποιείται ρητά μέσω ενός security option. Στο OCI layer, η ίδια έννοια εμφανίζεται ως `process.noNewPrivileges`.

## Σημαντικές λεπτομέρειες

Το `no_new_privs` μπλοκάρει το privilege gain **κατά το exec**, όχι κάθε αλλαγή privilege. Συγκεκριμένα:

- οι μεταβάσεις setuid και setgid παύουν να λειτουργούν μέσω `execve()`
- τα file capabilities δεν προστίθενται στο permitted set μέσω `execve()`
- τα LSMs, όπως το AppArmor ή το SELinux, δεν χαλαρώνουν τους περιορισμούς μετά το `execve()`
- το privilege που έχει ήδη αποκτηθεί εξακολουθεί να είναι ήδη αποκτημένο

Το τελευταίο σημείο είναι σημαντικό σε operational επίπεδο. Αν η διεργασία εκτελείται ήδη ως root, διαθέτει ήδη ένα επικίνδυνο capability ή έχει ήδη πρόσβαση σε ένα ισχυρό runtime API ή σε writable host mount, η ρύθμιση του `no_new_privs` δεν εξουδετερώνει αυτές τις εκθέσεις. Απλώς αφαιρεί ένα συνηθισμένο **επόμενο βήμα** σε ένα privilege-escalation chain.

Σημειώστε επίσης ότι το flag δεν μπλοκάρει αλλαγές privilege που δεν εξαρτώνται από το `execve()`. Για παράδειγμα, ένα task που έχει ήδη αρκετά privileges μπορεί να καλέσει απευθείας το `setuid(2)` ή να λάβει ένα privileged file descriptor μέσω ενός Unix socket. Γι' αυτό το `no_new_privs` θα πρέπει να εξετάζεται μαζί με το [seccomp](seccomp.md), τα capability sets και το namespace exposure, και όχι ως αυτόνομη λύση.

## Lab

Επιθεωρήστε την κατάσταση της τρέχουσας διεργασίας:
```bash
grep NoNewPrivs /proc/self/status
```
Συγκρίνετέ το με ένα container στο οποίο το runtime ενεργοποιεί το flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Σε ένα hardened workload, το αποτέλεσμα θα πρέπει να εμφανίζει `NoNewPrivs: 1`.

Μπορείτε επίσης να επιδείξετε το πραγματικό αποτέλεσμα σε ένα setuid binary:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Το σημείο της σύγκρισης δεν είναι ότι το `su` είναι καθολικά exploitable. Είναι ότι το ίδιο image μπορεί να συμπεριφέρεται πολύ διαφορετικά, ανάλογα με το αν το `execve()` εξακολουθεί να επιτρέπεται να διασχίσει ένα privilege boundary.

## Επίδραση στην ασφάλεια

Αν απουσιάζει το `no_new_privs`, ένα foothold μέσα στο container μπορεί ακόμη να αναβαθμιστεί μέσω setuid helpers ή binaries με file capabilities. Αν είναι ενεργοποιημένο, αυτές οι αλλαγές privilege μετά το exec διακόπτονται. Η επίδραση είναι ιδιαίτερα σημαντική σε broad base images που περιλαμβάνουν πολλά utilities τα οποία η εφαρμογή δεν χρειάστηκε ποτέ.

Υπάρχει επίσης μια σημαντική αλληλεπίδραση με το seccomp. Τα unprivileged tasks γενικά χρειάζονται να έχει οριστεί το `no_new_privs` πριν μπορέσουν να εγκαταστήσουν ένα seccomp filter σε filter mode. Αυτός είναι ένας λόγος για τον οποίο τα hardened containers συχνά εμφανίζουν ενεργοποιημένα τόσο τα `Seccomp` όσο και `NoNewPrivs`. Από την οπτική γωνία ενός attacker, η παρουσία και των δύο συνήθως σημαίνει ότι το environment ρυθμίστηκε σκόπιμα και όχι κατά λάθος.

## Misconfigurations

Το πιο συνηθισμένο πρόβλημα είναι απλώς η μη ενεργοποίηση του control σε environments όπου θα ήταν συμβατό. Στο Kubernetes, το να παραμένει ενεργοποιημένο το `allowPrivilegeEscalation` είναι συχνά το προεπιλεγμένο operational mistake. Στα Docker και Podman, η παράλειψη του σχετικού security option έχει το ίδιο αποτέλεσμα. Ένα ακόμη επαναλαμβανόμενο failure mode είναι η υπόθεση ότι, επειδή ένα container είναι "not privileged", οι privilege transitions κατά το exec είναι αυτόματα άσχετες.

Ένα πιο subtle Kubernetes pitfall είναι ότι το `allowPrivilegeEscalation: false` **δεν** εφαρμόζεται με τον τρόπο που περιμένουν πολλοί όταν το container είναι `privileged` ή όταν διαθέτει `CAP_SYS_ADMIN`. Το Kubernetes API τεκμηριώνει ότι το `allowPrivilegeEscalation` είναι ουσιαστικά πάντα true σε αυτές τις περιπτώσεις. Στην πράξη, αυτό σημαίνει ότι το field πρέπει να αντιμετωπίζεται ως ένα signal στο τελικό posture και όχι ως εγγύηση ότι το runtime κατέληξε με `NoNewPrivs: 1`.

## Abuse

Αν δεν έχει οριστεί το `no_new_privs`, το πρώτο ερώτημα είναι αν το image περιέχει binaries που μπορούν ακόμη να αυξήσουν το privilege:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Ενδιαφέροντα αποτελέσματα περιλαμβάνουν:

- `NoNewPrivs: 0`
- setuid helpers όπως `su`, `mount`, `passwd` ή distribution-specific admin tools
- binaries με file capabilities που παρέχουν network ή filesystem privileges

Σε ένα real assessment, αυτά τα ευρήματα δεν αποδεικνύουν από μόνα τους ένα working escalation, αλλά εντοπίζουν ακριβώς τα binaries που αξίζει να δοκιμαστούν στη συνέχεια.

Στο Kubernetes, επαληθεύστε επίσης ότι το YAML intent αντιστοιχεί στην πραγματικότητα του kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Ενδιαφέροντες συνδυασμοί περιλαμβάνουν:

- `allowPrivilegeEscalation: false` στο Pod spec, αλλά `NoNewPrivs: 0` στο container
- παρουσία του `cap_sys_admin`, γεγονός που καθιστά το Kubernetes field πολύ λιγότερο αξιόπιστο
- `Seccomp: 0` και `NoNewPrivs: 0`, κάτι που συνήθως υποδεικνύει μια γενικά αποδυναμωμένη runtime posture και όχι ένα μεμονωμένο λάθος

### Πλήρες Παράδειγμα: In-Container Privilege Escalation μέσω setuid

Αυτός ο έλεγχος συνήθως αποτρέπει το **in-container privilege escalation** και όχι άμεσα το host escape. Αν το `NoNewPrivs` είναι `0` και υπάρχει setuid helper, δοκιμάστε το ρητά:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Εάν υπάρχει και λειτουργεί ένα γνωστό setuid binary, δοκιμάστε να το εκκινήσετε με τρόπο που διατηρεί τη μετάβαση προνομίων:
```bash
/bin/su -c id 2>/dev/null
```
Αυτό από μόνο του δεν πραγματοποιεί escape από το container, αλλά μπορεί να μετατρέψει ένα foothold χαμηλών προνομίων μέσα στο container σε container-root, κάτι που συχνά αποτελεί προϋπόθεση για μεταγενέστερο host escape μέσω mounts, runtime sockets ή interfaces που επικοινωνούν με τον kernel.

## Checks

Στόχος αυτών των checks είναι να διαπιστωθεί αν το gain προνομίων κατά το exec-time είναι αποκλεισμένο και αν το image εξακολουθεί να περιέχει helpers που θα είχαν σημασία σε περίπτωση που δεν είναι.
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
- Το `NoNewPrivs: 0` σημαίνει ότι τα μονοπάτια escalation που βασίζονται σε setuid και file-cap παραμένουν σχετικά.
- Ο συνδυασμός `NoNewPrivs: 1` και `Seccomp: 2` αποτελεί συχνή ένδειξη πιο intentional hardening posture.
- Ένα Kubernetes manifest που ορίζει `allowPrivilegeEscalation: false` είναι χρήσιμο, αλλά το kernel status είναι η πραγματική πηγή αλήθειας.
- Ένα minimal image με λίγα ή καθόλου setuid/file-cap binaries προσφέρει σε έναν attacker λιγότερες post-exploitation επιλογές, ακόμη και όταν λείπει το `no_new_privs`.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Δεν είναι enabled by default | Ενεργοποιείται ρητά με `--security-opt no-new-privileges=true`; υπάρχει επίσης daemon-wide default μέσω του `dockerd --no-new-privileges` | παράλειψη του flag, `--privileged` |
| Podman | Δεν είναι enabled by default | Ενεργοποιείται ρητά με `--security-opt no-new-privileges` ή ισοδύναμη security configuration | παράλειψη της option, `--privileged` |
| Kubernetes | Ελέγχεται από workload policy | Το `allowPrivilegeEscalation: false` ζητά το συγκεκριμένο effect, αλλά τα `privileged: true` και `CAP_SYS_ADMIN` το διατηρούν effectively true | `allowPrivilegeEscalation: true`, `privileged: true`, προσθήκη του `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Ακολουθεί τα Kubernetes workload settings / OCI `process.noNewPrivileges` | Συνήθως κληρονομείται από το Pod security context και μεταφράζεται σε OCI runtime config | ίδιο με τη γραμμή του Kubernetes |

Αυτή η protection συχνά απουσιάζει απλώς επειδή κανείς δεν την ενεργοποίησε, όχι επειδή το runtime δεν την υποστηρίζει.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
