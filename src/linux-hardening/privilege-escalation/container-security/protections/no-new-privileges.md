# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` είναι ένα feature hardening του kernel που αποτρέπει μια διεργασία από το να αποκτήσει περισσότερα privilege μέσω `execve()`. Στην πράξη, μόλις οριστεί το flag, η εκτέλεση ενός setuid binary, ενός setgid binary ή ενός file με Linux file capabilities δεν δίνει επιπλέον privilege πέρα από ό,τι είχε ήδη η διεργασία. Σε containerized environments, αυτό είναι σημαντικό επειδή πολλές privilege-escalation chains βασίζονται στο να βρουν ένα executable μέσα στο image που αλλάζει privilege όταν εκκινεί.

Από αμυντική σκοπιά, το `no_new_privs` δεν είναι υποκατάστατο για namespaces, seccomp ή capability dropping. Είναι ένα reinforcement layer. Μπλοκάρει μια συγκεκριμένη κατηγορία follow-up escalation αφού έχει ήδη αποκτηθεί code execution. Αυτό το κάνει ιδιαίτερα χρήσιμο σε environments όπου τα images περιέχουν helper binaries, package-manager artifacts ή legacy tools που αλλιώς θα ήταν επικίνδυνα όταν συνδυάζονται με partial compromise.

## Operation

Το kernel flag πίσω από αυτή τη συμπεριφορά είναι το `PR_SET_NO_NEW_PRIVS`. Μόλις οριστεί για μια διεργασία, τα μετέπειτα `execve()` calls δεν μπορούν να αυξήσουν το privilege. Η σημαντική λεπτομέρεια είναι ότι η διεργασία μπορεί ακόμα να εκτελεί binaries· απλώς δεν μπορεί να χρησιμοποιήσει αυτά τα binaries για να περάσει ένα privilege boundary που ο kernel διαφορετικά θα αναγνώριζε.

Η συμπεριφορά του kernel είναι επίσης **κληρονομούμενη και μη αναστρέψιμη**: μόλις ένα task ορίσει `no_new_privs`, το bit κληρονομείται μέσω `fork()`, `clone()` και `execve()`, και δεν μπορεί να απενεργοποιηθεί αργότερα. Αυτό είναι χρήσιμο σε assessments επειδή ένα μόνο `NoNewPrivs: 1` στη διεργασία του container συνήθως σημαίνει ότι και οι απόγονοι θα πρέπει να παραμείνουν σε αυτό το mode, εκτός αν εξετάζεις ένα εντελώς διαφορετικό process tree.

Σε Kubernetes-oriented environments, το `allowPrivilegeEscalation: false` αντιστοιχεί σε αυτή τη συμπεριφορά για τη διεργασία του container. Σε Docker και Podman style runtimes, το αντίστοιχο συνήθως ενεργοποιείται ρητά μέσω μιας security option. Στο OCI layer, η ίδια έννοια εμφανίζεται ως `process.noNewPrivileges`.

## Important Nuances

Το `no_new_privs` μπλοκάρει την απόκτηση privilege κατά το **exec-time**, όχι κάθε αλλαγή privilege. Συγκεκριμένα:

- οι μεταβάσεις setuid και setgid σταματούν να λειτουργούν μέσω `execve()`
- τα file capabilities δεν προστίθενται στο permitted set στο `execve()`
- LSMs όπως το AppArmor ή το SELinux δεν χαλαρώνουν τους περιορισμούς μετά το `execve()`
- το ήδη-held privilege παραμένει ήδη-held privilege

Αυτό το τελευταίο σημείο έχει operational σημασία. Αν η διεργασία τρέχει ήδη ως root, έχει ήδη ένα επικίνδυνο capability ή έχει ήδη πρόσβαση σε ένα ισχυρό runtime API ή σε writable host mount, το `no_new_privs` δεν εξουδετερώνει αυτά τα exposures. Απλώς αφαιρεί ένα κοινό **next step** σε μια privilege-escalation chain.

Σημείωσε επίσης ότι το flag δεν μπλοκάρει αλλαγές privilege που δεν εξαρτώνται από το `execve()`. Για παράδειγμα, ένα task που είναι ήδη αρκετά privileged μπορεί ακόμα να καλέσει `setuid(2)` απευθείας ή να λάβει ένα privileged file descriptor μέσω ενός Unix socket. Γι’ αυτό το `no_new_privs` πρέπει να διαβάζεται μαζί με [seccomp](seccomp.md), capability sets και namespace exposure, αντί ως αυτόνομη απάντηση.

## Lab

Επιθεώρησε την τρέχουσα κατάσταση της διεργασίας:
```bash
grep NoNewPrivs /proc/self/status
```
Σύγκρινέ το με ένα container όπου το runtime ενεργοποιεί το flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Σε ένα hardened workload, το αποτέλεσμα θα πρέπει να δείχνει `NoNewPrivs: 1`.

Μπορείς επίσης να δείξεις το πραγματικό effect απέναντι σε ένα setuid binary:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Το σημείο της σύγκρισης δεν είναι ότι το `su` είναι καθολικά εκμεταλλεύσιμο. Είναι ότι η ίδια εικόνα μπορεί να συμπεριφέρεται πολύ διαφορετικά ανάλογα με το αν το `execve()` επιτρέπεται ακόμα να διασχίσει ένα όριο δικαιωμάτων.

## Security Impact

Αν το `no_new_privs` απουσιάζει, ένα foothold μέσα στο container μπορεί ακόμη να αναβαθμιστεί μέσω setuid helpers ή binaries με file capabilities. Αν υπάρχει, αυτές οι post-exec αλλαγές δικαιωμάτων κόβονται. Το αποτέλεσμα είναι ιδιαίτερα σχετικό σε ευρείες base images που περιλαμβάνουν πολλά utilities τα οποία η εφαρμογή δεν χρειαζόταν εξαρχής.

Υπάρχει επίσης μια σημαντική αλληλεπίδραση με το seccomp. Unprivileged tasks γενικά χρειάζονται το `no_new_privs` ενεργοποιημένο πριν μπορέσουν να εγκαταστήσουν ένα seccomp filter σε filter mode. Αυτός είναι ένας λόγος που hardened containers συχνά εμφανίζουν και τα `Seccomp` και `NoNewPrivs` ενεργοποιημένα μαζί. Από την οπτική του attacker, η παρουσία και των δύο συνήθως σημαίνει ότι το environment ρυθμίστηκε σκόπιμα και όχι κατά λάθος.

## Misconfigurations

Το πιο συνηθισμένο πρόβλημα είναι απλώς η μη ενεργοποίηση του control σε environments όπου θα ήταν συμβατό. Στο Kubernetes, το να αφήνεις το `allowPrivilegeEscalation` ενεργοποιημένο είναι συχνά το προεπιλεγμένο operational λάθος. Στο Docker και το Podman, η παράλειψη της σχετικής security option έχει το ίδιο αποτέλεσμα. Ένας άλλος επαναλαμβανόμενος failure mode είναι η υπόθεση ότι επειδή ένα container είναι "not privileged", οι exec-time privilege transitions είναι αυτόματα άσχετες.

Ένα πιο λεπτό Kubernetes pitfall είναι ότι το `allowPrivilegeEscalation: false` **δεν** εφαρμόζεται όπως το περιμένουν οι άνθρωποι όταν το container είναι `privileged` ή όταν έχει `CAP_SYS_ADMIN`. Το Kubernetes API τεκμηριώνει ότι το `allowPrivilegeEscalation` είναι πρακτικά πάντα true σε αυτές τις περιπτώσεις. Στην πράξη, αυτό σημαίνει ότι το field πρέπει να αντιμετωπίζεται ως ένα signal στη συνολική στάση ασφάλειας, όχι ως εγγύηση ότι το runtime κατέληξε με `NoNewPrivs: 1`.

## Abuse

Αν το `no_new_privs` δεν είναι ενεργό, το πρώτο ερώτημα είναι αν η image περιέχει binaries που μπορούν ακόμα να αυξήσουν privilege:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Ενδιαφέροντα αποτελέσματα περιλαμβάνουν:

- `NoNewPrivs: 0`
- setuid helpers όπως `su`, `mount`, `passwd`, ή distribution-specific admin tools
- binaries με file capabilities που δίνουν network ή filesystem privileges

Σε μια πραγματική assessment, αυτά τα ευρήματα δεν αποδεικνύουν από μόνα τους ένα working escalation, αλλά εντοπίζουν ακριβώς τα binaries που αξίζει να δοκιμάσεις στη συνέχεια.

Στο Kubernetes, επαλήθευσε επίσης ότι το YAML intent ταιριάζει με την kernel reality:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Ενδιαφέροντες συνδυασμοί περιλαμβάνουν:

- `allowPrivilegeEscalation: false` στο Pod spec αλλά `NoNewPrivs: 0` στο container
- `cap_sys_admin` παρόν, κάτι που κάνει το Kubernetes field πολύ λιγότερο αξιόπιστο
- `Seccomp: 0` και `NoNewPrivs: 0`, που συνήθως υποδηλώνει μια γενικά αποδυναμωμένη runtime στάση αντί για ένα μεμονωμένο, απομονωμένο λάθος

### Full Example: In-Container Privilege Escalation Through setuid

Αυτό το control συνήθως αποτρέπει **in-container privilege escalation** αντί για host escape άμεσα. Αν το `NoNewPrivs` είναι `0` και υπάρχει ένα setuid helper, δοκίμασέ το ρητά:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Αν υπάρχει ένα γνωστό setuid binary και είναι λειτουργικό, δοκίμασε να το εκκινήσεις με τρόπο που διατηρεί τη μετάβαση δικαιωμάτων:
```bash
/bin/su -c id 2>/dev/null
```
Αυτό από μόνο του δεν διαφεύγει από το container, αλλά μπορεί να μετατρέψει ένα low-privilege foothold μέσα στο container σε container-root, κάτι που συχνά γίνεται η προϋπόθεση για αργότερο host escape μέσω mounts, runtime sockets ή kernel-facing interfaces.

## Checks

Ο στόχος αυτών των checks είναι να διαπιστωθεί αν το exec-time privilege gain είναι blocked και αν το image εξακολουθεί να περιέχει helpers που θα είχαν σημασία αν δεν είναι.
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

- `NoNewPrivs: 1` είναι συνήθως το πιο ασφαλές αποτέλεσμα.
- `NoNewPrivs: 0` σημαίνει ότι τα setuid και file-cap escalation paths παραμένουν σχετικά.
- `NoNewPrivs: 1` μαζί με `Seccomp: 2` είναι συχνό σημάδι μιας πιο συνειδητής hardening posture.
- Ένα Kubernetes manifest που λέει `allowPrivilegeEscalation: false` είναι χρήσιμο, αλλά η kernel κατάσταση είναι η ground truth.
- Ένα minimal image με λίγα ή καθόλου setuid/file-cap binaries δίνει σε έναν attacker λιγότερες post-exploitation επιλογές ακόμα και όταν λείπει το `no_new_privs`.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges=true`; daemon-wide default also exists via `dockerd --no-new-privileges` | omitting the flag, `--privileged` |
| Podman | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges` or equivalent security configuration | omitting the option, `--privileged` |
| Kubernetes | Controlled by workload policy | `allowPrivilegeEscalation: false` requests the effect, but `privileged: true` and `CAP_SYS_ADMIN` keep it effectively true | `allowPrivilegeEscalation: true`, `privileged: true`, adding `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes workload settings / OCI `process.noNewPrivileges` | Usually inherited from the Pod security context and translated into OCI runtime config | same as Kubernetes row |

Αυτή η προστασία συχνά απουσιάζει απλώς επειδή κανείς δεν την ενεργοποίησε, όχι επειδή το runtime δεν την υποστηρίζει.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
