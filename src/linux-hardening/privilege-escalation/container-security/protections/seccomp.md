# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

**seccomp** είναι ο μηχανισμός που επιτρέπει στον kernel να εφαρμόσει ένα φίλτρο στα syscalls που μπορεί να καλέσει μια διεργασία. Σε περιβάλλοντα με containers, το seccomp συνήθως χρησιμοποιείται σε filter mode ώστε η διεργασία να μην χαρακτηρίζεται απλώς "restricted" με ασαφή τρόπο, αλλά να υπόκειται σε μια συγκεκριμένη πολιτική για syscalls. Αυτό έχει σημασία γιατί πολλά container breakouts απαιτούν πρόσβαση σε πολύ συγκεκριμένα interfaces του kernel. Αν η διεργασία δεν μπορεί επιτυχώς να καλέσει τα σχετικά syscalls, μια μεγάλη κατηγορία επιθέσεων εξαφανίζεται πριν ακόμη αποκτήσουν σημασία αποχρώσεις σε namespaces ή capabilities.

Το βασικό νοητικό μοντέλο είναι απλό: τα namespaces αποφασίζουν **τι μπορεί να δει η διεργασία**, οι capabilities αποφασίζουν **ποιες προνομιούχες ενέργειες επιτρέπεται ονομαστικά να προσπαθήσει η διεργασία**, και το seccomp αποφασίζει **εάν ο πυρήνας θα δεχτεί καν το syscall ως σημείο εισόδου για την επιδιωκόμενη ενέργεια**. Γι' αυτό το seccomp συχνά αποτρέπει επιθέσεις που διαφορετικά θα φαινόντουσαν δυνατές βάσει μόνο των capabilities.

## Επίδραση Ασφαλείας

Πολύ επικίνδυνη επιφάνεια του kernel είναι προσβάσιμη μόνο μέσω ενός σχετικά μικρού συνόλου syscalls. Παραδείγματα που συχνά έχουν σημασία στην ενίσχυση ασφάλειας container περιλαμβάνουν `mount`, `unshare`, `clone` ή `clone3` με συγκεκριμένα flags, `bpf`, `ptrace`, `keyctl`, και `perf_event_open`. Επιτιθέμενος που μπορεί να φτάσει αυτά τα syscalls μπορεί να δημιουργήσει νέα namespaces, να χειριστεί υποσυστήματα του kernel ή να αλληλεπιδράσει με επιφάνειες επίθεσης που ένα συνηθισμένο application container δεν χρειάζεται καθόλου.

Γι' αυτό οι προεπιλεγμένες runtime seccomp profiles είναι τόσο σημαντικές. Δεν αποτελούν απλώς "επιπλέον άμυνα". Σε πολλά περιβάλλοντα είναι η διαφορά ανάμεσα σε ένα container που μπορεί να χρησιμοποιήσει μεγάλο μέρος της λειτουργικότητας του kernel και σε ένα που περιορίζεται σε μια επιφάνεια syscalls πιο κοντά σε αυτήν που χρειάζεται πραγματικά η εφαρμογή.

## Καθεστώτα και Κατασκευή Φίλτρου

Ο seccomp ιστορικά είχε ένα strict mode στο οποίο μόνο ένα πολύ μικρό σύνολο syscalls παρέμενε διαθέσιμο, αλλά το καθεστώς που αφορά τους σύγχρονους container runtimes είναι το seccomp filter mode, συχνά αποκαλούμενο **seccomp-bpf**. Σε αυτό το μοντέλο, ο kernel αξιολογεί ένα πρόγραμμα φίλτρου που αποφασίζει εάν ένα syscall πρέπει να επιτραπεί, να απορριφθεί με errno, να παγιδευτεί, να καταγραφεί ή να τερματίσει τη διεργασία. Τα container runtimes χρησιμοποιούν αυτόν τον μηχανισμό επειδή είναι αρκετά εκφραστικός ώστε να μπλοκάρει ευρείες κατηγορίες επικίνδυνων syscalls ενώ ταυτόχρονα επιτρέπει τη φυσιολογική συμπεριφορά των εφαρμογών.

Two low-level examples are useful because they make the mechanism concrete rather than magical. Strict mode demonstrates the old "only a minimal syscall set survives" model:
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
Το τελευταίο `open` προκαλεί τη διακοπή της διεργασίας επειδή δεν αποτελεί μέρος του ελάχιστου συνόλου του strict mode.

Ένα παράδειγμα φίλτρου libseccomp δείχνει πιο καθαρά το σύγχρονο μοντέλο πολιτικής:
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
Αυτό το στυλ πολιτικής είναι αυτό που οι περισσότεροι αναγνώστες πρέπει να φαντάζονται όταν σκέφτονται runtime seccomp profiles.

## Εργαστήριο

Ένας απλός τρόπος να επιβεβαιώσετε ότι το seccomp είναι ενεργό σε ένα container είναι:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Μπορείτε επίσης να δοκιμάσετε μια λειτουργία που τα προεπιλεγμένα προφίλ συνήθως περιορίζουν:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Αν το container τρέχει υπό ένα κανονικό προεπιλεγμένο seccomp profile, οι λειτουργίες τύπου `unshare` συχνά αποκλείονται. Αυτό είναι μια χρήσιμη επίδειξη επειδή δείχνει ότι ακόμα κι αν το userspace tool υπάρχει μέσα στην image, η διαδρομή του kernel που χρειάζεται μπορεί να παραμένει μη διαθέσιμη.
Αν το container τρέχει υπό ένα κανονικό προεπιλεγμένο seccomp profile, οι λειτουργίες τύπου `unshare` συχνά αποκλείονται ακόμη και όταν το userspace tool υπάρχει μέσα στην image.

Για να ελέγξετε γενικότερα την κατάσταση της διεργασίας, εκτελέστε:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Χρήση κατά την εκτέλεση

Docker υποστηρίζει τόσο προεπιλεγμένα όσο και προσαρμοσμένα seccomp profiles και επιτρέπει στους διαχειριστές να τα απενεργοποιήσουν με `--security-opt seccomp=unconfined`. Το Podman έχει παρόμοια υποστήριξη και συχνά συνδυάζει το seccomp με εκτέλεση χωρίς root ως λογική προεπιλεγμένη ρύθμιση. Το Kubernetes εκθέτει το seccomp μέσω της ρύθμισης των workloads, όπου το `RuntimeDefault` είναι συνήθως η λογική βάση και το `Unconfined` θα πρέπει να θεωρείται εξαίρεση που απαιτεί αιτιολόγηση και όχι απλώς ένα βολικό toggle.

Σε περιβάλλοντα βάσει containerd και CRI-O, η ακριβής διαδρομή είναι πιο πολυεπίπεδη, αλλά η αρχή παραμένει η ίδια: ο engine ή orchestrator υψηλότερου επιπέδου αποφασίζει τι πρέπει να γίνει, και το runtime τελικά εγκαθιστά την προκύπτουσα πολιτική seccomp για τη διεργασία του container. Το αποτέλεσμα εξακολουθεί να εξαρτάται από την τελική runtime ρύθμιση που φτάνει στον kernel.

### Παράδειγμα Προσαρμοσμένης Πολιτικής

Το Docker και παρόμοιοι engines μπορούν να φορτώσουν ένα προσαρμοσμένο seccomp profile από JSON. Ένα ελάχιστο παράδειγμα που απορρίπτει την `chmod` ενώ επιτρέπει τα υπόλοιπα έχει ως εξής:
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Εφαρμόστηκε με:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Η εντολή αποτυγχάνει με `Operation not permitted`, αποδεικνύοντας ότι ο περιορισμός προέρχεται από την πολιτική των syscall και όχι μόνο από τα συνήθη δικαιώματα αρχείων. Σε πραγματική σκλήρυνση, οι λίστες επιτρεπόμενων είναι γενικά πιο ισχυρές από τις χαλαρές προεπιλογές με μια μικρή μαύρη λίστα.

## Εσφαλμένες διαμορφώσεις

Το πιο τρανταχτό λάθος είναι να ορίσετε το seccomp σε **unconfined** επειδή μια εφαρμογή απέτυχε κάτω από την προεπιλεγμένη πολιτική. Αυτό είναι συνηθισμένο κατά τη διερεύνηση προβλημάτων και πολύ επικίνδυνο ως μόνιμη διόρθωση. Μόλις το φίλτρο εξαφανιστεί, πολλά primitives διαφυγής βασισμένα σε syscall γίνονται ξανά προσβάσιμα, ειδικά όταν υπάρχουν ισχυρές capabilities ή κοινή χρήση host namespaces.

Ένα ακόμα συχνό πρόβλημα είναι η χρήση ενός **custom permissive profile** που αντιγράφηκε από κάποιο blog ή εσωτερικό workaround χωρίς προσεκτική αναθεώρηση. Ομάδες μερικές φορές διατηρούν σχεδόν όλα τα επικίνδυνα syscalls απλώς επειδή το profile κατασκευάστηκε με στόχο το "stop the app from breaking" αντί για το "grant only what the app actually needs". Μια τρίτη παρανόηση είναι η υπόθεση ότι το seccomp είναι λιγότερο σημαντικό για μη-root containers. Στην πραγματικότητα, μεγάλη επιφάνεια επίθεσης του kernel παραμένει σχετική ακόμη και όταν η διεργασία δεν είναι UID 0.

## Κατάχρηση

Αν το seccomp απουσιάζει ή είναι σοβαρά αποδυναμωμένο, ένας επιτιθέμενος μπορεί να καταφέρει να καλέσει syscalls δημιουργίας namespaces, να επεκτείνει την προσβάσιμη επιφάνεια επίθεσης του kernel μέσω `bpf` ή `perf_event_open`, να καταχραστεί το `keyctl`, ή να συνδυάσει αυτές τις διαδρομές syscall με επικίνδυνες capabilities όπως το `CAP_SYS_ADMIN`. Σε πολλές πραγματικές επιθέσεις, το seccomp δεν είναι ο μόνος ελλείπων έλεγχος, αλλά η απουσία του συντομεύει δραματικά τη διαδρομή exploit επειδή αφαιρεί μία από τις λίγες άμυνες που μπορούν να σταματήσουν ένα ριψοκίνδυνο syscall πριν μπει στο παιχνίδι το υπόλοιπο μοντέλο προνομίων.

Το πιο χρήσιμο πρακτικό τεστ είναι να δοκιμάσετε τις ακριβείς οικογένειες syscall που συνήθως μπλοκάρουν τα default profiles. Αν ξαφνικά δουλέψουν, η στάση του container έχει αλλάξει πολύ:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Εάν το `CAP_SYS_ADMIN` ή κάποια άλλη ισχυρή capability υπάρχει, ελέγξτε αν το seccomp είναι το μόνο εμπόδιο που λείπει πριν από mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Σε ορισμένους στόχους, η άμεση αξία δεν είναι το πλήρες escape αλλά το information gathering και η kernel attack-surface expansion. Αυτές οι εντολές βοηθούν να διαπιστωθεί εάν ιδιαίτερα ευαίσθητες syscall διαδρομές είναι προσβάσιμες:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Εάν το seccomp απουσιάζει και το container είναι επίσης privileged με άλλους τρόπους, τότε έχει νόημα να μεταβείτε σε πιο συγκεκριμένες breakout techniques που έχουν ήδη τεκμηριωθεί στις legacy container-escape σελίδες.

### Πλήρες παράδειγμα: seccomp ήταν το μόνο που εμπόδιζε το `unshare`

Σε πολλούς στόχους, το πρακτικό αποτέλεσμα της αφαίρεσης του seccomp είναι ότι namespace-creation ή mount syscalls ξαφνικά αρχίζουν να λειτουργούν. Αν το container έχει επίσης `CAP_SYS_ADMIN`, η ακόλουθη αλληλουχία μπορεί να γίνει δυνατή:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
Από μόνο του αυτό δεν αποτελεί ακόμη host escape, αλλά δείχνει ότι το seccomp ήταν το εμπόδιο που απέτρεπε mount-related exploitation.

### Πλήρες Παράδειγμα: seccomp απενεργοποιημένο + cgroup v1 `release_agent`

Εάν το seccomp είναι απενεργοποιημένο και το container μπορεί να mount ιεραρχίες cgroup v1, η τεχνική `release_agent` από την ενότητα cgroups γίνεται προσβάσιμη:
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Αυτό δεν είναι seccomp-only exploit. Το σημείο είναι ότι μόλις το seccomp απελευθερωθεί, οι syscall-heavy breakout chains που προηγουμένως αποκλείονταν μπορεί να αρχίσουν να λειτουργούν ακριβώς όπως έχουν γραφτεί.

## Έλεγχοι

Ο σκοπός αυτών των ελέγχων είναι να διαπιστωθεί αν το seccomp είναι ενεργό, αν συνοδεύεται από το `no_new_privs`, και αν η ρύθμιση χρόνου εκτέλεσης δείχνει ρητά ότι το seccomp έχει απενεργοποιηθεί.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Τι είναι ενδιαφέρον εδώ:

- Μία μη μηδενική τιμή `Seccomp` σημαίνει ότι το φιλτράρισμα είναι ενεργό· `0` συνήθως σημαίνει ότι δεν υπάρχει seccomp προστασία.
- Αν οι επιλογές ασφάλειας του runtime περιλαμβάνουν `seccomp=unconfined`, το workload έχει χάσει μία από τις πιο χρήσιμες syscall-level άμυνές του.
- `NoNewPrivs` δεν είναι seccomp από μόνο του, αλλά το να βλέπεις και τα δύο μαζί υποδεικνύει συνήθως μια πιο προσεκτική στάση hardening από το να μη βλέπεις κανένα.

Αν ένα container ήδη έχει ύποπτα mounts, broad capabilities, ή shared host namespaces, και το seccomp είναι επίσης unconfined, αυτός ο συνδυασμός πρέπει να θεωρηθεί ως σημαντικό σήμα escalation. Το container μπορεί παρ' όλα αυτά να μην είναι εύκολα διασπώμενο, αλλά ο αριθμός των kernel entry points που είναι διαθέσιμοι στον attacker έχει αυξηθεί απότομα.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Συνήθως ενεργοποιημένο από προεπιλογή | Χρησιμοποιεί το ενσωματωμένο προεπιλεγμένο seccomp profile του Docker εκτός αν παρακαμφθεί | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Συνήθως ενεργοποιημένο από προεπιλογή | Εφαρμόζει το runtime προεπιλεγμένο seccomp profile εκτός αν παρακαμφθεί | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Δεν εγγυάται από προεπιλογή** | Εάν `securityContext.seccompProfile` δεν έχει οριστεί, η προεπιλογή είναι `Unconfined` εκτός αν ο kubelet ενεργοποιήσει `--seccomp-default`; πρέπει διαφορετικά να οριστεί ρητά `RuntimeDefault` ή `Localhost` | `securityContext.seccompProfile.type: Unconfined`, αφήνοντας seccomp μη ορισμένο σε clusters χωρίς `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Ακολουθεί τις ρυθμίσεις κόμβου και Pod του Kubernetes | Το runtime profile χρησιμοποιείται όταν το Kubernetes ζητάει `RuntimeDefault` ή όταν η προεπιλογή seccomp του kubelet είναι ενεργοποιημένη | Ίδιο με την σειρά Kubernetes; απευθείας CRI/OCI διαμόρφωση μπορεί επίσης να παραλείψει εντελώς το seccomp |

Η συμπεριφορά του Kubernetes είναι αυτή που εκπλήσσει πιο συχνά τους operators. Σε πολλά clusters, το seccomp εξακολουθεί να απουσιάζει εκτός αν το Pod το ζητήσει ή ο kubelet έχει ρυθμιστεί να έχει ως προεπιλογή το `RuntimeDefault`.
