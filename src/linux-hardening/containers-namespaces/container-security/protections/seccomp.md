# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το **seccomp** είναι ο μηχανισμός που επιτρέπει στον kernel να εφαρμόζει ένα filter στα syscalls που μπορεί να καλέσει ένα process. Σε containerized environments, το seccomp χρησιμοποιείται συνήθως σε filter mode, ώστε το process να μην χαρακτηρίζεται απλώς ως "restricted" με αόριστη έννοια, αλλά να υπόκειται σε μια συγκεκριμένη πολιτική syscalls. Αυτό έχει σημασία επειδή πολλά container breakouts απαιτούν πρόσβαση σε πολύ συγκεκριμένα kernel interfaces. Αν το process δεν μπορεί να καλέσει επιτυχώς τα σχετικά syscalls, μια μεγάλη κατηγορία attacks εξαφανίζεται προτού αποκτήσει σημασία οποιαδήποτε λεπτομέρεια σχετικά με namespaces ή capabilities.

Το βασικό mental model είναι απλό: τα namespaces αποφασίζουν **τι μπορεί να δει το process**, τα capabilities αποφασίζουν **ποιες privileged ενέργειες επιτρέπεται ονομαστικά να επιχειρήσει το process**, και το seccomp αποφασίζει **αν ο kernel θα αποδεχτεί καν το syscall entry point για την ενέργεια που επιχειρείται**. Γι' αυτό το seccomp αποτρέπει συχνά attacks που διαφορετικά θα φαίνονταν εφικτά με βάση μόνο τα capabilities.

## Επίδραση στην Ασφάλεια

Μεγάλο μέρος της επικίνδυνης επιφάνειας του kernel είναι προσβάσιμο μόνο μέσω ενός σχετικά μικρού συνόλου syscalls. Παραδείγματα που έχουν επανειλημμένα σημασία στο container hardening περιλαμβάνουν τα `mount`, `unshare`, `clone` ή `clone3` με συγκεκριμένα flags, `bpf`, `ptrace`, `keyctl` και `perf_event_open`. Ένας attacker που μπορεί να καλέσει αυτά τα syscalls ενδέχεται να μπορεί να δημιουργήσει νέα namespaces, να χειριστεί kernel subsystems ή να αλληλεπιδράσει με attack surface που ένα normal application container δεν χρειάζεται καθόλου.

Γι' αυτό τα default runtime seccomp profiles είναι τόσο σημαντικά. Δεν αποτελούν απλώς "extra defense". Σε πολλά environments, είναι η διαφορά ανάμεσα σε ένα container που μπορεί να χρησιμοποιήσει ένα μεγάλο μέρος της λειτουργικότητας του kernel και σε ένα container που περιορίζεται σε syscall surface πιο κοντά σε αυτήν που χρειάζεται πραγματικά η εφαρμογή.

## Modes And Filter Construction

Το seccomp διέθετε ιστορικά ένα strict mode, στο οποίο παρέμενε διαθέσιμο μόνο ένα πολύ μικρό σύνολο syscalls, όμως το mode που αφορά τα σύγχρονα container runtimes είναι το seccomp filter mode, το οποίο συχνά ονομάζεται **seccomp-bpf**. Σε αυτό το model, ο kernel αξιολογεί ένα filter program που αποφασίζει αν ένα syscall θα επιτραπεί, θα απορριφθεί με ένα errno, θα γίνει trapped, θα καταγραφεί ή θα τερματίσει το process. Τα container runtimes χρησιμοποιούν αυτόν τον μηχανισμό επειδή είναι αρκετά εκφραστικός ώστε να αποκλείει ευρείες κατηγορίες επικίνδυνων syscalls, ενώ παράλληλα επιτρέπει τη normal συμπεριφορά της εφαρμογής.

Δύο low-level παραδείγματα είναι χρήσιμα επειδή κάνουν τον μηχανισμό συγκεκριμένο αντί για μαγικό. Το strict mode επιδεικνύει το παλιό model "επιβιώνει μόνο ένα ελάχιστο σύνολο syscalls":
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
Το τελικό `open` προκαλεί τον τερματισμό της διεργασίας, επειδή δεν αποτελεί μέρος του ελάχιστου συνόλου του strict mode.

Ένα παράδειγμα φίλτρου libseccomp παρουσιάζει πιο ξεκάθαρα το σύγχρονο μοντέλο policy:
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
Αυτό το στυλ policy είναι αυτό που οι περισσότεροι αναγνώστες θα πρέπει να φαντάζονται όταν σκέφτονται τα runtime seccomp profiles.

## Εργαστήριο

Ένας απλός τρόπος για να επιβεβαιώσετε ότι το seccomp είναι ενεργό σε ένα container είναι:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Μπορείτε επίσης να δοκιμάσετε μια λειτουργία που τα προεπιλεγμένα προφίλ συνήθως περιορίζουν:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Εάν το container εκτελείται με ένα κανονικό προεπιλεγμένο seccomp profile, οι λειτουργίες τύπου `unshare` συχνά αποκλείονται. Αυτό αποτελεί χρήσιμη επίδειξη, επειδή δείχνει ότι, ακόμη και αν το εργαλείο userspace υπάρχει μέσα στο image, η διαδρομή του kernel που χρειάζεται ενδέχεται να μην είναι διαθέσιμη.

Εάν το container εκτελείται με ένα κανονικό προεπιλεγμένο seccomp profile, οι λειτουργίες τύπου `unshare` συχνά αποκλείονται, ακόμη και όταν το εργαλείο userspace υπάρχει μέσα στο image.

Για να επιθεωρήσετε γενικότερα την κατάσταση της διεργασίας, εκτελέστε:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Χρήση κατά το Runtime

Το Docker υποστηρίζει τόσο προεπιλεγμένα όσο και custom seccomp profiles και επιτρέπει στους administrators να τα απενεργοποιούν με `--security-opt seccomp=unconfined`. Το Podman παρέχει παρόμοια υποστήριξη και συχνά συνδυάζει το seccomp με rootless execution, προσφέροντας μια πολύ λογική προεπιλεγμένη στάση ασφαλείας. Το Kubernetes εκθέτει το seccomp μέσω της ρύθμισης των workloads, όπου το `RuntimeDefault` αποτελεί συνήθως τη σωστή βασική επιλογή, ενώ το `Unconfined` θα πρέπει να αντιμετωπίζεται ως εξαίρεση που απαιτεί αιτιολόγηση και όχι ως επιλογή ευκολίας.

Σε περιβάλλοντα που βασίζονται σε containerd και CRI-O, η ακριβής διαδρομή είναι πιο πολυεπίπεδη, αλλά η αρχή παραμένει η ίδια: ο ανώτερου επιπέδου engine ή orchestrator αποφασίζει τι πρέπει να συμβεί και το runtime τελικά εγκαθιστά την προκύπτουσα seccomp policy για τη διεργασία του container. Το αποτέλεσμα εξακολουθεί να εξαρτάται από την τελική runtime configuration που φτάνει στον kernel.

### Παράδειγμα Custom Policy

Το Docker και παρόμοιοι engines μπορούν να φορτώσουν ένα custom seccomp profile από JSON. Ένα ελάχιστο παράδειγμα που αρνείται το `chmod` ενώ επιτρέπει οτιδήποτε άλλο έχει ως εξής:
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
Εφαρμόζεται με:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Η εντολή αποτυγχάνει με `Operation not permitted`, αποδεικνύοντας ότι ο περιορισμός προέρχεται από την πολιτική syscall και όχι μόνο από τα συνηθισμένα δικαιώματα αρχείων. Στο πραγματικό hardening, οι allowlists είναι γενικά ισχυρότερες από τις permissive προεπιλογές με μια μικρή blacklist.

## Λανθασμένες ρυθμίσεις

Το πιο χονδροειδές λάθος είναι να οριστεί το seccomp ως **unconfined**, επειδή μια εφαρμογή απέτυχε με την προεπιλεγμένη πολιτική. Αυτό είναι συνηθισμένο κατά την αντιμετώπιση προβλημάτων και πολύ επικίνδυνο ως μόνιμη λύση. Μόλις αφαιρεθεί το filter, πολλά syscall-based breakout primitives γίνονται ξανά προσβάσιμα, ιδιαίτερα όταν υπάρχουν επίσης ισχυρές capabilities ή κοινή χρήση host namespaces.

Ένα άλλο συχνό πρόβλημα είναι η χρήση ενός **custom permissive profile** που αντιγράφηκε από κάποιο blog ή εσωτερικό workaround χωρίς προσεκτικό έλεγχο. Οι ομάδες διατηρούν μερικές φορές σχεδόν όλα τα επικίνδυνα syscalls, απλώς επειδή το profile σχεδιάστηκε με βάση το «να μην σταματά να λειτουργεί η εφαρμογή» αντί για το «να παρέχεται μόνο ό,τι χρειάζεται πραγματικά η εφαρμογή». Μια τρίτη παρανόηση είναι η υπόθεση ότι το seccomp είναι λιγότερο σημαντικό για non-root containers. Στην πραγματικότητα, παραμένει σχετικό μεγάλο μέρος του kernel attack surface, ακόμη και όταν η διεργασία δεν έχει UID 0.

## Κατάχρηση

Αν το seccomp απουσιάζει ή έχει αποδυναμωθεί σημαντικά, ένας attacker μπορεί να είναι σε θέση να καλέσει syscalls δημιουργίας namespaces, να διευρύνει το προσβάσιμο kernel attack surface μέσω των `bpf` ή `perf_event_open`, να κάνει abuse του `keyctl` ή να συνδυάσει αυτά τα syscall paths με επικίνδυνες capabilities, όπως το `CAP_SYS_ADMIN`. Σε πολλές πραγματικές επιθέσεις, το seccomp δεν είναι ο μόνος έλεγχος που λείπει, όμως η απουσία του συντομεύει δραματικά το exploit path, επειδή αφαιρεί μία από τις λίγες άμυνες που μπορούν να σταματήσουν ένα επικίνδυνο syscall πριν εμπλακεί το υπόλοιπο privilege model.

Το πιο χρήσιμο πρακτικό test είναι να δοκιμαστούν οι ακριβείς syscall families που συνήθως αποκλείουν τα default profiles. Αν λειτουργούν ξαφνικά, το posture του container έχει αλλάξει σημαντικά:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Εάν υπάρχει το `CAP_SYS_ADMIN` ή κάποια άλλη ισχυρή capability, ελέγξτε εάν το seccomp είναι το μόνο εμπόδιο που απομένει πριν από abuse μέσω mount:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Σε ορισμένους στόχους, η άμεση αξία δεν είναι το πλήρες escape, αλλά η συλλογή πληροφοριών και η διεύρυνση της επιφάνειας επίθεσης του kernel. Αυτές οι εντολές βοηθούν να προσδιοριστεί αν είναι προσβάσιμες ιδιαίτερα ευαίσθητες διαδρομές syscall:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Αν το seccomp απουσιάζει και το container είναι επίσης privileged με άλλους τρόπους, τότε έχει νόημα να μεταβείτε στις πιο συγκεκριμένες τεχνικές breakout που έχουν ήδη τεκμηριωθεί στις legacy σελίδες container-escape.

### Πλήρες Παράδειγμα: Το seccomp Ήταν Το Μόνο Πράγμα Που Εμπόδιζε το `unshare`

Σε πολλούς στόχους, η πρακτική συνέπεια της αφαίρεσης του seccomp είναι ότι οι syscalls δημιουργίας namespaces ή mount ξαφνικά αρχίζουν να λειτουργούν. Αν το container διαθέτει επίσης `CAP_SYS_ADMIN`, η ακόλουθη ακολουθία μπορεί να καταστεί δυνατή:
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
Από μόνο του αυτό δεν αποτελεί ακόμη host escape, αλλά δείχνει ότι το seccomp ήταν το εμπόδιο που απέτρεπε την εκμετάλλευση που σχετίζεται με το mount.

### Πλήρες Παράδειγμα: Το seccomp Απενεργοποιημένο + `release_agent` του cgroup v1

Εάν το seccomp είναι απενεργοποιημένο και το container μπορεί να κάνει mount ιεραρχιών cgroup v1, η τεχνική `release_agent` από την ενότητα cgroups γίνεται προσβάσιμη:
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
Αυτό δεν είναι exploit που βασίζεται αποκλειστικά στο seccomp. Το βασικό σημείο είναι ότι, μόλις το seccomp τεθεί σε unconfined κατάσταση, αλυσίδες breakout με έντονη χρήση syscall που προηγουμένως αποκλείονταν ενδέχεται να αρχίσουν να λειτουργούν ακριβώς όπως είναι γραμμένες.

## Έλεγχοι

Σκοπός αυτών των ελέγχων είναι να διαπιστωθεί αν το seccomp είναι ενεργό, αν συνοδεύεται από `no_new_privs` και αν η ρύθμιση του runtime δείχνει ότι το seccomp έχει απενεργοποιηθεί ρητά.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Τι είναι ενδιαφέρον εδώ:

- Μια μη μηδενική τιμή `Seccomp` σημαίνει ότι το filtering είναι ενεργό· το `0` συνήθως σημαίνει ότι δεν υπάρχει προστασία seccomp.
- Αν οι επιλογές ασφάλειας του runtime περιλαμβάνουν `seccomp=unconfined`, το workload έχει χάσει μία από τις πιο χρήσιμες άμυνές του σε επίπεδο syscall.
- Το `NoNewPrivs` δεν είναι το ίδιο το seccomp, αλλά η παρουσία και των δύο μαζί συνήθως υποδεικνύει πιο προσεκτική hardening στάση σε σχέση με την απουσία και των δύο.

Αν ένα container έχει ήδη ύποπτα mounts, ευρείες capabilities ή shared host namespaces, και το seccomp είναι επίσης unconfined, αυτός ο συνδυασμός θα πρέπει να αντιμετωπίζεται ως σημαντικό escalation signal. Το container μπορεί να μην παραβιάζεται ακόμη trivially, αλλά ο αριθμός των kernel entry points που είναι διαθέσιμα στον attacker έχει αυξηθεί απότομα.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Συνήθως ενεργοποιημένο από προεπιλογή | Χρησιμοποιεί το ενσωματωμένο default seccomp profile του Docker, εκτός αν παρακαμφθεί | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Συνήθως ενεργοποιημένο από προεπιλογή | Εφαρμόζει το default seccomp profile του runtime, εκτός αν παρακαμφθεί | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Δεν είναι εγγυημένο από προεπιλογή** | Αν το `securityContext.seccompProfile` δεν έχει οριστεί, η προεπιλογή είναι `Unconfined`, εκτός αν το kubelet έχει ενεργοποιημένο το `--seccomp-default`· διαφορετικά, πρέπει να οριστεί ρητά `RuntimeDefault` ή `Localhost` | `securityContext.seccompProfile.type: Unconfined`, μη ορισμός του seccomp σε clusters χωρίς `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Ακολουθεί τις ρυθμίσεις του Kubernetes για τον node και το Pod | Το runtime profile χρησιμοποιείται όταν το Kubernetes ζητά `RuntimeDefault` ή όταν είναι ενεργοποιημένο το seccomp defaulting του kubelet | Όπως στη γραμμή του Kubernetes· η άμεση ρύθμιση CRI/OCI μπορεί επίσης να παραλείψει πλήρως το seccomp |

Η συμπεριφορά του Kubernetes είναι αυτή που εκπλήσσει συχνότερα τους operators. Σε πολλά clusters, το seccomp εξακολουθεί να απουσιάζει, εκτός αν το ζητήσει το Pod ή το kubelet έχει ρυθμιστεί ώστε να χρησιμοποιεί από προεπιλογή το `RuntimeDefault`.
{{#include ../../../../banners/hacktricks-training.md}}
