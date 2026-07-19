# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces sind ein Kernel-Feature, durch das sich ein Container wie "seine eigene Maschine" anfühlt, obwohl er tatsächlich nur ein Prozessbaum des Hosts ist. Sie erstellen keinen neuen Kernel und virtualisieren nicht alles, ermöglichen dem Kernel aber, verschiedenen Prozessgruppen unterschiedliche Ansichten ausgewählter Ressourcen bereitzustellen. Das ist der Kern der Container-Illusion: Die Workload sieht ein Dateisystem, eine Prozesstabelle, einen Netzwerk-Stack, einen Hostnamen, IPC-Ressourcen sowie ein Modell für Benutzer- und Gruppenidentitäten, die lokal erscheinen, obwohl das zugrunde liegende System gemeinsam genutzt wird.

Deshalb sind Namespaces das erste Konzept, mit dem die meisten Menschen in Berührung kommen, wenn sie lernen, wie Container funktionieren. Gleichzeitig gehören sie zu den am häufigsten missverstandenen Konzepten, weil Leser oft annehmen, dass "Namespaces vorhanden" bedeutet, dass "eine sichere Isolation besteht". Tatsächlich isoliert ein Namespace nur die spezifische Ressourcenklasse, für die er entwickelt wurde. Ein Prozess kann einen privaten PID-Namespace haben und trotzdem gefährlich sein, weil er über einen beschreibbaren Host-Bind-Mount verfügt. Er kann einen privaten Network-Namespace haben und trotzdem gefährlich sein, weil er `CAP_SYS_ADMIN` behält und ohne seccomp ausgeführt wird. Namespaces sind grundlegend, aber sie bilden nur eine Schicht der endgültigen Boundary.

## Namespace-Typen

Linux-Container verwenden häufig mehrere Namespace-Typen gleichzeitig. Der **Mount-Namespace** stellt dem Prozess eine separate Mount-Tabelle und damit eine kontrollierte Dateisystemansicht bereit. Der **PID-Namespace** verändert die Sichtbarkeit und Nummerierung von Prozessen, sodass die Workload ihren eigenen Prozessbaum sieht. Der **Network-Namespace** isoliert Interfaces, Routen, Sockets und den Firewall-Status. Der **IPC-Namespace** isoliert SysV-IPC und POSIX-Message-Queues. Der **UTS-Namespace** isoliert Hostnamen und NIS-Domainnamen. Der **User-Namespace** ordnet Benutzer- und Gruppen-IDs neu zu, sodass root innerhalb des Containers nicht zwangsläufig root auf dem Host bedeutet. Der **cgroup-Namespace** virtualisiert die sichtbare cgroup-Hierarchie, und der **Time-Namespace** virtualisiert in neueren Kerneln ausgewählte Uhren.

Jeder dieser Namespaces löst ein anderes Problem. Deshalb läuft die praktische Analyse der Container-Sicherheit häufig darauf hinaus zu prüfen, **welche Namespaces isoliert sind** und **welche absichtlich mit dem Host geteilt werden**.

## Gemeinsame Nutzung von Host-Namespaces

Viele Container-Breakouts beginnen nicht mit einer Kernel-Schwachstelle. Sie beginnen damit, dass ein Operator das Isolationsmodell absichtlich abschwächt. Die Beispiele `--pid=host`, `--network=host` und `--userns=host` sind **Docker/Podman-style CLI-Flags**, die hier als konkrete Beispiele für die gemeinsame Nutzung von Host-Namespaces verwendet werden. Andere Runtimes drücken dieselbe Idee anders aus. In Kubernetes erscheinen die Entsprechungen normalerweise als Pod-Einstellungen wie `hostPID: true`, `hostNetwork: true` oder `hostIPC: true`. In Low-Level-Runtime-Stacks wie containerd oder CRI-O wird dasselbe Verhalten häufig über die generierte OCI-Runtime-Konfiguration erreicht und nicht über ein benutzerseitiges Flag mit demselben Namen. In all diesen Fällen ist das Ergebnis ähnlich: Die Workload erhält nicht mehr die standardmäßige isolierte Namespace-Ansicht.

Deshalb sollten Namespace-Reviews niemals bei der Feststellung enden, dass sich "der Prozess in irgendeinem Namespace befindet". Die wichtige Frage ist, ob der Namespace privat für den Container ist, mit benachbarten Containern geteilt wird oder direkt dem Host beigetreten ist. In Kubernetes erscheint dieselbe Idee mit Flags wie `hostPID`, `hostNetwork` und `hostIPC`. Die Namen ändern sich zwischen den Plattformen, aber das Risikomuster bleibt gleich: Ein gemeinsam genutzter Host-Namespace macht die verbleibenden Privilegien und den erreichbaren Host-Zustand des Containers deutlich relevanter.

## Inspektion

Die einfachste Übersicht lautet:
```bash
ls -l /proc/self/ns
```
Jeder Eintrag ist ein symbolischer Link mit einem inode-ähnlichen Bezeichner. Wenn zwei Prozesse auf denselben Namespace-Bezeichner verweisen, befinden sie sich im selben Namespace dieses Typs. Dadurch ist `/proc` ein sehr nützlicher Ort, um den aktuellen Prozess mit anderen interessanten Prozessen auf dem Rechner zu vergleichen.

Diese kurzen Befehle reichen oft als Ausgangspunkt aus:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Von dort aus besteht der nächste Schritt darin, den Containerprozess mit Prozessen auf dem Host oder in benachbarten Containern zu vergleichen und festzustellen, ob ein Namespace tatsächlich privat ist oder nicht.

### Auflisten von Namespace-Instanzen vom Host aus

Wenn Sie bereits Zugriff auf den Host haben und verstehen möchten, wie viele unterschiedliche Namespaces eines bestimmten Typs existieren, bietet `/proc` eine schnelle Übersicht:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
Wenn du herausfinden möchtest, welche Prozesse zu einer bestimmten Namespace-ID gehören, wechsle von `readlink` zu `ls -l` und suche mit grep nach der Ziel-Namespace-Nummer:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Diese Befehle sind nützlich, weil sie dir ermöglichen festzustellen, ob ein Host eine isolierte Workload, mehrere isolierte Workloads oder eine Mischung aus gemeinsam genutzten und privaten Namespace-Instanzen ausführt.

### Einen Ziel-Namespace betreten

Wenn der Aufrufer über ausreichende Berechtigungen verfügt, ist `nsenter` die Standardmethode, um dem Namespace eines anderen Prozesses beizutreten:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
Der Punkt, diese Formen gemeinsam aufzulisten, besteht nicht darin, dass jede Bewertung alle davon benötigt, sondern darin, dass Namespace-spezifisches post-exploitation oft deutlich einfacher wird, sobald der Operator die genaue Einstiegssyntax kennt, anstatt sich nur an die Form für alle Namespaces zu erinnern.

## Seiten

Die folgenden Seiten erklären jeden Namespace ausführlicher:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

Behalte beim Lesen zwei Gedanken im Hinterkopf. Erstens isoliert jeder Namespace nur eine bestimmte Art von Ansicht. Zweitens ist ein privater Namespace nur dann nützlich, wenn das restliche Privilegienmodell diese Isolation weiterhin sinnvoll macht.

## Laufzeitstandards

| Laufzeit / Plattform | Standardmäßige Namespace-Konfiguration | Häufige manuelle Abschwächung |
| --- | --- | --- |
| Docker Engine | Neue mount-, PID-, Netzwerk-, IPC- und UTS-Namespaces standardmäßig; User-Namespaces sind verfügbar, aber in standardmäßigen rootful Setups nicht standardmäßig aktiviert | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Standardmäßig neue Namespaces; rootless Podman verwendet automatisch einen User-Namespace; der Standard des cgroup-Namespaces hängt von der cgroup-Version ab | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods teilen standardmäßig **nicht** die Host-PID-, Host-Netzwerk- oder Host-IPC-Namespaces; das Pod-Netzwerk ist für den Pod privat, nicht für jeden einzelnen Container; User-Namespaces werden über `spec.hostUsers: false` auf unterstützten Clustern opt-in aktiviert | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / Weglassen des User-Namespace-Opt-ins, Einstellungen für privilegierte Workloads |
| containerd / CRI-O unter Kubernetes | Folgen normalerweise den Kubernetes-Pod-Standards | wie in der Kubernetes-Zeile; direkte CRI/OCI-Spezifikationen können ebenfalls Host-Namespace-Beitritte anfordern |

Die wichtigste Portabilitätsregel ist einfach: Das **Konzept** der gemeinsamen Nutzung von Host-Namespaces ist bei den Laufzeiten verbreitet, aber die **Syntax** ist laufzeitspezifisch.
{{#include ../../../../../banners/hacktricks-training.md}}
