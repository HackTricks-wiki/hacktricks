# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces sind ein Kernel-Feature, durch das sich ein Container wie „seine eigene Maschine“ anfühlt, obwohl er tatsächlich nur ein Prozessbaum des Hosts ist. Sie erstellen keinen neuen Kernel und virtualisieren nicht alles, ermöglichen es dem Kernel jedoch, verschiedenen Prozessgruppen unterschiedliche Ansichten ausgewählter Ressourcen bereitzustellen. Das ist der Kern der Container-Illusion: Die Workload sieht ein Dateisystem, eine Prozesstabelle, einen Netzwerk-Stack, einen Hostnamen, IPC-Ressourcen sowie ein Benutzer-/Gruppenidentitätsmodell, die lokal erscheinen, obwohl das zugrunde liegende System gemeinsam genutzt wird.

Deshalb sind Namespaces das erste Konzept, mit dem die meisten Menschen in Berührung kommen, wenn sie lernen, wie Container funktionieren. Gleichzeitig gehören sie zu den am häufigsten missverstandenen Konzepten, weil Leser oft annehmen, dass „Namespaces vorhanden“ gleichbedeutend mit „sicher isoliert“ ist. Tatsächlich isoliert ein Namespace nur die spezifische Ressourcenklasse, für die er entwickelt wurde. Ein Prozess kann über einen privaten PID-Namespace verfügen und trotzdem gefährlich sein, weil er ein beschreibbares Host-Bind-Mount besitzt. Er kann über einen privaten Network-Namespace verfügen und trotzdem gefährlich sein, weil er `CAP_SYS_ADMIN` behält und ohne seccomp ausgeführt wird. Namespaces bilden die Grundlage, sind aber nur eine Schicht innerhalb der letztendlichen Grenze.

## Namespace-Typen

Linux-Container verwenden häufig mehrere Namespace-Typen gleichzeitig. Der **mount namespace** gibt dem Prozess eine separate Mount-Tabelle und damit eine kontrollierte Ansicht des Dateisystems. Der **PID namespace** verändert die Sichtbarkeit und Nummerierung von Prozessen, sodass die Workload ihren eigenen Prozessbaum sieht. Der **network namespace** isoliert Interfaces, Routen, Sockets und Firewall-Status. Der **IPC namespace** isoliert SysV-IPC und POSIX-Message-Queues. Der **UTS namespace** isoliert den Hostnamen und den NIS-Domainnamen. Der **user namespace** bildet Benutzer- und Gruppen-IDs neu ab, sodass root innerhalb des Containers nicht zwangsläufig root auf dem Host bedeutet. Der **cgroup namespace** virtualisiert die sichtbare cgroup-Hierarchie, und der **time namespace** virtualisiert in neueren Kernels ausgewählte Uhren.

Jeder dieser Namespaces löst ein anderes Problem. Deshalb läuft die praktische Sicherheitsanalyse von Containern häufig darauf hinaus zu prüfen, **welche Namespaces isoliert sind** und **welche absichtlich mit dem Host geteilt werden**.

## Host-Namespace-Sharing

Viele Container-Breakouts beginnen nicht mit einer Kernel-Schwachstelle. Sie beginnen damit, dass ein Operator das Isolationsmodell absichtlich abschwächt. Die Beispiele `--pid=host`, `--network=host` und `--userns=host` sind hier **Docker/Podman-style CLI flags**, die als konkrete Beispiele für das Teilen von Host-Namespaces verwendet werden. Andere Runtimes setzen dieselbe Idee auf andere Weise um. In Kubernetes erscheinen die entsprechenden Einstellungen normalerweise als Pod-Einstellungen wie `hostPID: true`, `hostNetwork: true` oder `hostIPC: true`. In Low-Level-Runtime-Stacks wie containerd oder CRI-O wird dasselbe Verhalten häufig über die generierte OCI-Runtime-Konfiguration erreicht und nicht über ein benutzerseitiges Flag mit demselben Namen. In all diesen Fällen ist das Ergebnis ähnlich: Die Workload erhält nicht länger die standardmäßig isolierte Namespace-Ansicht.

Deshalb sollte die Prüfung von Namespaces niemals bei der Aussage „der Prozess befindet sich in irgendeinem Namespace“ enden. Die wichtige Frage ist, ob der Namespace privat für den Container ist, mit benachbarten Containern geteilt wird oder direkt dem Host beigetreten ist. In Kubernetes erscheint dieselbe Idee bei Flags wie `hostPID`, `hostNetwork` und `hostIPC`. Die Namen ändern sich zwischen den Plattformen, aber das Risikomuster bleibt gleich: Ein geteilter Host-Namespace macht die verbleibenden Privilegien des Containers und den erreichbaren Host-Zustand wesentlich relevanter.

## Prüfung

Die einfachste Übersicht lautet:
```bash
ls -l /proc/self/ns
```
Jeder Eintrag ist ein symbolischer Link mit einem inodeähnlichen Bezeichner. Wenn zwei Prozesse auf denselben Namespace-Bezeichner verweisen, befinden sie sich im selben Namespace dieses Typs. Dadurch ist `/proc` ein sehr nützlicher Ort, um den aktuellen Prozess mit anderen interessanten Prozessen auf dem Rechner zu vergleichen.

Diese kurzen Befehle reichen oft für den Anfang aus:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Von dort aus besteht der nächste Schritt darin, den Container-Prozess mit Prozessen des Hosts oder benachbarten Prozessen zu vergleichen und festzustellen, ob ein Namespace tatsächlich privat ist oder nicht.

### Auflisten von Namespace-Instanzen vom Host aus

Wenn Sie bereits Zugriff auf den Host haben und verstehen möchten, wie viele unterschiedlichen Namespaces eines bestimmten Typs existieren, bietet `/proc` eine schnelle Übersicht:
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
Wenn du herausfinden möchtest, welche Prozesse zu einem bestimmten Namespace-Identifier gehören, wechsle von `readlink` zu `ls -l` und suche mit grep nach der Nummer des Ziel-Namespace:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Diese Befehle sind nützlich, da sie Ihnen ermöglichen festzustellen, ob auf einem Host eine isolierte Workload, mehrere isolierte Workloads oder eine Mischung aus gemeinsam genutzten und privaten Namespace-Instanzen ausgeführt werden.

### Ein Ziel-Namespace betreten

Wenn der Aufrufer über ausreichende Berechtigungen verfügt, ist `nsenter` die standardmäßige Methode, um dem Namespace eines anderen Prozesses beizutreten:
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
Der Zweck, diese Formen gemeinsam aufzulisten, besteht nicht darin, dass jede Bewertung alle davon benötigt, sondern darin, dass namespace-spezifisches post-exploitation oft wesentlich einfacher wird, sobald der Operator die genaue Einstiegssyntax kennt, anstatt sich nur an die Form für alle namespaces zu erinnern.

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

Behalte beim Lesen zwei Ideen im Hinterkopf. Erstens isoliert jeder Namespace nur eine bestimmte Art von Ansicht. Zweitens ist ein privater Namespace nur dann nützlich, wenn das übrige Privilegienmodell diese Isolation weiterhin sinnvoll macht.

## Laufzeitstandards

| Laufzeit / Plattform | Standardmäßige Namespace-Konfiguration | Übliche manuelle Abschwächung |
| --- | --- | --- |
| Docker Engine | Standardmäßig neue mount-, PID-, Netzwerk-, IPC- und UTS-Namespaces; user namespaces sind verfügbar, aber in standardmäßigen rootful-Setups nicht aktiviert | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Standardmäßig neue namespaces; rootless Podman verwendet automatisch einen user namespace; die Standardeinstellungen für den cgroup namespace hängen von der cgroup-Version ab | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods teilen standardmäßig **nicht** die PID-, Netzwerk- oder IPC-Namespaces des Hosts; das Pod-Netzwerk ist für den Pod privat, nicht für jeden einzelnen Container; user namespaces werden auf unterstützten Clustern über `spec.hostUsers: false` optional aktiviert | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / Weglassen der user-namespace-Option, privilegierte Workload-Einstellungen |
| containerd / CRI-O unter Kubernetes | Folgen normalerweise den Kubernetes-Pod-Standards | wie in der Kubernetes-Zeile; direkte CRI/OCI-Spezifikationen können ebenfalls den Beitritt zu Host-Namespaces anfordern |

Die wichtigste Portabilitätsregel ist einfach: Das **Konzept** der gemeinsamen Nutzung von Host-Namespaces ist bei verschiedenen Runtimes verbreitet, aber die **Syntax** ist runtime-spezifisch.

{{#include ../../../../../banners/hacktricks-training.md}}
