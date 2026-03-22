# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces sind die Kernel-Funktion, die einen Container wie "seine eigene Maschine" erscheinen lässt, obwohl er in Wirklichkeit nur ein Prozessbaum des Hosts ist. Sie erzeugen keinen neuen Kernel und virtualisieren nicht alles, aber sie erlauben dem Kernel, verschiedenen Prozessgruppen unterschiedliche Ansichten ausgewählter Ressourcen zu präsentieren. Das ist der Kern der Container-Illusion: die Workload sieht ein Dateisystem, eine Prozessliste, einen Netzwerkstack, Hostname, IPC-Ressourcen und ein Benutzer-/Gruppen-Identitätsmodell, die lokal erscheinen, obwohl das zugrundeliegende System geteilt wird.

Deshalb sind namespaces das erste Konzept, dem die meisten begegnen, wenn sie lernen, wie Container funktionieren. Gleichzeitig gehören sie zu den am häufigsten missverstandenen Konzepten, weil Leser oft annehmen, dass "hat namespaces" gleichbedeutend mit "ist sicher isoliert" ist. In Wirklichkeit isoliert ein namespace nur die Ressourcenkategorie, für die er entworfen wurde. Ein Prozess kann ein privates PID-namespace haben und trotzdem gefährlich sein, weil er ein beschreibbares Host-Bind-Mount besitzt. Er kann ein privates network-namespace haben und trotzdem gefährlich sein, weil er `CAP_SYS_ADMIN` behält und ohne seccomp läuft. Namespaces sind grundlegend, aber sie sind nur eine Schicht in der finalen Grenze.

## Namespace Types

Linux-Container verlassen sich üblicherweise gleichzeitig auf mehrere Namespace-Typen. Das **mount namespace** gibt dem Prozess eine separate Mount-Tabelle und damit eine kontrollierte Dateisystemsicht. Das **PID namespace** ändert Sichtbarkeit und Nummerierung von Prozessen, sodass die Workload ihren eigenen Prozessbaum sieht. Das **network namespace** isoliert Interfaces, Routen, Sockets und Firewall-Zustand. Das **IPC namespace** isoliert SysV IPC und POSIX-Message-Queues. Das **UTS namespace** isoliert Hostname und NIS-Domainname. Das **user namespace** remappt Benutzer- und Gruppen-IDs, sodass root innerhalb des Containers nicht unbedingt root auf dem Host bedeutet. Das **cgroup namespace** virtualisiert die sichtbare cgroup-Hierarchie, und das **time namespace** virtualisiert in neueren Kerneln ausgewählte Uhren.

Jeder dieser namespaces löst ein anderes Problem. Deshalb läuft eine praktische Container-Security-Analyse oft darauf hinaus zu prüfen, **welche namespaces isoliert** sind und **welche absichtlich mit dem Host geteilt wurden**.

## Host Namespace Sharing

Viele Container-Breakouts beginnen nicht mit einer Kernel-Schwachstelle. Sie beginnen damit, dass ein Operator das Isolationsmodell bewusst abschwächt. Die Beispiele `--pid=host`, `--network=host` und `--userns=host` sind **Docker/Podman-style CLI flags**, die hier als konkrete Beispiele für Host-Namespace-Sharing verwendet werden. Andere Runtimes drücken dieselbe Idee anders aus. In Kubernetes erscheinen die Äquivalente normalerweise als Pod-Settings wie `hostPID: true`, `hostNetwork: true` oder `hostIPC: true`. In niedrigeren Runtime-Stacks wie containerd oder CRI-O wird dasselbe Verhalten oft über die generierte OCI runtime-Konfiguration erreicht, statt über ein benutzerseitiges Flag mit demselben Namen. In all diesen Fällen ist das Ergebnis ähnlich: die Workload erhält nicht mehr die standardmäßige isolierte Namespace-Sicht.

Deshalb sollten Namespace-Reviews niemals bei "der Prozess ist in irgendeinem namespace" aufhören. Die wichtige Frage ist, ob das namespace privat für den Container ist, mit Schwester-Containern geteilt wird oder direkt mit dem Host verbunden ist. In Kubernetes erscheint dieselbe Idee mit Flags wie `hostPID`, `hostNetwork` und `hostIPC`. Die Namen ändern sich zwischen Plattformen, aber das Risikomuster ist dasselbe: ein geteiltes Host-namespace macht die verbleibenden Rechte des Containers und den erreichbaren Host-Zustand wesentlich relevanter.

## Inspection

Die einfachste Übersicht ist:
```bash
ls -l /proc/self/ns
```
Jeder Eintrag ist ein symbolischer Link mit einer inode-ähnlichen Kennung. Wenn zwei Prozesse auf denselben Namespace-Bezeichner zeigen, befinden sie sich im selben Namespace dieses Typs. Das macht `/proc` zu einem sehr nützlichen Ort, um den aktuellen Prozess mit anderen interessanten Prozessen auf dem System zu vergleichen.

Diese schnellen Befehle reichen oft aus, um loszulegen:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Von dort aus besteht der nächste Schritt darin, den container process mit Prozessen auf dem host oder benachbarten Prozessen zu vergleichen und festzustellen, ob ein namespace tatsächlich privat ist oder nicht.

### Auflisten von namespace-Instanzen vom host

Wenn Sie bereits host access haben und wissen möchten, wie viele unterschiedliche namespaces eines bestimmten Typs existieren, liefert `/proc` eine schnelle Übersicht:
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
Wenn Sie herausfinden möchten, welche Prozesse zu einer bestimmten Namespace-ID gehören, verwenden Sie statt `readlink` `ls -l` und `grep`, um nach der Ziel-Namespace-Nummer zu suchen:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Diese Befehle sind nützlich, weil sie es ermöglichen, festzustellen, ob ein Host eine einzelne isolierte Workload, viele isolierte Workloads oder eine Mischung aus gemeinsam genutzten und privaten Namespace-Instanzen ausführt.

### Ein Ziel-Namespace betreten

Wenn der Aufrufer über ausreichende Berechtigungen verfügt, ist `nsenter` die Standardmethode, um in den Namespace eines anderen Prozesses einzutreten:
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
Der Grund, diese Formen zusammen aufzulisten, ist nicht, dass jede Bewertung alle davon benötigt, sondern dass namespace-spezifisches post-exploitation oft viel einfacher wird, sobald der Operator die exakte Entry-Syntax kennt, anstatt sich nur an die All-Namespaces-Form zu erinnern.

## Pages

Die folgenden Seiten erklären die einzelnen Namespaces detaillierter:

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

Wenn Sie sie lesen, behalten Sie zwei Gedanken im Kopf. Erstens isoliert jedes Namespace nur eine Art von Ansicht. Zweitens ist ein privates Namespace nur dann nützlich, wenn das restliche Berechtigungsmodell diese Isolation weiterhin sinnvoll macht.

## Laufzeit-Standardwerte

| Runtime / Plattform | Standard-Verhalten der Namespaces | Häufige manuelle Abschwächungen |
| --- | --- | --- |
| Docker Engine | Standardmäßig werden neue mount-, PID-, network-, IPC- und UTS-Namespaces erstellt; user namespaces sind verfügbar, aber in üblichen rootful-Setups standardmäßig nicht aktiviert | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Standardmäßig neue Namespaces; rootless Podman verwendet automatisch eine user namespace; die Standardwerte für cgroup-Namespaces hängen von der cgroup-Version ab | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods teilen standardmäßig nicht den Host-PID, das Netzwerk oder IPC; Pod-Netzwerk ist privat für den Pod, nicht für jeden einzelnen Container; user namespaces sind opt-in via `spec.hostUsers: false` auf unterstützten Clustern | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privilegierte Workload-Einstellungen |
| containerd / CRI-O under Kubernetes | Folgen üblicherweise den Kubernetes-Pod-Standardeinstellungen | wie in der Kubernetes-Zeile; direkte CRI/OCI-Spezifikationen können ebenfalls Host-Namespace-Beitritte anfordern |

Die wichtigste Portabilitätsregel ist einfach: Das **Konzept** der gemeinsamen Nutzung von Host-Namespaces ist bei verschiedenen Runtimes verbreitet, aber die **Syntax** ist runtime-spezifisch.
{{#include ../../../../../banners/hacktricks-training.md}}
