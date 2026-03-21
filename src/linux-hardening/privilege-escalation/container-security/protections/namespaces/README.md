# Namensräume

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces sind eine Kernel-Funktion, die dafür sorgt, dass sich ein Container wie "seine eigene Maschine" anfühlt, obwohl er eigentlich nur ein Prozessbaum des Hosts ist. Sie erzeugen keinen neuen Kernel und virtualisieren nicht alles, aber sie erlauben dem Kernel, verschiedenen Gruppen von Prozessen unterschiedliche Sichten auf ausgewählte Ressourcen zu präsentieren. Das ist der Kern der Container-Illusion: Die Workload sieht ein Dateisystem, eine Prozessliste, einen Netzwerkstack, Hostname, IPC-Ressourcen und ein Benutzer-/Gruppen-Identitätsmodell, die lokal erscheinen, obwohl das zugrunde liegende System geteilt wird.

Deshalb sind Namespaces das erste Konzept, dem die meisten begegnen, wenn sie lernen, wie Container funktionieren. Gleichzeitig sind sie eines der meistmissverstandenen Konzepte, weil Leser oft annehmen, dass "has namespaces" gleichbedeutend mit "ist sicher isoliert" sei. In Wirklichkeit isoliert ein Namespace nur die konkrete Klasse von Ressourcen, für die er entworfen wurde. Ein Prozess kann ein privates PID namespace haben und trotzdem gefährlich sein, weil er einen schreibbaren Host bind mount besitzt. Er kann ein privates network namespace haben und trotzdem gefährlich sein, weil er `CAP_SYS_ADMIN` behält und ohne seccomp läuft. Namespaces sind grundlegend, aber sie sind nur eine Schicht in der finalen Grenze.

## Namespace-Typen

Linux-Container verlassen sich meist gleichzeitig auf mehrere Namespace-Typen. Der **mount namespace** gibt dem Prozess eine separate Mount-Tabelle und damit eine kontrollierte Sicht auf das Dateisystem. Der **PID namespace** verändert die Prozesssichtbarkeit und -nummerierung, sodass die Workload ihren eigenen Prozessbaum sieht. Der **network namespace** isoliert Interfaces, Routen, Sockets und Firewall-Zustand. Der **IPC namespace** isoliert SysV IPC und POSIX message queues. Der **UTS namespace** isoliert Hostname und NIS-Domainnamen. Der **user namespace** remapt Benutzer- und Gruppen-IDs, sodass root innerhalb des Containers nicht zwangsläufig root auf dem Host bedeutet. Der **cgroup namespace** virtualisiert die sichtbare cgroup-Hierarchie, und der **time namespace** virtualisiert ausgewählte Uhren in neueren Kerneln.

Jeder dieser Namespaces löst ein anderes Problem. Deshalb läuft praktische Container-Security-Analyse oft darauf hinaus zu prüfen, **welche Namespaces isoliert sind** und **welche absichtlich mit dem Host geteilt wurden**.

## Teilen von Host-Namespaces

Viele Container-Breakouts beginnen nicht mit einer Kernel-Schwachstelle. Sie beginnen damit, dass ein Operator das Isolationsmodell absichtlich schwächt. Die Beispiele `--pid=host`, `--network=host` und `--userns=host` sind **Docker/Podman-style CLI flags**, die hier als konkrete Beispiele für das Teilen von Host-Namespaces verwendet werden. Andere runtimes drücken dieselbe Idee anders aus. In Kubernetes erscheinen die äquivalenten Einstellungen normalerweise als Pod-Settings wie `hostPID: true`, `hostNetwork: true` oder `hostIPC: true`. In tieferliegenden Runtime-Stacks wie containerd oder CRI-O wird dasselbe Verhalten oft über die erzeugte OCI runtime configuration erreicht, statt über ein benutzerseitiges Flag mit identischem Namen. In all diesen Fällen ist das Ergebnis ähnlich: Die Workload erhält nicht mehr die standardmäßig isolierte Namespace-Sicht.

Deshalb sollten Namespace-Reviews niemals bei "der Prozess ist in irgendeinem Namespace" stoppen. Die wichtige Frage ist, ob der Namespace privat für den Container ist, mit sibling-Containern geteilt wird oder direkt mit dem Host verbunden ist. In Kubernetes tritt dieselbe Idee mit Flags wie `hostPID`, `hostNetwork` und `hostIPC` auf. Die Namen ändern sich zwischen den Plattformen, aber das Risikomuster bleibt gleich: Ein geteilter Host-Namespace macht die verbleibenden Privilegien des Containers und den erreichbaren Host-Zustand wesentlich relevanter.

## Inspektion

Die einfachste Übersicht ist:
```bash
ls -l /proc/self/ns
```
Jeder Eintrag ist ein symbolischer Link mit einer inode-ähnlichen Kennung. Wenn zwei Prozesse auf dieselbe Namespace-Kennung zeigen, befinden sie sich im selben Namespace dieses Typs. Das macht `/proc` zu einem sehr nützlichen Ort, um den aktuellen Prozess mit anderen interessanten Prozessen auf dem System zu vergleichen.

Diese kurzen Befehle reichen oft aus, um zu beginnen:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Von dort aus ist der nächste Schritt, den Container-Prozess mit Host- oder benachbarten Prozessen zu vergleichen und festzustellen, ob ein namespace tatsächlich privat ist oder nicht.

### Auflisten von Namespace-Instanzen vom Host

Wenn Sie bereits Zugriff auf den Host haben und verstehen wollen, wie viele unterschiedliche namespaces eines bestimmten Typs existieren, liefert `/proc` eine schnelle Übersicht:
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
Wenn du herausfinden willst, welche Prozesse zu einer bestimmten namespace-ID gehören, wechsle von `readlink` zu `ls -l` und `grep` nach der Ziel-namespace-Nummer:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Diese Befehle sind nützlich, weil sie es Ihnen erlauben festzustellen, ob ein Host eine einzelne isolierte workload, viele isolierte workloads oder eine Mischung aus gemeinsam genutzten und privaten Namespace-Instanzen ausführt.

### Betreten eines Ziel-Namespaces

Wenn der Aufrufer über ausreichende Rechte verfügt, ist `nsenter` die Standardmethode, um dem Namespace eines anderen Prozesses beizutreten:
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
Der Zweck, diese Formen zusammen aufzulisten, ist nicht, dass jede Bewertung alle davon benötigt, sondern dass namespace-spezifische post-exploitation oft viel einfacher wird, sobald der Operator die genaue Entry-Syntax kennt, statt sich nur die all-namespaces form zu merken.

## Seiten

Die folgenden Seiten erklären jedes Namespace genauer:

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

Wenn du sie liest, behalte zwei Gedanken im Kopf. Erstens isoliert jedes Namespace nur eine Art von Sicht. Zweitens ist ein privates Namespace nur nützlich, wenn das restliche Privilegienmodell diese Isolation weiterhin sinnvoll macht.

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

Die wichtigste Regel zur Portabilität ist einfach: das **Konzept** des host namespace sharing ist bei Runtimes allgemein, aber die **Syntax** ist runtime-spezifisch.
