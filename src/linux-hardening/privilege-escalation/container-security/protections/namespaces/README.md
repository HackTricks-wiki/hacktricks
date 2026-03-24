# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces sind eine Kernel-Funktion, die einen Container wie "seine eigene Maschine" erscheinen lässt, obwohl er in Wirklichkeit nur ein Prozessbaum des Hosts ist. Sie erzeugen keinen neuen Kernel und virtualisieren nicht alles, aber sie erlauben dem Kernel, verschiedenen Prozessgruppen unterschiedliche Sichten auf ausgewählte Ressourcen zu präsentieren. Das ist der Kern der Container-Illusion: die Workload sieht ein Dateisystem, eine Prozessliste, einen Netzwerkstack, einen Hostnamen, IPC-Ressourcen und ein Benutzer-/Gruppen-Identitätsmodell, die lokal erscheinen, obwohl das zugrundeliegende System geteilt wird.

Deshalb sind Namespaces das erste Konzept, dem die meisten begegnen, wenn sie lernen, wie Container funktionieren. Gleichzeitig gehören sie zu den am häufigsten missverstandenen Konzepten, weil Leser oft annehmen, "hat Namespaces" bedeute "ist sicher isoliert". In Wirklichkeit isoliert ein Namespace nur die spezifische Klasse von Ressourcen, für die er entwickelt wurde. Ein Prozess kann einen privaten PID-Namespace haben und trotzdem gefährlich sein, weil er einen beschreibbaren Host-bind-Mount hat. Er kann einen privaten network namespace haben und trotzdem gefährlich sein, weil er `CAP_SYS_ADMIN` behält und ohne seccomp läuft. Namespaces sind grundlegend, aber sie sind nur eine Schicht an der finalen Grenze.

## Namespace Types

Linux-Container verlassen sich üblicherweise gleichzeitig auf mehrere Namespace-Typen. Der **mount namespace** gibt dem Prozess eine separate Mount-Tabelle und damit eine kontrollierte Sicht auf das Dateisystem. Der **PID namespace** verändert die Prozesssichtbarkeit und -nummerierung, sodass die Workload ihren eigenen Prozessbaum sieht. Der **network namespace** isoliert Interfaces, Routen, Sockets und Firewall-Zustand. Der **IPC namespace** isoliert SysV IPC und POSIX-Message-Queues. Der **UTS namespace** isoliert Hostname und NIS-Domänenname. Der **user namespace** mappt Benutzer- und Gruppen-IDs um, sodass root innerhalb des Containers nicht unbedingt root auf dem Host bedeutet. Der **cgroup namespace** virtualisiert die sichtbare cgroup-Hierarchie, und der **time namespace** virtualisiert ausgewählte Uhren in neueren Kerneln.

Jeder dieser Namespaces löst ein anderes Problem. Deshalb läuft praktische Container-Sicherheitsanalyse oft darauf hinaus, zu prüfen, **welche Namespaces isoliert sind** und **welche bewusst mit dem Host geteilt wurden**.

## Host Namespace Sharing

Viele Container-Breakouts beginnen nicht mit einer Kernel-Schwachstelle. Sie beginnen damit, dass ein Operator das Isolationsmodell absichtlich schwächt. Die Beispiele `--pid=host`, `--network=host` und `--userns=host` sind **Docker/Podman-ähnliche CLI-Flags**, die hier als konkrete Beispiele für das Teilen von Host-Namespaces verwendet werden. Andere runtimes drücken dieselbe Idee anders aus. In Kubernetes erscheinen die Äquivalente normalerweise als Pod-Einstellungen wie `hostPID: true`, `hostNetwork: true` oder `hostIPC: true`. In niedriger gelegenen Runtime-Stacks wie containerd oder CRI-O wird dasselbe Verhalten oft über die generierte OCI-Runtime-Konfiguration erreicht statt über ein benutzerseitiges Flag mit demselben Namen. In all diesen Fällen ist das Ergebnis ähnlich: die Workload erhält nicht mehr die standardmäßig isolierte Namespace-Sicht.

Deshalb sollten Namespace-Reviews niemals bei "der Prozess ist in irgendeinem Namespace" aufhören. Die wichtige Frage ist, ob der Namespace privat für den Container ist, mit Geschwister-Containern geteilt wird oder direkt mit dem Host verbunden ist. In Kubernetes tritt dieselbe Idee mit Flags wie `hostPID`, `hostNetwork` und `hostIPC` auf. Die Namen ändern sich zwischen Plattformen, aber das Risikomuster ist dasselbe: ein geteilter Host-Namespace macht die verbleibenden Privilegien des Containers und den erreichbaren Host-Zustand deutlich aussagekräftiger.

## Inspection

Die einfachste Übersicht ist:
```bash
ls -l /proc/self/ns
```
Jeder Eintrag ist ein symbolischer Link mit einer inode-ähnlichen Kennung. Wenn zwei Prozesse auf denselben Namespace-Kennzeichner zeigen, befinden sie sich im selben Namespace dieses Typs. Das macht `/proc` zu einem sehr nützlichen Ort, um den aktuellen Prozess mit anderen interessanten Prozessen auf der Maschine zu vergleichen.

Diese kurzen Befehle sind oft genug, um zu beginnen:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Von dort aus besteht der nächste Schritt darin, den container process mit host- oder benachbarten Prozessen zu vergleichen und festzustellen, ob ein namespace tatsächlich privat ist oder nicht.

### Auflisten von Namespace-Instanzen vom Host

Wenn du bereits host access hast und wissen möchtest, wie viele verschiedene Namespace-Instanzen eines bestimmten Typs existieren, liefert `/proc` eine schnelle Übersicht:
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
Wenn Sie herausfinden möchten, welche Prozesse zu einer bestimmten Namespace-Kennung gehören, wechseln Sie von `readlink` zu `ls -l` und grep nach der Ziel-Namespace-Nummer:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Diese Befehle sind nützlich, weil sie es erlauben zu beantworten, ob ein Host einen isolierten workload, viele isolierte workloads oder eine Mischung aus gemeinsam genutzten und privaten Namespace-Instanzen ausführt.

### Einen Ziel-Namespace betreten

Wenn der Aufrufer über ausreichende Berechtigungen verfügt, ist `nsenter` der Standardweg, um dem Namespace eines anderen Prozesses beizutreten:
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
Der Zweck, diese Formen zusammen aufzulisten, ist nicht, dass jede Bewertung alle davon benötigt, sondern dass namespace-spezifische post-exploitation oft deutlich einfacher wird, sobald der Operator die genaue Eintrittssyntax kennt, anstatt sich nur die all-namespaces-Form zu merken.

## Seiten

Die folgenden Seiten erklären die einzelnen Namespaces genauer:

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

Behalte beim Lesen zwei Dinge im Hinterkopf. Erstens isoliert jedes Namespace nur eine Art von Ansicht. Zweitens ist ein privater Namespace nur nützlich, wenn das restliche Berechtigungsmodell diese Isolation weiterhin sinnvoll macht.

## Standardeinstellungen der Laufzeit

| Runtime / platform | Standard-Namespace-Konfiguration | Gängige manuelle Schwächung |
| --- | --- | --- |
| Docker Engine | Standardmäßig neue mount-, PID-, network-, IPC- und UTS-Namespaces; user namespaces sind verfügbar, werden aber in typischen rootful-Setups nicht standardmäßig aktiviert | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Standardmäßig neue Namespaces; rootless Podman verwendet automatisch eine user namespace; die Default-Werte für das cgroup-namespace hängen von der cgroup-Version ab | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods teilen standardmäßig **nicht** den Host-PID-, Network- oder IPC-Namespace; das Pod-Netzwerk ist privat für das Pod, nicht für jeden einzelnen Container; user namespaces sind auf unterstützten Clustern per `spec.hostUsers: false` opt-in | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Folgen üblicherweise den Kubernetes Pod-Standardeinstellungen | wie in der Kubernetes-Zeile; direkte CRI/OCI-Spezifikationen können ebenfalls Host-Namespace-Beitritte anfordern |

Die wichtigste Portabilitätsregel ist einfach: das **Konzept** des Teilens von Host-Namespaces ist runtimes-übergreifend verbreitet, aber die **Syntax** ist runtime-spezifisch.
{{#include ../../../../../banners/hacktricks-training.md}}
