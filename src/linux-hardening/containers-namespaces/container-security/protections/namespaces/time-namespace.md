# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der Time Namespace virtualisiert ausgewählte Uhren im Monotonic-Stil anstelle der Wall Clock des Hosts. In der Praxis bedeutet dies private Offsets für **`CLOCK_MONOTONIC`** und **`CLOCK_BOOTTIME`** sowie die eng verwandten Ansichten **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** und **`CLOCK_BOOTTIME_ALARM`**. **`CLOCK_REALTIME`** wird nicht virtualisiert, daher sehen `date` und die Logik für das Ablaufdatum von Zertifikaten weiterhin die Wall Clock des Hosts, sofern kein anderer Mechanismus eingreift.<sup>[[1]](#references)</sup>

Der Hauptzweck besteht darin, dass ein Prozess kontrollierte Offsets für die vergangene Zeit beobachten kann, ohne die globale Zeitanzeige des Hosts zu verändern. Dies ist für Checkpoint/Restore-Workflows, deterministische Tests und fortgeschrittenes Runtime-Verhalten nützlich. Im Gegensatz zu Mount- oder User-Namespaces ist dies normalerweise keine zentrale Isolation Control, trägt aber dennoch dazu bei, die Prozessumgebung stärker in sich geschlossen zu machen.

Aus offensiver Sicht ist dieser Namespace in der Regel eher für **Reconnaissance, Timer-Skew und das Verständnis der Runtime** relevant als für einen direkten Breakout. Dennoch ist er wichtig, da immer mehr Container-Runtimes und Checkpoint/Restore-Workflows ihn explizit anfordern können.

## Lab

Wenn der Host-Kernel und der Userspace dies unterstützen, kannst du den Namespace mit folgendem Befehl untersuchen:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
Die Unterstützung variiert je nach Kernel- und Tool-Version. Daher geht es auf dieser Seite eher darum, den Mechanismus zu verstehen, als zu erwarten, dass er in jeder Lab-Umgebung sichtbar ist. Die wichtige Beobachtung ist, dass `date` weiterhin die Systemuhr des Hosts widerspiegeln sollte, während sich Werte auf Basis von monotonic/boottime ändern, wenn Offsets ungleich null konfiguriert sind.

### Besonderheit bei der Erstellung

Time namespaces sind im Vergleich zu Mount-, PID- oder Network-Namespaces etwas ungewöhnlich:<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)` erstellt einen neuen Time Namespace für **zukünftige Kindprozesse**.
- Der aufrufende Task bleibt in seinem aktuellen Time Namespace.
- `/proc/<pid>/ns/time_for_children` ist daher beim Debugging des Runtime-Setups oft interessanter als `/proc/<pid>/ns/time`.

Auch das Schreibfenster ist speziell. Offsets in `/proc/<pid>/timens_offsets` müssen geschrieben werden, bevor der neue Time Namespace vollständig mit laufenden Tasks befüllt wurde. In der Praxis erledigen Runtimes dies während des kurzen Setup-Fensters zwischen der Erstellung des Namespace und dem Start des finalen Payloads. Sobald dort bereits ein Task läuft, schlagen spätere Schreibvorgänge mit `EACCES` fehl. Deshalb behandeln Low-Level-Runtimes das Setup von Time Namespaces als frühen Bootstrap-Schritt, anstatt zu versuchen, Offsets aus einem bereits gestarteten Container-Prozess heraus zu ändern.<sup>[[1]](#references)</sup>

### Time Offsets

Linux Time Namespaces stellen die Offsets pro Namespace über `/proc/<pid>/timens_offsets` bereit. Das Format besteht aus einer Reihe von Clock-Namen oder IDs sowie Sekunden-/Nanosekunden-Deltas relativ zum initialen Time Namespace.<sup>[[1]](#references)</sup>

In der Praxis besteht der zuverlässigste benutzerseitige Workflow darin, `unshare` diese Offsets für dich schreiben zu lassen:
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Der wichtige Punkt ist nicht die genaue Syntax des Befehls, sondern das Verhalten: Ein Container kann eine andere uptime-ähnliche Ansicht beobachten, ohne die Systemzeit des Hosts zu ändern.

### `unshare`-Hilfsflags

Aktuelle Versionen von `util-linux` bieten Komfortflags, die die Offsets während der Erstellung des Namespace automatisch schreiben:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Diese Flags sind hauptsächlich eine Verbesserung der Benutzerfreundlichkeit, machen es aber auch einfacher, das Feature in Dokumentation, Test-Harnesses und Runtime-Wrappern zu erkennen.

## Runtime Usage

Time-Namespaces werden weniger universell verwendet als Mount- oder PID-Namespaces und sind neuer. Die OCI Runtime Specification v1.1 fügte explizite Unterstützung für den `time`-Namespace und das Feld `linux.timeOffsets` hinzu, und moderne Runtimes können diese Daten in den Kernel-Bootstrap-Ablauf übertragen. Ein minimales OCI-Fragment sieht folgendermaßen aus:
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Das ist wichtig, weil es time namespacing von einem speziellen Kernel-Primitiv zu etwas macht, das runtimes portabel anfordern können. Es erklärt außerdem, warum die Interna von runtimes einen expliziten Synchronisierungsschritt benötigen: Der Offset muss in `/proc/<pid>/timens_offsets` geschrieben werden, bevor der Container-payload vollständig in den neuen Namespace eintritt.

Checkpoint/restore-Stacks wie CRIU sind einer der Hauptgründe aus der Praxis, warum es diese Funktion überhaupt gibt. Ohne time namespaces würden beim Wiederherstellen einer pausierten Workload die monotonic- und boot-time-Uhren um die Zeit springen, während der die Workload suspendiert war.<sup>[[2]](#references)</sup>

## Security-Auswirkungen

Es gibt weniger klassische Breakout-Szenarien, die sich um den time namespace drehen, als bei anderen Namespace-Typen. Das Risiko besteht hier normalerweise nicht darin, dass der time namespace direkt einen Escape ermöglicht, sondern darin, dass Leser ihn vollständig ignorieren und dadurch übersehen, wie fortgeschrittene runtimes das Prozessverhalten beeinflussen können.

In spezialisierten Umgebungen können veränderte Ansichten der monotonic- oder boottime-Uhren Folgendes beeinflussen:

- Timeout- und Retry-Verhalten
- Watchdogs und Lease-Logik
- das Verhalten von `timerfd`, `nanosleep` und `clock_nanosleep`
- Forensik bei Checkpoint/restore
- Telemetrie zur verstrichenen Zeit und auf Uptime basierende Heuristiken

Auch wenn dies selten der erste Namespace ist, den man abuse, kann er während eines Assessments definitiv "unmögliches" Zeitverhalten erklären.

## Missbrauch

Hier gibt es normalerweise kein direktes Breakout-Primitiv, aber ein verändertes Uhrenverhalten kann dennoch nützlich sein, um die Ausführungsumgebung zu verstehen, fortgeschrittene runtime-Funktionen zu identifizieren und timer-basierte Logik zu erkennen, die anhand monotonic clocks statt anhand der wall clock time gemessen wird:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Wenn Sie zwei Prozesse vergleichen, können Unterschiede hier dabei helfen, ungewöhnliches Timing-Verhalten, Checkpoint/Restore-Artefakte oder umgebungsspezifische Abweichungen bei der Protokollierung zu erklären.

Praktische, für Angreifer relevante Ansatzpunkte:

- Backoff-, Sleep- oder Watchdog-Logik verwirren, die mit monotonic clocks implementiert wurde
- erklären, warum `/proc/uptime` und timer-gesteuertes Verhalten nicht mit den Erwartungen an die hostseitige Systemzeit übereinstimmen
- CRIU/Checkpoint-restore-Workflows und andere fortgeschrittene Runtime-Features erkennen
- Umgebungen identifizieren, in denen das Beitreten zu einem target time namespace mit `nsenter -T -t <pid> -- ...` das container-lokale Timer-Verhalten zur Fehlersuche oder für Post-Exploitation reproduzieren kann

Auswirkungen:

- fast immer Reconnaissance oder das Verständnis der Umgebung
- nützlich zum Erklären von Anomalien bei Protokollierung, Uptime oder Checkpoint/Restore
- nützlich zur Analyse von Sleeps, Retries und Timern, die auf monotonic time basieren
- normalerweise kein direkter Container-Escape-Mechanismus an sich

Der wichtige Abuse-Aspekt ist, dass time namespaces `CLOCK_REALTIME` nicht virtualisieren. Sie ermöglichen es einem Angreifer daher nicht allein, die Systemzeit des Hosts zu fälschen oder Zertifikatsablaufprüfungen systemweit direkt zu umgehen. Ihr Wert liegt hauptsächlich darin, Logik zu verwirren, die auf monotonic time basiert, umgebungsspezifische Fehler zu reproduzieren oder fortgeschrittenes Runtime-Verhalten zu verstehen.

## Prüfungen

Bei diesen Prüfungen geht es hauptsächlich darum festzustellen, ob die Runtime überhaupt einen privaten time namespace verwendet und ob sie tatsächlich von null verschiedene Offsets gesetzt hat.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
Was ist hier interessant:

- In vielen Umgebungen führen diese Werte nicht unmittelbar zu einem Security Finding, aber sie zeigen, ob ein spezialisiertes Runtime-Feature aktiv ist.
- Wenn sich `time_for_children` von `time` unterscheidet, könnte der Aufrufer einen nur für Child-Prozesse vorgesehenen time namespace vorbereitet haben, den er selbst noch nicht betreten hat.
- Wenn `date` mit dem Host übereinstimmt, monotonic-/boottime-basierte Werte jedoch nicht, handelt es sich wahrscheinlich um time namespacing und nicht um eine Manipulation der Systemzeit.
- Beim Vergleich zweier Prozesse können Unterschiede hier verwirrendes Timing- oder Checkpoint/Restore-Verhalten erklären.

Bei den meisten Container Breakouts ist der time namespace nicht die erste Kontrolle, die du untersuchen wirst. Dennoch sollte ein vollständiger Abschnitt zur Container-Sicherheit ihn erwähnen, da er Teil des modernen Kernel-Modells ist und in fortgeschrittenen Runtime-Szenarien gelegentlich relevant wird.

## Referenzen

- [1] [Linux-Handbuchseite `time_namespaces(7)`](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Clock Offsets pro Container für CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
