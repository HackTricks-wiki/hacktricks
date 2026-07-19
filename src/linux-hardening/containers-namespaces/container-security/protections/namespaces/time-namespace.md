# Zeit-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der time namespace virtualisiert ausgewählte Uhren im monotonic-Stil anstelle der Wanduhr des Hosts. In der Praxis bedeutet dies private Offsets für **`CLOCK_MONOTONIC`** und **`CLOCK_BOOTTIME`** sowie für die eng verwandten Ansichten **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** und **`CLOCK_BOOTTIME_ALARM`**. **`CLOCK_REALTIME`** wird nicht virtualisiert. Daher beobachten `date` und die Logik für den Ablauf von Zertifikaten weiterhin die Wanduhr des Hosts, sofern kein anderer Mechanismus eingreift.

Der Hauptzweck besteht darin, einem Prozess zu ermöglichen, kontrollierte Offsets der verstrichenen Zeit zu beobachten, ohne die globale Zeitanzeige des Hosts zu ändern. Dies ist für Checkpoint/Restore-Workflows, deterministische Tests und fortgeschrittenes Runtime-Verhalten nützlich. Im Gegensatz zu mount- oder user namespaces ist dies normalerweise keine zentrale Isolation-Kontrolle, trägt aber dennoch dazu bei, die Prozessumgebung stärker in sich geschlossen zu gestalten.

Aus offensiver Sicht ist dieser Namespace normalerweise eher für **Reconnaissance, Timer-Skew und das Verständnis der Runtime** relevant als für einen direkten Breakout. Dennoch ist er wichtig, da immer mehr Container-Runtimes und Checkpoint/Restore-Workflows ihn ausdrücklich anfordern können.

## Labor

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
Die Unterstützung variiert je nach Kernel- und Tool-Version. Daher geht es auf dieser Seite eher darum, den Mechanismus zu verstehen, als zu erwarten, dass er in jeder Lab-Umgebung sichtbar ist. Die wichtige Beobachtung ist, dass `date` weiterhin die Wall Clock des Hosts anzeigen sollte, während sich auf monotonic/boottime basierende Werte ändern, wenn ungleich null Offsets konfiguriert sind.

### Besonderheit bei der Erstellung

Time-Namespaces sind im Vergleich zu Mount-, PID- oder Netzwerk-Namespaces etwas ungewöhnlich:

- `unshare(CLONE_NEWTIME)` erstellt einen neuen Time-Namespace für **zukünftige Child-Prozesse**.
- Der aufrufende Task bleibt in seinem aktuellen Time-Namespace.
- `/proc/<pid>/ns/time_for_children` ist daher beim Debugging des Runtime-Setups oft interessanter als `/proc/<pid>/ns/time`.

Auch das Schreibfenster ist speziell. Offsets in `/proc/<pid>/timens_offsets` müssen geschrieben werden, bevor der neue Time-Namespace vollständig mit laufenden Tasks gefüllt ist. In der Praxis erledigen Runtimes dies während des engen Setup-Fensters zwischen der Erstellung des Namespace und dem Start des finalen Payloads. Sobald dort bereits ein Task läuft, schlagen spätere Schreibvorgänge mit `EACCES` fehl. Deshalb behandeln Low-Level-Runtimes das Setup des Time-Namespaces als frühen Bootstrap-Schritt, anstatt zu versuchen, Offsets aus einem bereits gestarteten Container-Prozess heraus zu ändern.

### Time-Offsets

Linux-Time-Namespaces stellen die Namespace-spezifischen Offsets über `/proc/<pid>/timens_offsets` bereit. Das Format besteht aus einer Gruppe von Clock-Namen oder -IDs sowie Sekunden-/Nanosekunden-Deltas relativ zum initialen Time-Namespace.

In der Praxis besteht der zuverlässigste User-facing-Workflow darin, `unshare` diese Offsets für dich schreiben zu lassen:
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
Der wichtige Punkt ist nicht die exakte Befehlssyntax, sondern das Verhalten: Ein Container kann eine andere uptime-ähnliche Ansicht beobachten, ohne die Systemzeit des Hosts zu ändern.

### `unshare`-Hilfs-Flags

Aktuelle `util-linux`-Versionen bieten praktische Flags, die die Offsets während der Erstellung des Namespace automatisch schreiben:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Diese Flags stellen hauptsächlich eine Verbesserung der Benutzerfreundlichkeit dar, erleichtern aber auch das Erkennen des Features in Dokumentation, Test-Harnesses und Runtime-Wrappern.

## Verwendung zur Laufzeit

Time-Namespaces sind neuer und werden weniger universell verwendet als Mount- oder PID-Namespaces. Die OCI Runtime Specification v1.1 fügte explizite Unterstützung für den `time`-Namespace und das Feld `linux.timeOffsets` hinzu, und moderne Runtimes können diese Daten in den Kernel-Bootstrap-Ablauf übertragen. Ein minimales OCI-Fragment sieht wie folgt aus:
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
Das ist relevant, weil es Time Namespacing von einem speziellen Kernel-Primitiv zu etwas macht, das Runtimes portabel anfordern können. Es erklärt außerdem, warum die Interna von Runtimes einen expliziten Synchronisierungsschritt benötigen: Der Offset muss in `/proc/<pid>/timens_offsets` geschrieben werden, bevor die Container-Payload vollständig in den neuen Namespace eintritt.

Checkpoint/restore-Stacks wie CRIU sind einer der wichtigsten Gründe aus der Praxis, warum dies überhaupt existiert. Ohne Time Namespaces würden beim Wiederherstellen einer pausierten Workload monotone Uhren und Bootzeit-Uhren um die Zeit springen, die die Workload suspendiert war.

## Sicherheitsauswirkungen

Es gibt weniger klassische Breakout-Szenarien, die sich um den Time Namespace drehen, als bei anderen Namespace-Typen. Das Risiko besteht hier normalerweise nicht darin, dass der Time Namespace direkt einen Escape ermöglicht, sondern darin, dass Leser ihn vollständig ignorieren und dadurch übersehen, wie fortgeschrittene Runtimes das Prozessverhalten beeinflussen können.

In spezialisierten Umgebungen können veränderte Ansichten der monotonen Zeit oder der Boottime Folgendes beeinflussen:

- Timeout- und Retry-Verhalten
- Watchdogs und Lease-Logik
- Verhalten von `timerfd`, `nanosleep` und `clock_nanosleep`
- Forensik bei Checkpoint/restore
- Telemetrie zur verstrichenen Zeit und auf Uptime basierende Heuristiken

Auch wenn dies selten der erste Namespace ist, den man missbraucht, kann er während eines Assessments durchaus „unmögliches“ Zeitverhalten erklären.

## Missbrauch

Hier gibt es normalerweise kein direktes Breakout-Primitiv, aber verändertes Uhrverhalten kann dennoch nützlich sein, um die Ausführungsumgebung zu verstehen, fortgeschrittene Runtime-Funktionen zu erkennen und timerbasierte Logik aufzuspüren, die anhand monotoner Uhren statt anhand der Wanduhrzeit gemessen wird:
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
Wenn du zwei Prozesse vergleichst, können Unterschiede hier helfen, ungewöhnliches Timing-Verhalten, Checkpoint/Restore-Artefakte oder umgebungsspezifische Abweichungen bei der Protokollierung zu erklären.

Praktische, für Angreifer relevante Ansatzpunkte:

- Backoff-, Sleep- oder Watchdog-Logik verwirren, die mit monotonic clocks implementiert ist
- erklären, warum `/proc/uptime` und timer-gesteuertes Verhalten nicht mit den Erwartungen an die hostseitige wall clock übereinstimmen
- CRIU/Checkpoint-Restore-Workflows und andere fortgeschrittene Runtime-Features erkennen
- Umgebungen erkennen, in denen das Beitreten zu einem target time namespace mit `nsenter -T -t <pid> -- ...` das Verhalten containerlokaler Timer für Debugging oder Post-Exploitation reproduzieren kann

Auswirkungen:

- fast immer Reconnaissance oder besseres Verständnis der Umgebung
- nützlich zum Erklären von Anomalien bei Logging, Uptime oder Checkpoint/Restore
- nützlich zur Analyse von Sleeps, Retries und Timern, die auf monotonic time basieren
- normalerweise kein direkter Container-Escape-Mechanismus an sich

Die wichtige Abuse-Nuance ist, dass time namespaces `CLOCK_REALTIME` nicht virtualisieren. Sie ermöglichen es einem Angreifer daher nicht allein, die wall clock des Hosts zu fälschen oder systemweite Certificate-Expiry-Checks direkt zu umgehen. Ihr Wert liegt hauptsächlich darin, Logik zu verwirren, die auf monotonic time basiert, umgebungsspezifische Bugs zu reproduzieren oder fortgeschrittenes Runtime-Verhalten zu verstehen.

## Checks

Bei diesen Checks geht es hauptsächlich darum zu bestätigen, ob die Runtime überhaupt einen privaten time namespace verwendet und ob sie tatsächlich Offsets ungleich null gesetzt hat.
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
Was hier interessant ist:

- In vielen Umgebungen führen diese Werte nicht unmittelbar zu einem Security Finding, zeigen aber, ob ein spezialisiertes Runtime-Feature aktiv ist.
- Wenn sich `time_for_children` von `time` unterscheidet, hat der aufrufende Prozess möglicherweise einen nur für Child-Prozesse bestimmten Time Namespace vorbereitet, den er selbst nicht betreten hat.
- Wenn `date` mit dem Host übereinstimmt, monotonic-/boottime-basierte Werte jedoch nicht, handelt es sich wahrscheinlich um Time Namespacing und nicht um eine Manipulation der Systemzeit.
- Beim Vergleich zweier Prozesse können Unterschiede hier verwirrendes Timing- oder Checkpoint/Restore-Verhalten erklären.

Bei den meisten Container Breakouts ist der Time Namespace nicht die erste Kontrolle, die untersucht wird. Trotzdem sollte ein vollständiger Abschnitt zur Container-Sicherheit darauf eingehen, da er Teil des modernen Kernel-Modells ist und in fortgeschrittenen Runtime-Szenarien gelegentlich relevant wird.

## Referenzen

- [Linux-Handbuchseite `time_namespaces(7)`](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces – Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
