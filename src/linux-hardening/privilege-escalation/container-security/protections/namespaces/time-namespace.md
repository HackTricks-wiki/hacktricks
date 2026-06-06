# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Der time namespace virtualisiert ausgewählte monotonic-style clocks statt der host wall clock. In der Praxis bedeutet das private Offsets für **`CLOCK_MONOTONIC`** und **`CLOCK_BOOTTIME`**, plus die eng verwandten **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** und **`CLOCK_BOOTTIME_ALARM`**-Ansichten. Es virtualisiert **`CLOCK_REALTIME`** nicht, daher beobachten `date` und certificate-expiry-Logik weiterhin die host wall clock, sofern kein anderer Mechanismus eingreift.

Der Hauptzweck ist, einem Prozess kontrollierte elapsed-time-Offsets zu erlauben, ohne die globale time view des hosts zu ändern. Das ist nützlich für checkpoint/restore workflows, deterministic testing und advanced runtime behavior. Es ist normalerweise keine prominente isolation control wie mount oder user namespaces, trägt aber dennoch dazu bei, die process environment eigenständiger zu machen.

Aus offensiver Sicht ist dieser namespace meist eher relevant für **reconnaissance, timer skew und runtime understanding** als für einen direkten breakout. Trotzdem ist er wichtig, weil immer mehr container runtimes und checkpoint/restore workflows ihn nun explizit anfordern können.

## Lab

Wenn der host kernel und userspace es unterstützen, kannst du den namespace mit folgendem Befehl inspizieren:
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
Support variiert je nach Kernel- und Tool-Version, daher geht es auf dieser Seite eher darum, den Mechanismus zu verstehen, als zu erwarten, dass er in jeder Lab-Umgebung sichtbar ist. Die wichtige Beobachtung ist, dass `date` weiterhin die Host-Wall-Clock widerspiegeln sollte, während monotonic/boottime-basierte Werte diejenigen sind, die sich ändern, wenn nonzero offsets konfiguriert sind.

### Creation Nuance

Time namespaces sind im Vergleich zu mount, PID oder network namespaces etwas ungewöhnlich:

- `unshare(CLONE_NEWTIME)` erstellt einen neuen time namespace für **future children**.
- Der aufrufende Task bleibt in seinem aktuellen time namespace.
- `/proc/<pid>/ns/time_for_children` ist daher beim Debugging des Runtime-Setups oft interessanter als `/proc/<pid>/ns/time`.

Auch das write window ist speziell. Offsets in `/proc/<pid>/timens_offsets` müssen geschrieben werden, bevor der neue time namespace vollständig mit laufenden Tasks gefüllt ist; in der Praxis erledigen runtimes das während des engen Setup-Fensters zwischen der Namespace-Erstellung und dem Start des final payloads. Sobald dort bereits ein Task läuft, schlagen spätere Writes mit `EACCES` fehl. Deshalb behandeln Low-Level-Runtimes das time-namespace-Setup als frühen Bootstrap-Schritt, statt zu versuchen, Offsets von داخل eines bereits gestarteten container processes zu patchen.

### Time Offsets

Linux time namespaces stellen die per-namespace offsets über `/proc/<pid>/timens_offsets` bereit. Das Format ist eine Menge von clock names oder IDs plus second/nanosecond deltas relativ zum initial time namespace.

In der Praxis ist der zuverlässigste user-facing workflow, `unshare` diese offsets für dich schreiben zu lassen:
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
Der wichtige Punkt ist nicht die genaue Befehls-Syntax, sondern das Verhalten: Ein Container kann eine andere uptime-ähnliche Ansicht beobachten, ohne die Host-Wanduhr zu ändern.

### `unshare` Helper Flags

Neuere `util-linux`-Versionen bieten Komfort-Flags, die die Offsets während der Namespace-Erstellung automatisch schreiben:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Diese Flags sind hauptsächlich eine Verbesserung der Benutzerfreundlichkeit, aber sie machen es auch einfacher, das Feature in Dokumentation, Test-Harnesses und Runtime-Wrappers zu erkennen.

## Runtime Usage

Time namespaces sind neuer und weniger universell genutzt als mount- oder PID-namespaces. Die OCI Runtime Specification v1.1 hat explizite Unterstützung für den `time`-namespace und das `linux.timeOffsets`-Feld hinzugefügt, und moderne runtimes können diese Daten in den Kernel-Bootstrap-Flow einbinden. Ein minimales OCI-Fragment sieht so aus:
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
Das ist wichtig, weil es time namespacing von einem Nischen-Kernel-Primitive zu etwas macht, das runtimes portabel anfordern können. Es erklärt auch, warum runtime internals einen expliziten Synchronisationsschritt brauchen: Der Offset muss in `/proc/<pid>/timens_offsets` geschrieben werden, bevor der container payload vollständig in das neue namespace eintritt.

Checkpoint/restore-Stacks wie CRIU sind einer der Hauptgründe in der Praxis, warum es das überhaupt gibt. Ohne time namespaces würde das Wiederherstellen eines pausierten Workloads dazu führen, dass monotonic- und boot-time clocks um die Zeit springen, die der Workload im suspendierten Zustand verbracht hat.

## Security Impact

Es gibt weniger klassische breakout-Geschichten rund um das time namespace als bei anderen namespace-Typen. Das Risiko ist hier meist nicht, dass das time namespace direkt escape ermöglicht, sondern dass Leser es komplett ignorieren und dadurch übersehen, wie fortgeschrittene runtimes das Verhalten von Prozessen formen.

In spezialisierten Umgebungen können veränderte monotonic- oder boottime-Ansichten Folgendes beeinflussen:

- timeout- und retry-Verhalten
- watchdogs und lease-Logik
- `timerfd`, `nanosleep` und `clock_nanosleep`-Verhalten
- checkpoint/restore forensics
- elapsed-time-Telemetrie und uptime-basierte Heuristiken

Auch wenn dies selten das erste namespace ist, das man abuse, kann es während einer assessment durchaus "unmögliches" Timing-Verhalten erklären.

## Abuse

Normalerweise gibt es hier kein direktes breakout-Primitive, aber verändertes clock-Verhalten kann trotzdem nützlich sein, um die Ausführungsumgebung zu verstehen, fortgeschrittene runtime-Features zu erkennen und timer-basierte Logik zu finden, die gegen monotonic clocks statt gegen wall clock time gemessen wird:
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
Wenn du zwei Prozesse vergleichst, können Unterschiede hier helfen, seltsames Timing-Verhalten, Checkpoint/Restore-Artefakte oder umgebungsabhängige Logging-Mismatches zu erklären.

Praktische attacker-relevante Aspekte:

- Backoff-, Sleep- oder Watchdog-Logik mit monotonic clocks verwirren
- erklären, warum `/proc/uptime` und timer-gesteuertes Verhalten von den wall-clock-Erwartungen auf Host-Seite abweichen
- CRIU/Checkpoint-restore-Workflows und andere fortgeschrittene Runtime-Features erkennen
- Umgebungen erkennen, in denen das Verbinden mit einer Ziel-Time-Namespace mit `nsenter -T -t <pid> -- ...` container-lokales Timer-Verhalten für Debugging oder post-exploitation reproduzieren kann

Auswirkung:

- fast immer reconnaissance oder Verständnis der Umgebung
- nützlich, um Logging-, Uptime- oder Checkpoint/Restore-Anomalien zu erklären
- nützlich für die Analyse von Sleeps, Retries und Timern auf Basis von monotonic time
- normalerweise selbst kein direkter container-escape-Mechanismus

Die wichtige Missbrauchs-Nuance ist, dass time namespaces `CLOCK_REALTIME` nicht virtualisieren, sodass sie es einem Angreifer allein nicht erlauben, die Host wall clock zu fälschen oder certificate-expiry-Checks systemweit direkt zu umgehen. Ihr Nutzen liegt vor allem darin, monotonic-time-basierte Logik zu verwirren, umgebungsabhängige Bugs zu reproduzieren oder fortgeschrittenes Runtime-Verhalten zu verstehen.

## Checks

Diese Checks dienen hauptsächlich dazu, zu bestätigen, ob die Runtime überhaupt eine private time namespace verwendet und ob sie tatsächlich von Null verschiedene Offsets gesetzt hat.
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

- In vielen Umgebungen führen diese Werte nicht zu einem sofortigen Sicherheitsbefund, aber sie zeigen dir, ob ein spezialisierter Runtime-Feature im Einsatz ist.
- Wenn `time_for_children` sich von `time` unterscheidet, kann der Caller möglicherweise ein child-only time namespace vorbereitet haben, das er selbst nicht betreten hat.
- Wenn `date` dem Host entspricht, aber monotonic/boottime-basierte Werte nicht, schaust du dir wahrscheinlich time namespacing an und nicht eine Manipulation der wall-clock.
- Wenn du zwei Prozesse vergleichst, können Unterschiede hier verwirrendes Timing oder checkpoint/restore-Verhalten erklären.

Für die meisten container breakouts ist das time namespace nicht die erste Kontrolle, die du untersuchen wirst. Trotzdem sollte ein vollständiger container-security-Abschnitt es erwähnen, weil es Teil des modernen Kernel-Modells ist und in fortgeschrittenen Runtime-Szenarien gelegentlich wichtig ist.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
