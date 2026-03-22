# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Das time namespace virtualisiert ausgewählte Uhren, insbesondere **`CLOCK_MONOTONIC`** und **`CLOCK_BOOTTIME`**. Es ist ein neueres und spezialisierteres Namespace als mount-, PID-, network- oder user-Namespaces und selten das Erste, an das ein Betreiber denkt, wenn es um die Absicherung von Containern geht. Trotzdem gehört es zur modernen Namespace-Familie und ist konzeptionell wert zu verstehen.

Der Hauptzweck besteht darin, einem Prozess kontrollierte Offsets für bestimmte Uhren zu erlauben, ohne die globale Zeitansicht des Hosts zu ändern. Das ist nützlich für Checkpoint/Restore-Workflows, deterministische Tests und einige fortgeschrittene Laufzeitverhalten. Es ist normalerweise kein vordergründiges Isolationsmerkmal wie mount- oder user-Namespaces, trägt aber trotzdem dazu bei, die Prozessumgebung selbstständiger zu gestalten.

## Labor

Wenn der Host-Kernel und Userspace es unterstützen, können Sie das Namespace mit folgendem Befehl inspizieren:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Die Unterstützung variiert je nach Kernel- und Tool-Version, daher geht es auf dieser Seite eher darum, den Mechanismus zu verstehen, als davon auszugehen, dass er in jeder Laborumgebung sichtbar ist.

### Zeitoffsets

Linux time namespaces virtualisieren Offsets für `CLOCK_MONOTONIC` und `CLOCK_BOOTTIME`. Die aktuellen Offsets pro Namespace werden über `/proc/<pid>/timens_offsets` offengelegt, die auf unterstützenden Kerneln auch von einem Prozess verändert werden können, der `CAP_SYS_TIME` innerhalb des relevanten Namespace besitzt:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Die Datei enthält Nanosekunden-Differenzen. Das Anpassen von `monotonic` um zwei Tage verändert uptime-ähnliche Beobachtungen innerhalb dieses Namespaces, ohne die Uhrzeit des Hosts zu ändern.

### `unshare` Helper Flags

Neuere `util-linux`-Versionen bieten praktische Flags, die die Offsets automatisch schreiben:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Diese Flags sind größtenteils eine Verbesserung der Benutzerfreundlichkeit, erleichtern aber auch das Erkennen der Funktion in Dokumentation und Tests.

## Laufzeitverwendung

Time-Namespaces sind neuer und weniger weit verbreitet als mount- oder PID-Namespaces. Die OCI Runtime Specification v1.1 hat explizite Unterstützung für den `time`-Namespace und das Feld `linux.timeOffsets` hinzugefügt, und neuere `runc`-Releases implementieren diesen Teil des Modells. Ein minimales OCI-Fragment sieht folgendermaßen aus:
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
Das ist wichtig, weil es time namespacing von einem Nischen-Kernel-Primitiv in etwas verwandelt, das runtimes portabel anfordern können.

## Sicherheitsauswirkungen

Es gibt weniger klassische breakout stories, die sich auf den time namespace konzentrieren, als bei anderen Namespace-Typen. Das Risiko besteht hier meist nicht darin, dass der time namespace direkt eine escape ermöglicht, sondern darin, dass er von Lesern komplett ignoriert wird und sie dadurch übersehen, wie fortgeschrittene runtimes das Verhalten von Prozessen beeinflussen können. In spezialisierten Umgebungen können veränderte Zeitansichten checkpoint/restore, observability oder forensische Annahmen beeinflussen.

## Missbrauch

In der Regel gibt es hier kein direktes breakout primitive, aber verändertes Zeitverhalten kann dennoch nützlich sein, um die Ausführungsumgebung zu verstehen und fortgeschrittene runtime features zu identifizieren:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Wenn Sie zwei Prozesse vergleichen, können Unterschiede hier dabei helfen, ungewöhnliches Timing-Verhalten, Checkpoint/Restore-Artefakte oder umgebungsspezifische Protokollierungs-Mismatches zu erklären.

Auswirkung:

- fast immer reconnaissance oder Verständnis der Umgebung
- nützlich, um Protokollierungs-, Uptime- oder Checkpoint/Restore-Anomalien zu erklären
- normalerweise kein direkter container-escape-Mechanismus für sich allein

Die wichtige Missbrauchs-Nuance ist, dass time namespaces `CLOCK_REALTIME` nicht virtualisieren, sodass sie einem Angreifer nicht von sich aus erlauben, die Host-Systemuhr zu fälschen oder systemweit direkt certificate-expiry-Checks zu umgehen. Ihr Wert liegt hauptsächlich darin, monotonic-time-basierte Logik zu verwirren, umgebungsspezifische Bugs zu reproduzieren oder fortgeschrittenes Laufzeitverhalten zu verstehen.

## Prüfungen

Diese Checks dienen hauptsächlich dazu zu bestätigen, ob die Runtime überhaupt ein privates time namespace verwendet.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
- In vielen Umgebungen führen diese Werte nicht zu einem unmittelbaren Sicherheitsbefund, aber sie sagen Ihnen, ob eine spezialisierte runtime-Funktion aktiv ist.
- Wenn Sie zwei Prozesse vergleichen, können Unterschiede hier verwirrendes Timing- oder checkpoint/restore-Verhalten erklären.

Für die meisten container breakouts ist das time namespace nicht die erste Kontrolle, die Sie untersuchen werden. Dennoch sollte ein vollständiger container-security-Abschnitt es erwähnen, da es Teil des modernen Kernel-Modells ist und gelegentlich in fortgeschrittenen runtime-Szenarien eine Rolle spielt.
{{#include ../../../../../banners/hacktricks-training.md}}
