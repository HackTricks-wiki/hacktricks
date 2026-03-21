# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Das time namespace virtualisiert ausgewählte Uhren, insbesondere **`CLOCK_MONOTONIC`** und **`CLOCK_BOOTTIME`**. Es ist ein neueres und spezialisierteres Namespace als mount-, PID-, network- oder user-namespaces und selten das Erste, woran ein Betreiber denkt, wenn es um die Absicherung von Containern geht. Trotzdem gehört es zur modernen Namespace-Familie und lohnt sich, konzeptionell verstanden zu werden.

Der Hauptzweck besteht darin, einem Prozess kontrollierte Offsets für bestimmte Uhren zu erlauben, ohne die globale Zeitansicht des Hosts zu ändern. Das ist nützlich für checkpoint/restore-Workflows, deterministische Tests und einige fortgeschrittene Laufzeitverhalten. Es ist normalerweise keine prominente Isolationsebene in der gleichen Weise wie mount- oder user-Namespaces, trägt aber dennoch dazu bei, die Prozessumgebung selbstständiger zu machen.

## Lab

Wenn der Kernel und der Userspace des Hosts es unterstützen, können Sie das Namespace mit folgendem Befehl inspizieren:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Die Unterstützung variiert je nach Kernel- und Tool-Versionen, daher geht es auf dieser Seite eher darum, den Mechanismus zu verstehen, als zu erwarten, dass er in jeder Laborumgebung sichtbar ist.

### Zeit-Offsets

Linux time namespaces virtualisieren Offsets für `CLOCK_MONOTONIC` und `CLOCK_BOOTTIME`. Die aktuellen Offsets pro Namespace werden über `/proc/<pid>/timens_offsets` bereitgestellt, die auf unterstützenden Kerneln auch von einem Prozess geändert werden können, der `CAP_SYS_TIME` innerhalb des betreffenden Namespace besitzt:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Die Datei enthält Nanosekunden-Offsets. Das Anpassen von `monotonic` um zwei Tage verändert uptime-ähnliche Beobachtungen innerhalb dieses Namespace, ohne die Uhrzeit des Hosts zu ändern.

### `unshare` Hilfsflags

Neuere `util-linux`-Versionen bieten Komfortflags, die die Offsets automatisch setzen:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Diese flags sind größtenteils eine Usability-Verbesserung, erleichtern aber auch das Erkennen der Funktion in der Dokumentation und beim Testen.

## Runtime-Nutzung

Time namespaces sind neuer und werden weniger häufig genutzt als mount- oder PID-namespaces. OCI Runtime Specification v1.1 fügte explizite Unterstützung für das `time` namespace und das Feld `linux.timeOffsets` hinzu, und neuere `runc`-Releases implementieren diesen Teil des Modells. Ein minimales OCI-Fragment sieht wie folgt aus:
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
Das ist wichtig, weil es time namespacing von einer Nischen-Kernel-Primitive in etwas verwandelt, das runtimes portabel anfordern können.

## Sicherheitsauswirkungen

Es gibt weniger klassische breakout stories, die sich auf das time namespace konzentrieren, als bei anderen Namespace-Typen. Das Risiko besteht hier meist nicht darin, dass das time namespace direkt eine escape ermöglicht, sondern darin, dass Leser es komplett ignorieren und dadurch übersehen, wie fortgeschrittene runtimes das Prozessverhalten formen können. In spezialisierten Umgebungen können veränderte clock-Ansichten checkpoint/restore, observability oder forensische Annahmen beeinflussen.

## Missbrauch

Normalerweise gibt es hier kein direktes breakout primitive, aber verändertes clock-Verhalten kann dennoch nützlich sein, um die Ausführungsumgebung zu verstehen und fortgeschrittene runtime-Funktionen zu identifizieren:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Wenn Sie zwei Prozesse vergleichen, können Unterschiede hier helfen, seltsames Timing-Verhalten, Checkpoint/Restore-Artefakte oder umgebungsspezifische Abweichungen in den Protokollen zu erklären.

Auswirkung:

- beinahe immer Aufklärung oder Verständnis der Umgebung
- nützlich, um Abweichungen in Protokollen, Betriebszeit oder Checkpoint/Restore-Anomalien zu erklären
- normalerweise nicht selbst ein direkter container-escape-Mechanismus

Wichtig für den Missbrauch ist die Nuance, dass Time-Namespaces `CLOCK_REALTIME` nicht virtualisieren, sodass sie für sich genommen einem Angreifer nicht erlauben, die Host-Wanduhr zu fälschen oder systemweit Zertifikatsablaufprüfungen direkt zu umgehen. Ihr Wert liegt hauptsächlich darin, auf monotone Zeit basierende Logik zu verwirren, umgebungsspezifische Bugs zu reproduzieren oder fortgeschrittenes Laufzeitverhalten zu verstehen.

## Prüfungen

Bei diesen Checks geht es hauptsächlich darum zu bestätigen, ob die Runtime überhaupt ein privates Time-Namespace verwendet.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
- In vielen Umgebungen führen diese Werte nicht zu einer unmittelbaren Sicherheitsfeststellung, aber sie zeigen, ob eine spezialisierte runtime-Funktion aktiv ist.
- Wenn Sie zwei Prozesse vergleichen, können Unterschiede hier verwirrendes Timing- oder Checkpoint/Restore-Verhalten erklären.

Für die meisten container breakouts ist die time namespace nicht die erste Kontrolle, die Sie untersuchen werden. Dennoch sollte eine vollständige container-security section sie erwähnen, da sie Teil des modernen kernel model ist und gelegentlich in fortgeschrittenen runtime-Szenarien relevant sein kann.
