# Time-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Das Time-Namespace virtualisiert ausgewählte Uhren, insbesondere **`CLOCK_MONOTONIC`** und **`CLOCK_BOOTTIME`**. Es ist ein neueres und spezialisierteres Namespace im Vergleich zu mount-, PID-, network- oder user-namespaces und steht bei Diskussionen zur Container-Härtung selten an erster Stelle. Dennoch gehört es zur modernen Namespace-Familie und ist konzeptionell erklärenswert.

Der Hauptzweck besteht darin, einem Prozess kontrollierte Offsets für bestimmte Uhren beobachten zu lassen, ohne die globale Zeitansicht des Hosts zu verändern. Das ist nützlich für Checkpoint/Restore-Workflows, deterministische Tests und einige fortgeschrittene Laufzeitverhalten. Es ist normalerweise keine zentrale Isolationseinheit wie mount- oder user-namespaces, trägt aber dennoch dazu bei, die Prozessumgebung stärker zu isolieren.

## Labor

Wenn der Kernel und Userspace des Hosts es unterstützen, können Sie das Namespace wie folgt untersuchen:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Die Unterstützung variiert je nach Kernel- und Tool-Versionen, daher geht es auf dieser Seite eher darum, den Mechanismus zu verstehen, als zu erwarten, dass er in jeder Laborumgebung sichtbar ist.

### Zeitverschiebungen

Linux time namespaces virtualisieren Offsets für `CLOCK_MONOTONIC` und `CLOCK_BOOTTIME`. Die aktuellen pro-Namespace-Offsets werden über `/proc/<pid>/timens_offsets` angezeigt; auf unterstützenden Kerneln kann diese Datei außerdem von einem Prozess verändert werden, der `CAP_SYS_TIME` im entsprechenden Namespace hat:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Die Datei enthält Nanosekunden-Deltawerte. Das Anpassen von `monotonic` um zwei Tage ändert uptime-ähnliche Beobachtungen innerhalb dieses Namespaces, ohne die Wanduhr des Hosts zu ändern.

### `unshare` Hilfs-Flags

Neuere `util-linux`-Versionen bieten praktische Flags, die die Offsets automatisch setzen:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Diese Flags sind größtenteils eine Verbesserung der Benutzerfreundlichkeit, erleichtern aber auch das Erkennen der Funktion in der Dokumentation und beim Testen.

## Laufzeitnutzung

Time namespaces sind neuer und werden weniger universell genutzt als mount- oder PID namespaces. OCI Runtime Specification v1.1 hat explizite Unterstützung für das `time` namespace und das Feld `linux.timeOffsets` hinzugefügt, und neuere `runc` Releases setzen diesen Teil des Modells um. Ein minimales OCI-Fragment sieht folgendermaßen aus:
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
Das ist wichtig, weil dadurch time namespacing von einer Nischen-Kernel-Primitive zu etwas wird, das runtimes portabel anfordern können.

## Sicherheitsauswirkungen

Es gibt weniger klassische Breakout-Fälle, die sich auf das time namespace konzentrieren, als auf andere Namespace-Typen. Das Risiko besteht hier normalerweise nicht darin, dass das time namespace direkt einen Escape ermöglicht, sondern darin, dass Leser es komplett ignorieren und dadurch übersehen, wie fortgeschrittene runtimes das Prozessverhalten beeinflussen können. In spezialisierten Umgebungen können veränderte Zeitsichten checkpoint/restore, observability oder forensische Annahmen beeinflussen.

## Missbrauch

Hier gibt es normalerweise keine direkte Breakout-Primitive, aber verändertes Uhrenverhalten kann dennoch nützlich sein, um die Ausführungsumgebung zu verstehen und fortgeschrittene runtime-Funktionen zu identifizieren:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Wenn Sie zwei Prozesse vergleichen, können Unterschiede hier helfen, ungewöhnliches Timing-Verhalten, Checkpoint/Restore-Artefakte oder umgebungsspezifische Abweichungen in Logs zu erklären.

Auswirkungen:

- Fast immer reconnaissance oder Umgebungsverständnis
- Nützlich, um Logging-, Uptime- oder Checkpoint/Restore-Anomalien zu erklären
- Normalerweise kein direkter container-escape-Mechanismus für sich allein

Die wichtige Missbrauchsnuance ist, dass time namespaces `CLOCK_REALTIME` nicht virtualisieren, sodass sie nicht von sich aus einem Angreifer erlauben, die Systemuhr des Hosts zu fälschen oder systemweit direkt Zertifikatsablaufprüfungen zu umgehen. Ihr Wert liegt hauptsächlich darin, monotonic-time-basierte Logik zu verwirren, umgebungsspezifische Bugs zu reproduzieren oder fortgeschrittenes Runtime-Verhalten zu verstehen.

## Checks

Diese Checks betreffen hauptsächlich die Bestätigung, ob die Runtime überhaupt ein privates time namespace verwendet.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Was hier interessant ist:

- In vielen Umgebungen führen diese Werte nicht zu einem unmittelbaren Sicherheitsbefund, geben aber Auskunft darüber, ob eine spezialisierte runtime-Funktion zum Einsatz kommt.
- Wenn Sie zwei Prozesse vergleichen, können Unterschiede hier verwirrendes Timing- oder checkpoint/restore-Verhalten erklären.

Für die meisten container breakouts ist das time namespace nicht die erste Kontrolle, die Sie untersuchen werden. Dennoch sollte ein vollständiger container-security-Abschnitt es erwähnen, da es Teil des modernen Kernel-Modells ist und gelegentlich in fortgeschrittenen runtime-Szenarien relevant wird.
{{#include ../../../../../banners/hacktricks-training.md}}
