# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Der UTS-Namespace isoliert den vom Prozess gesehenen **hostname** und den **NIS domain name**. Auf den ersten Blick mag dies im Vergleich zu mount-, PID- oder user-Namespaces trivial erscheinen, aber es ist ein Teil dessen, was einen Container wie einen eigenen Host erscheinen lässt. Innerhalb des Namespace kann die Workload einen Hostnamen sehen und manchmal ändern, der lokal für diesen Namespace und nicht global für die Maschine ist.

Allein betrachtet ist dies normalerweise nicht das Herzstück einer Breakout-Story. Sobald jedoch der Host-UTS-Namespace geteilt wird, kann ein ausreichend privilegierter Prozess hostbezogene Identitätseinstellungen beeinflussen, was betrieblich und gelegentlich auch sicherheitsrelevant sein kann.

## Labor

Sie können einen UTS-Namespace mit folgendem Befehl erstellen:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Die Änderung des Hostnamens bleibt lokal in diesem Namespace und verändert nicht den globalen Hostnamen. Das ist eine einfache, aber effektive Demonstration des Isolationsprinzips.

## Laufzeitnutzung

Normale Container erhalten einen isolierten UTS namespace. Docker und Podman können dem host UTS namespace über `--uts=host` beitreten, und ähnliche Host-Sharing-Muster können in anderen Runtimes und Orchestrierungssystemen vorkommen. In den meisten Fällen ist die private UTS-Isolation jedoch einfach Teil der normalen Container-Konfiguration und erfordert nur wenig Aufmerksamkeit des Betreibers.

## Sicherheitsauswirkungen

Obwohl der UTS namespace normalerweise nicht der gefährlichste Namespace ist, den man teilen kann, trägt er dennoch zur Integrität der Container-Grenze bei. Wird der host UTS namespace offengelegt und hat der Prozess die notwendigen Privilegien, kann er möglicherweise Informationen zum Hostnamen ändern. Das kann Monitoring, Logging, betriebliche Annahmen oder Skripte beeinflussen, die Vertrauensentscheidungen auf Basis von Host-Identitätsdaten treffen.

## Missbrauch

Wenn der host UTS namespace geteilt wird, ist die praktische Frage, ob der Prozess die Host-Identitätseinstellungen ändern kann, anstatt sie nur zu lesen:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Wenn der Container außerdem über das notwendige Privileg verfügt, teste, ob der Hostname geändert werden kann:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Dies ist primär ein Integritäts- und betriebliches Auswirkungsproblem, kein vollständiger escape, zeigt aber dennoch, dass der Container direkt eine hostweite Eigenschaft beeinflussen kann.

Auswirkungen:

- Manipulation der Host-Identität
- Verwirrende Logs, Monitoring oder Automatisierung, die dem Hostnamen vertrauen
- in der Regel kein vollständiger escape für sich allein, es sei denn, er wird mit anderen Schwachstellen kombiniert

In Docker-ähnlichen Umgebungen ist ein nützliches hostseitiges Erkennungsmuster:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Container, die `UTSMode=host` anzeigen, teilen den UTS-Namensraum des Hosts und sollten sorgfältiger überprüft werden, wenn sie außerdem capabilities besitzen, die ihnen erlauben, `sethostname()` oder `setdomainname()` aufzurufen.

## Überprüfungen

Diese Befehle reichen aus, um zu erkennen, ob die Workload eine eigene Ansicht des Hostnamens hat oder den UTS-Namensraum des Hosts teilt.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Was hier interessant ist:

- Das Abgleichen von Namespace-Identifikatoren mit einem Host-Prozess kann auf ein geteiltes UTS des Hosts hinweisen.
- Wenn das Ändern des Hostnamens mehr als nur den Container selbst beeinflusst, hat der Workload mehr Einfluss auf die Host-Identität, als er haben sollte.
- Dies ist normalerweise ein Befund mit niedrigerer Priorität als Probleme in PID-, mount- oder user-namespace, bestätigt aber trotzdem, wie isoliert der Prozess wirklich ist.

In den meisten Umgebungen ist der UTS-Namespace am besten als eine unterstützende Isolationsebene zu betrachten. Er ist selten das Erste, dem man bei einem breakout nachgeht, gehört aber dennoch zur allgemeinen Konsistenz und Sicherheit der Container-Ansicht.
{{#include ../../../../../banners/hacktricks-training.md}}
