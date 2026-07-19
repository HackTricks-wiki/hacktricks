# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der UTS Namespace isoliert den vom Prozess sichtbaren **hostname** und **NIS domain name**. Auf den ersten Blick mag dies im Vergleich zu Mount-, PID- oder User-Namespaces trivial erscheinen, doch er trägt dazu bei, dass ein Container wie ein eigener Host wirkt. Innerhalb des Namespace kann die Workload einen hostname sehen und manchmal ändern, der auf diesen Namespace beschränkt ist und nicht global für die Maschine gilt.

Für sich genommen ist dies normalerweise nicht der Mittelpunkt eines Breakout-Szenarios. Sobald jedoch der UTS Namespace des Hosts geteilt wird, kann ein ausreichend privilegierter Prozess möglicherweise Einstellungen zur Host-Identität beeinflussen, was operativ und gelegentlich auch sicherheitsrelevant sein kann.

## Lab

Du kannst einen UTS Namespace erstellen mit:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Die Änderung des Hostnamens bleibt auf diesen Namespace beschränkt und verändert den globalen Hostnamen des Hosts nicht. Dies ist eine einfache, aber effektive Demonstration der Isolationseigenschaft.

## Laufzeitverwendung

Normale Container erhalten einen isolierten UTS-Namespace. Docker und Podman können über `--uts=host` dem UTS-Namespace des Hosts beitreten, und ähnliche Muster zur gemeinsamen Nutzung des Hosts können in anderen Runtimes und Orchestrierungssystemen auftreten. Meistens ist die private UTS-Isolation jedoch einfach Bestandteil der normalen Container-Konfiguration und erfordert nur wenig Aufmerksamkeit seitens des Operators.

## Sicherheitsauswirkungen

Obwohl der UTS-Namespace normalerweise nicht zu den gefährlichsten Namespaces gehört, die gemeinsam genutzt werden können, trägt er dennoch zur Integrität der Container-Grenze bei. Wenn der UTS-Namespace des Hosts exponiert ist und der Prozess über die erforderlichen Berechtigungen verfügt, kann er möglicherweise hostbezogene Informationen zum Hostnamen ändern. Dies kann sich auf Monitoring, Logging, betriebliche Annahmen oder Scripts auswirken, die Vertrauensentscheidungen auf Grundlage von Identitätsdaten des Hosts treffen.

## Missbrauch

Wenn der UTS-Namespace des Hosts gemeinsam genutzt wird, stellt sich praktisch die Frage, ob der Prozess die Identitätseinstellungen des Hosts ändern kann, statt sie nur zu lesen:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Wenn der Container außerdem über die erforderlichen Berechtigungen verfügt, teste, ob der Hostname geändert werden kann:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Dies ist in erster Linie ein Problem der Integrität und der betrieblichen Auswirkungen und kein vollständiger escape, zeigt jedoch weiterhin, dass der Container eine global für den Host geltende Eigenschaft direkt beeinflussen kann.

Auswirkungen:

- Manipulation der Host-Identität
- verwirrende Logs, Überwachung oder Automatisierung, die dem Hostnamen vertrauen
- normalerweise kein vollständiger escape allein, sofern er nicht mit anderen Schwachstellen kombiniert wird

In Docker-style-Umgebungen ist folgendes hostseitiges Erkennungsmuster nützlich:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Container mit `UTSMode=host` teilen den UTS-Namespace des Hosts und sollten sorgfältiger überprüft werden, wenn sie zusätzlich Capabilities besitzen, mit denen sie `sethostname()` oder `setdomainname()` aufrufen können.

## Prüfungen

Diese Befehle reichen aus, um festzustellen, ob die Workload eine eigene Ansicht des Hostnamens hat oder den UTS-Namespace des Hosts teilt.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Was hier interessant ist:

- Das Abgleichen von Namespace-IDs mit einem Host-Prozess kann auf eine gemeinsame UTS-Namespace mit dem Host hinweisen.
- Wenn das Ändern des Hostnamens mehr als nur den Container selbst betrifft, hat der Workload mehr Einfluss auf die Host-Identität, als er haben sollte.
- Dies ist in der Regel ein weniger dringlicher Befund als Probleme mit PID-, Mount- oder User-Namespaces, bestätigt aber dennoch, wie stark der Prozess tatsächlich isoliert ist.

In den meisten Umgebungen sollte die UTS-Namespace am besten als unterstützende Isolationsschicht betrachtet werden. Sie ist bei einem Breakout selten das Erste, wonach man sucht, gehört aber dennoch zur allgemeinen Konsistenz und Sicherheit der Containeransicht.
{{#include ../../../../../banners/hacktricks-training.md}}
