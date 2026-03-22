# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der UTS namespace isoliert den **hostname** und den **NIS domain name**, die vom Prozess gesehen werden. Auf den ersten Blick mag das im Vergleich zu mount, PID oder user namespaces trivial erscheinen, aber es ist ein Teil dessen, was einen container so erscheinen lässt, als wäre er ein eigener Host. Innerhalb des namespace kann die workload einen hostname sehen und manchmal ändern, der lokal für diesen namespace ist, statt global für die Maschine.

Alleinstehend ist das normalerweise nicht der Mittelpunkt einer breakout-Story. Sobald jedoch der host UTS namespace geteilt wird, kann ein ausreichend privilegierter Prozess host-Identitäts-bezogene Einstellungen beeinflussen, was operational und gelegentlich aus Sicht der Sicherheit relevant sein kann.

## Labor

Du kannst einen UTS namespace erstellen mit:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Die Änderung des Hostnamens bleibt lokal in diesem Namespace und verändert nicht den globalen Host-Hostname. Dies ist eine einfache, aber effektive Demonstration der Isolationseigenschaft.

## Laufzeitnutzung

Normale Container erhalten einen isolierten UTS namespace. Docker und Podman können über `--uts=host` dem host UTS namespace beitreten, und ähnliche Host-Sharing-Muster können in anderen runtimes und Orchestrierungssystemen auftreten. Meistens ist die private UTS-Isolierung jedoch einfach Teil der normalen Container-Konfiguration und erfordert wenig Aufmerksamkeit des Operators.

## Sicherheitsauswirkung

Auch wenn der UTS namespace normalerweise nicht der gefährlichste Namespace ist, den man teilen kann, trägt er dennoch zur Integrität der Container-Grenze bei. Wenn der host UTS namespace offengelegt ist und der Prozess über die notwendigen Privilegien verfügt, kann er möglicherweise hostname-bezogene Informationen des Hosts ändern. Das kann Monitoring, Logging, operative Annahmen oder Skripte beeinflussen, die Vertrauensentscheidungen auf Basis von Host-Identitätsdaten treffen.

## Missbrauch

Wenn der host UTS namespace geteilt wird, lautet die praktische Frage, ob der Prozess die Host-Identitätseinstellungen ändern kann, statt sie nur zu lesen:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Wenn der Container außerdem das erforderliche Privileg hat, teste, ob der Hostname geändert werden kann:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Dies ist primär ein Integritäts- und betrieblicher Auswirkungsfall und kein vollständiger Escape, zeigt aber dennoch, dass der Container eine hostweite Eigenschaft direkt beeinflussen kann.

Auswirkungen:

- Manipulation der Host-Identität
- Verwirrende Logs, Monitoring oder Automatisierung, die dem Hostname vertrauen
- in der Regel kein vollständiger Escape für sich allein, außer in Kombination mit anderen Schwachstellen

In Docker-style-Umgebungen ist ein nützliches hostseitiges Erkennungsmuster:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Container, die `UTSMode=host` anzeigen, teilen den UTS-Namespace des Hosts und sollten sorgfältiger geprüft werden, wenn sie auch capabilities besitzen, die es ihnen erlauben, `sethostname()` oder `setdomainname()` aufzurufen.

## Überprüfungen

Diese Befehle reichen aus, um zu sehen, ob die Workload ihre eigene Hostname-Ansicht hat oder den UTS-Namespace des Hosts teilt.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
- Das Abgleichen von Namespace-Identifikatoren mit einem Host-Prozess kann auf eine gemeinsame Nutzung des Host-UTS hindeuten.
- Wenn das Ändern des Hostnames mehr als nur den Container betrifft, hat die Workload mehr Einfluss auf die Host-Identität, als sie haben sollte.
- Dies ist normalerweise ein weniger hoch priorisierter Befund als Probleme mit PID, mount oder user namespace, bestätigt aber trotzdem, wie isoliert der Prozess tatsächlich ist.

In den meisten Umgebungen sollte der UTS namespace eher als unterstützende Isolationsebene betrachtet werden. Er ist selten das Erste, dem man bei einem breakout nachgeht, gehört aber dennoch zur Gesamtkonsistenz und -sicherheit der container view.
{{#include ../../../../../banners/hacktricks-training.md}}
