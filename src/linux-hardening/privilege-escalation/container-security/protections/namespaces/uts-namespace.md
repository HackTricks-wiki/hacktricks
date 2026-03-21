# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der UTS namespace isoliert den vom Prozess gesehenen **hostname** und **NIS domain name**. Auf den ersten Blick mag das im Vergleich zu mount-, PID- oder user-namespaces trivial erscheinen, aber es ist ein Bestandteil dessen, was einen container wie einen eigenen Host erscheinen lässt. Innerhalb des namespace kann die workload einen **hostname** sehen und manchmal ändern, der lokal für diesen Namespace ist statt global für die Maschine.

Allein betrachtet ist das in der Regel nicht der zentrale Punkt einer breakout story. Sobald jedoch der host UTS namespace geteilt wird, kann ein ausreichend privilegierter Prozess host identity-related settings beeinflussen, was operational wichtig sein kann und gelegentlich auch aus Sicherheitsgründen relevant ist.

## Labor

Du kannst einen UTS namespace mit:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Die Änderung des Hostnamens bleibt lokal in diesem UTS namespace und ändert nicht den globalen Hostnamen des Hosts. Das ist eine einfache, aber effektive Demonstration der Isolationseigenschaft.

## Laufzeitnutzung

Normale Container erhalten ein isoliertes UTS namespace. Docker und Podman können dem host UTS namespace über `--uts=host` beitreten, und ähnliche Host-Sharing-Muster können in anderen Runtimes und Orchestrationssystemen auftreten. Die meiste Zeit ist die private UTS-Isolierung jedoch einfach Teil der normalen Container-Konfiguration und erfordert nur wenig Aufmerksamkeit des Operators.

## Sicherheitsauswirkungen

Auch wenn das UTS namespace normalerweise nicht das gefährlichste zum Teilen ist, trägt es dennoch zur Integrität der Container-Grenze bei. Wenn das host UTS namespace exponiert ist und der Prozess über die notwendigen Privilegien verfügt, kann er möglicherweise host-bezogene Hostname-Informationen ändern. Das kann monitoring, logging, betriebliche Annahmen oder Skripte beeinflussen, die Vertrauensentscheidungen auf Basis von Host-Identitätsdaten treffen.

## Missbrauch

Wenn das host UTS namespace geteilt wird, ist die praktische Frage, ob der Prozess host-Identitätseinstellungen ändern kann, statt sie nur zu lesen:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Wenn der container außerdem das notwendige privilege hat, testen Sie, ob der hostname geändert werden kann:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Dies ist in erster Linie ein Integritäts- und betriebliches Problem mit Auswirkungen und kein vollständiger escape, zeigt aber dennoch, dass der container direkt eine host-global property beeinflussen kann.

Auswirkungen:

- Manipulation der host-Identität
- Verwirrung von logs, monitoring oder automation, die dem hostname vertrauen
- in der Regel kein vollständiger escape für sich allein, es sei denn, er wird mit anderen Schwachstellen kombiniert

In Docker-style-Umgebungen ist ein nützliches host-side detection pattern:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Container, die `UTSMode=host` anzeigen, teilen das UTS-Namespace des Hosts und sollten genauer überprüft werden, wenn sie außerdem capabilities besitzen, die ihnen erlauben, `sethostname()` oder `setdomainname()` aufzurufen.

## Prüfungen

Diese Befehle reichen aus, um zu sehen, ob die Workload ihre eigene Hostname-Ansicht hat oder das UTS-Namespace des Hosts teilt.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
- Das Abgleichen von Namespace-IDs mit einem Host-Prozess kann auf UTS-Sharing mit dem Host hinweisen.
- Wenn das Ändern des Hostnamens mehr als nur den Container beeinflusst, hat die Workload größeren Einfluss auf die Host-Identität, als sie haben sollte.
- Dies ist in der Regel ein Befund mit geringerer Priorität als Probleme in PID-, mount- oder user-Namespaces, bestätigt jedoch trotzdem, wie isoliert der Prozess tatsächlich ist.

In den meisten Umgebungen sollte der UTS-Namespace eher als unterstützende Isolationsebene betrachtet werden. Er ist selten das Erste, wonach man bei einem breakout sucht, gehört aber trotzdem zur Gesamt-Konsistenz und Sicherheit der Container-Ansicht.
