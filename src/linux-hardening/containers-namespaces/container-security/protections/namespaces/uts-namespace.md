# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der UTS-Namespace isoliert den **hostname** und den **NIS domain name**, die vom Prozess gesehen werden. Auf den ersten Blick mag dies im Vergleich zu Mount-, PID- oder User-Namespaces trivial erscheinen, aber er ist Teil dessen, was einen Container wie einen eigenen Host erscheinen lässt. Innerhalb des Namespace kann die Workload einen hostname sehen und manchmal ändern, der auf diesen Namespace beschränkt ist und nicht global für die Maschine gilt.

Für sich genommen ist dies normalerweise nicht der Mittelpunkt einer Breakout-Story. Wenn jedoch der UTS-Namespace des Hosts geteilt wird, kann ein ausreichend privilegierter Prozess möglicherweise Einstellungen zur Host-Identität beeinflussen, was betrieblich und gelegentlich auch sicherheitsrelevant sein kann.

## Labor

Du kannst einen UTS-Namespace erstellen mit:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Die Änderung des Hostnamens bleibt auf diesen Namespace beschränkt und verändert den globalen Hostnamen des Hosts nicht. Dies ist eine einfache, aber effektive Demonstration der Isolationseigenschaft.

## Verwendung zur Laufzeit

Normale Container erhalten einen isolierten UTS-Namespace. Docker und Podman können über `--uts=host` dem UTS-Namespace des Hosts beitreten, und ähnliche Muster zur gemeinsamen Nutzung des Hosts können in anderen Runtimes und Orchestrierungssystemen auftreten. Meistens ist die private UTS-Isolation jedoch einfach Bestandteil der normalen Containerkonfiguration und erfordert wenig Aufmerksamkeit seitens des Operators.

## Sicherheitsauswirkungen

Obwohl der UTS-Namespace normalerweise nicht zu den gefährlichsten Namespaces gehört, die gemeinsam genutzt werden können, trägt er dennoch zur Integrität der Container-Grenze bei. Wenn der UTS-Namespace des Hosts offengelegt ist und der Prozess über die erforderlichen Berechtigungen verfügt, kann er möglicherweise Hostname-bezogene Informationen des Hosts ändern. Dies kann sich auf Monitoring, Logging, betriebliche Annahmen oder Skripte auswirken, die Vertrauensentscheidungen anhand von Identitätsdaten des Hosts treffen.

## Missbrauch

Wenn der UTS-Namespace des Hosts gemeinsam genutzt wird, stellt sich praktisch die Frage, ob der Prozess die Identitätseinstellungen des Hosts ändern kann, anstatt sie nur zu lesen:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Wenn der Container auch über das erforderliche Privileg verfügt, teste, ob der Hostname geändert werden kann:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Dies ist in erster Linie ein Problem der Integrität und der betrieblichen Auswirkungen und kein vollständiger escape. Es zeigt jedoch weiterhin, dass der Container eine global für den Host geltende Eigenschaft direkt beeinflussen kann.

Auswirkungen:

- Manipulation der Host-Identität
- verwirrende Logs, Überwachung oder Automatisierung, die dem Hostnamen vertrauen
- für sich genommen normalerweise kein vollständiger escape, sofern keine weiteren Schwachstellen hinzukommen

In Docker-ähnlichen Umgebungen ist folgendes hostseitiges Erkennungsmuster hilfreich:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Container mit `UTSMode=host` teilen sich den UTS-Namespace des Hosts und sollten genauer überprüft werden, wenn sie außerdem über Capabilities verfügen, mit denen sie `sethostname()` oder `setdomainname()` aufrufen können.

## Prüfungen

Mit diesen Befehlen lässt sich feststellen, ob der Workload eine eigene Hostname-Sicht besitzt oder den UTS-Namespace des Hosts teilt.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Was ist hier interessant:

- Übereinstimmende Namespace-Kennungen mit einem Host-Prozess können auf eine gemeinsame UTS-Namespace mit dem Host hinweisen.
- Wenn das Ändern des Hostnamens mehr als nur den Container betrifft, hat der Workload mehr Einfluss auf die Host-Identität, als er sollte.
- Dies ist normalerweise ein Befund mit niedrigerer Priorität als Probleme mit PID-, Mount- oder User-Namespaces, bestätigt aber dennoch, wie isoliert der Prozess tatsächlich ist.

In den meisten Umgebungen sollte die UTS-Namespace am besten als unterstützende Isolationsschicht betrachtet werden. Sie ist bei einem Breakout nur selten das Erste, wonach man sucht, ist aber weiterhin Teil der allgemeinen Konsistenz und Sicherheit der Container-Sicht.

{{#include ../../../../../banners/hacktricks-training.md}}
