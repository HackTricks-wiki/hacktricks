# Image-Sicherheit, Signierung und Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Die Sicherheit von Containern beginnt, bevor der Workload gestartet wird. Das Image bestimmt, welche Binaries, Interpreter, Bibliotheken, Startskripte und eingebetteten Konfigurationen die Produktionsumgebung erreichen. Wenn das Image mit einer Backdoor versehen oder veraltet ist oder mit fest eingebauten Secrets erstellt wurde, arbeitet die anschließende Runtime-Härtung bereits mit einem kompromittierten Artefakt.

Aus diesem Grund gehören die Herkunft von Images, das Scannen auf Schwachstellen, die Überprüfung von Signaturen und der Umgang mit Secrets in dasselbe Gespräch wie Namespaces und seccomp. Sie schützen eine andere Phase des Lebenszyklus, aber Fehler in diesem Bereich bestimmen häufig die Angriffsfläche, die die Runtime später eindämmen muss.

## Image-Registries und Vertrauen

Images können aus öffentlichen Registries wie Docker Hub oder aus privaten Registries stammen, die von einer Organisation betrieben werden. Die Sicherheitsfrage lautet nicht einfach, wo das Image gespeichert ist, sondern ob das Team Herkunft und Integrität nachweisen kann. Das Herunterladen unsignierter oder unzureichend nachverfolgter Images aus öffentlichen Quellen erhöht das Risiko, dass schädliche oder manipulierte Inhalte in die Produktionsumgebung gelangen. Auch intern gehostete Registries benötigen klare Verantwortlichkeiten, Prüfprozesse und eine Vertrauensrichtlinie.

Docker Content Trust verwendete historisch Notary- und TUF-Konzepte, um signierte Images vorauszusetzen. Das genaue Ökosystem hat sich weiterentwickelt, aber die grundlegende Erkenntnis bleibt nützlich: Die Identität und Integrität eines Images sollten überprüfbar sein, statt vorausgesetzt zu werden.

Beispiel für einen historischen Docker-Content-Trust-Workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Der Punkt des Beispiels ist nicht, dass jedes Team weiterhin dieselben Tools verwenden muss, sondern dass Signieren und Schlüsselverwaltung operative Aufgaben und keine abstrakte Theorie sind.

## Schwachstellen-Scanning

Image-Scanning hilft bei der Beantwortung zweier verschiedener Fragen. Enthält das Image erstens bekannte verwundbare Pakete oder Bibliotheken? Enthält das Image zweitens unnötige Software, die die Angriffsfläche vergrößert? Ein Image voller Debugging-Tools, Shells, Interpreter und veralteter Pakete ist sowohl leichter auszunutzen als auch schwieriger einzuschätzen.

Beispiele für häufig verwendete Scanner sind:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Ergebnisse aus diesen Tools sollten sorgfältig interpretiert werden. Eine Vulnerability in einem nicht verwendeten Package ist hinsichtlich des Risikos nicht mit einem exponierten RCE-Pfad identisch, aber beide sind für Hardening-Entscheidungen weiterhin relevant.

## Secrets zur Build-Zeit

Einer der ältesten Fehler in Container-Build-Pipelines besteht darin, Secrets direkt in das Image einzubetten oder sie über Environment-Variablen zu übergeben, die später durch `docker inspect`, Build-Logs oder wiederhergestellte Layer sichtbar werden. Secrets zur Build-Zeit sollten während des Builds temporär gemountet werden, anstatt sie in das Image-Dateisystem zu kopieren.

BuildKit verbesserte dieses Modell, indem es eine dedizierte Verarbeitung von Secrets zur Build-Zeit ermöglicht. Anstatt ein Secret in eine Layer zu schreiben, kann der Build-Schritt es vorübergehend verwenden:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Das ist wichtig, weil Image-Layer dauerhafte Artefakte sind. Sobald ein Secret in einem committeten Layer enthalten ist, wird die ursprüngliche Offenlegung durch das spätere Löschen der Datei in einem anderen Layer nicht wirklich aus der Image-Historie entfernt.

## Secrets zur Laufzeit

Secrets, die von einem laufenden Workload benötigt werden, sollten nach Möglichkeit ebenfalls nicht über Ad-hoc-Muster wie einfache Umgebungsvariablen bereitgestellt werden. Volumes, dedizierte Secret-Management-Integrationen, Docker secrets und Kubernetes Secrets sind gängige Mechanismen. Keiner dieser Mechanismen beseitigt sämtliche Risiken, insbesondere wenn der Angreifer bereits Codeausführung im Workload besitzt. Sie sind jedoch weiterhin vorzuziehen, gegenüber der dauerhaften Speicherung von Zugangsdaten im Image oder ihrer unbedachten Offenlegung durch Inspection-Tools.

Eine einfache Secret-Deklaration im Docker-Compose-Stil sieht so aus:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
In Kubernetes bilden Secret-Objekte, projected volumes, Service-Account-Tokens und cloud workload identities ein umfassenderes und leistungsfähigeres Modell, schaffen aber auch mehr Möglichkeiten für eine versehentliche Offenlegung durch Host-Mounts, weitreichendes RBAC oder ein schwaches Pod-Design.

## Missbrauch

Bei der Überprüfung eines Ziels besteht das Ziel darin festzustellen, ob Secrets in das Image eingebettet, in Layern geleakt oder an vorhersehbaren Laufzeitpfaden eingebunden wurden:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Diese Befehle helfen dabei, drei verschiedene Probleme zu unterscheiden: Leaks durch die Anwendungskonfiguration, Leaks in Image-Layern und zur Laufzeit injizierte Secret-Dateien. Wenn ein Secret unter `/run/secrets`, in einem projected volume oder unter einem Cloud-Identity-Token-Pfad erscheint, besteht der nächste Schritt darin zu verstehen, ob es nur Zugriff auf den aktuellen Workload oder auf eine wesentlich größere Control Plane gewährt.

### Vollständiges Beispiel: Eingebettetes Secret im Image-Dateisystem

Wenn eine Build-Pipeline `.env`-Dateien oder Zugangsdaten in das finale Image kopiert hat, wird die Post-Exploitation einfach:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Die Auswirkungen hängen von der Anwendung ab, aber eingebettete Signaturschlüssel, JWT-Geheimnisse oder Cloud-Zugangsdaten können eine Container-Kompromittierung leicht in eine API-Kompromittierung, Seitwärtsbewegung oder Fälschung vertrauenswürdiger Anwendungstoken verwandeln.

### Vollständiges Beispiel: Prüfung auf Secret-Leaks zur Build-Zeit

Wenn die Sorge besteht, dass die Image-Historie eine Layer mit einem Secret erfasst hat:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Diese Art der Überprüfung ist nützlich, weil ein Secret möglicherweise aus der endgültigen Dateisystemansicht gelöscht wurde, während es weiterhin in einer früheren Layer oder in Build-Metadaten vorhanden ist.

## Prüfungen

Mit diesen Prüfungen soll festgestellt werden, ob die Image- und Secret-Handling-Pipeline die Angriffsfläche vor der Laufzeit wahrscheinlich vergrößert hat.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Was ist hier interessant:

- Eine verdächtige Build-Historie kann kopierte Zugangsdaten, SSH-Material oder unsichere Build-Schritte offenlegen.
- Secrets unter Pfaden für projizierte Volumes können zu Cluster- oder Cloud-Zugriff führen, nicht nur zum Zugriff auf die lokale Anwendung.
- Eine große Anzahl von Konfigurationsdateien mit Zugangsdaten im Klartext weist normalerweise darauf hin, dass das Image oder das Deployment-Modell mehr Vertrauensmaterial mit sich führt als notwendig.

## Laufzeit-Standards

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Schwächung |
| --- | --- | --- | --- |
| Docker / BuildKit | Unterstützt sichere Secret-Mounts zur Build-Zeit, jedoch nicht automatisch | Secrets können während des `build` flüchtig gemountet werden; Image-Signierung und -Scanning erfordern explizite Workflow-Entscheidungen | Secrets in das Image kopieren, Secrets über `ARG` oder `ENV` übergeben, Provenance-Prüfungen deaktivieren |
| Podman / Buildah | Unterstützt OCI-native Builds und Secret-bewusste Workflows | Starke Build-Workflows sind verfügbar, aber Betreiber müssen sie weiterhin bewusst auswählen | Secrets in Containerfiles einbetten, weit gefasste Build-Kontexte, freizügige Bind-Mounts während Builds |
| Kubernetes | Native Secret-Objekte und projizierte Volumes | Die Bereitstellung von Secrets zur Laufzeit ist eine Kernfunktion, aber die Offenlegung hängt von RBAC, Pod-Design und Host-Mounts ab | Zu weit gefasste Secret-Mounts, Missbrauch von Service-Account-Tokens, `hostPath`-Zugriff auf vom kubelet verwaltete Volumes |
| Registries | Integrität ist optional, sofern sie nicht erzwungen wird | Öffentliche und private Registries hängen gleichermaßen von Richtlinien, Signierung und Admission-Entscheidungen ab | Unsigned Images unkontrolliert abrufen, schwache Admission-Kontrolle, schlechtes Schlüsselmanagement |

{{#include ../../../banners/hacktricks-training.md}}
