# Image-Sicherheit, Signierung und Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Container-Sicherheit beginnt, bevor die Workload gestartet wird. Das Image bestimmt, welche Binaries, Interpreter, Bibliotheken, Startskripte und eingebetteten Konfigurationen die Produktionsumgebung erreichen. Wenn das Image eine Backdoor enthält, veraltet ist oder mit fest integrierten Secrets erstellt wurde, arbeitet die anschließende Runtime-Härtung bereits mit einem kompromittierten Artefakt.

Deshalb gehören Image-Provenance, Vulnerability Scanning, Signature Verification und der Umgang mit Secrets in dasselbe Gespräch wie Namespaces und seccomp. Sie schützen eine andere Phase des Lebenszyklus, aber Fehler an dieser Stelle bestimmen häufig die Angriffsfläche, die die Runtime später eindämmen muss.

## Image-Registries und Trust

Images können aus öffentlichen Registries wie Docker Hub oder aus privaten Registries stammen, die von einer Organisation betrieben werden. Die Sicherheitsfrage ist nicht einfach, wo das Image gespeichert ist, sondern ob das Team Provenance und Integrität feststellen kann. Das Abrufen unsignierter oder schlecht nachverfolgter Images aus öffentlichen Quellen erhöht das Risiko, dass bösartige oder manipulierte Inhalte in die Produktionsumgebung gelangen. Auch intern gehostete Registries benötigen klare Zuständigkeiten, Reviews und eine Trust Policy.

Docker Content Trust verwendete historisch die Konzepte von Notary und TUF, um signierte Images zu verlangen. Das genaue Ökosystem hat sich weiterentwickelt, aber die grundlegende Erkenntnis bleibt nützlich: Image-Identität und -Integrität sollten verifizierbar sein, statt vorausgesetzt zu werden.

Beispiel für einen historischen Docker-Content-Trust-Workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Der Punkt des Beispiels ist nicht, dass jedes Team weiterhin dieselben Tools verwenden muss, sondern dass Signierung und Schlüsselverwaltung operative Aufgaben und keine abstrakte Theorie sind.

## Schwachstellen-Scanning

Image-Scanning hilft dabei, zwei unterschiedliche Fragen zu beantworten. Erstens: Enthält das Image bekannte verwundbare Pakete oder Bibliotheken? Zweitens: Enthält das Image unnötige Software, die die Angriffsfläche vergrößert? Ein Image voller Debugging-Tools, Shells, Interpreter und veralteter Pakete ist sowohl leichter auszunutzen als auch schwieriger zu beurteilen.

Beispiele für häufig verwendete Scanner sind:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Ergebnisse aus diesen Tools sollten sorgfältig interpretiert werden. Eine Schwachstelle in einem nicht verwendeten Paket ist hinsichtlich des Risikos nicht gleichbedeutend mit einem exponierten RCE-Pfad, aber beide sind für Hardening-Entscheidungen weiterhin relevant.

## Secrets zur Build-Zeit

Einer der ältesten Fehler in Container-Build-Pipelines besteht darin, Secrets direkt in das Image einzubetten oder sie über Umgebungsvariablen weiterzugeben, die später über `docker inspect`, Build-Logs oder wiederhergestellte Layer sichtbar werden. Secrets zur Build-Zeit sollten während des Builds vorübergehend eingebunden werden, anstatt sie in das Dateisystem des Images zu kopieren.

BuildKit hat dieses Modell verbessert, indem es eine dedizierte Handhabung von Secrets zur Build-Zeit ermöglicht. Statt ein Secret in einen Layer zu schreiben, kann der Build-Schritt es vorübergehend verwenden:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Das ist wichtig, weil Image-Layer dauerhafte Artefakte sind. Sobald ein Secret in einem committeten Layer enthalten ist, wird die ursprüngliche Offenlegung durch das spätere Löschen der Datei in einem anderen Layer nicht wirklich aus der Image-Historie entfernt.

## Runtime-Secrets

Secrets, die von einem laufenden Workload benötigt werden, sollten nach Möglichkeit ebenfalls nicht über Ad-hoc-Muster wie einfache Umgebungsvariablen bereitgestellt werden. Volumes, dedizierte Secret-Management-Integrationen, Docker secrets und Kubernetes Secrets sind gängige Mechanismen. Keiner dieser Mechanismen beseitigt alle Risiken, insbesondere wenn der Angreifer bereits Codeausführung im Workload besitzt. Sie sind jedoch weiterhin besser, als Credentials dauerhaft im Image zu speichern oder sie unbedacht über Inspektions-Tools offenzulegen.

Eine einfache Secret-Deklaration im Docker-Compose-Stil sieht folgendermaßen aus:
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
In Kubernetes schaffen Secret-Objekte, projizierte Volumes, Service-Account-Tokens und Cloud-Workload-Identitäten ein umfassenderes und leistungsfähigeres Modell, bieten jedoch auch mehr Möglichkeiten für versehentliche Offenlegung durch Host-Mounts, weitreichendes RBAC oder ein schwaches Pod-Design.

## Missbrauch

Bei der Untersuchung eines Ziels besteht das Ziel darin festzustellen, ob Secrets in das Image eingebaut, in Layers geleakt oder in vorhersehbare Laufzeitverzeichnisse eingehängt wurden:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Diese Befehle helfen dabei, drei verschiedene Probleme zu unterscheiden: application configuration leaks, image-layer leaks und zur Laufzeit injizierte Secret-Dateien. Wenn ein Secret unter `/run/secrets`, in einem projected volume oder unter einem Pfad für Cloud-Identitätstoken erscheint, besteht der nächste Schritt darin zu verstehen, ob es nur Zugriff auf den aktuellen Workload oder auf eine wesentlich größere Control Plane gewährt.

### Vollständiges Beispiel: Eingebettetes Secret im Image-Dateisystem

Wenn eine Build-Pipeline `.env`-Dateien oder Zugangsdaten in das finale Image kopiert hat, wird post-exploitation einfach:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Die Auswirkungen hängen von der Anwendung ab, aber eingebettete Signing Keys, JWT-Secrets oder Cloud-Credentials können eine Container-Kompromittierung leicht in eine API-Kompromittierung, lateral movement oder die Fälschung vertrauenswürdiger Application-Tokens verwandeln.

### Full Example: Build-Time Secret Leakage Check

Wenn die Sorge besteht, dass die Image-Historie einen Layer mit einem Secret erfasst hat:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Diese Art der Prüfung ist nützlich, da ein Secret möglicherweise aus der endgültigen Dateisystemansicht gelöscht wurde, aber weiterhin in einer früheren Ebene oder in Build-Metadaten vorhanden ist.

## Prüfungen

Diese Prüfungen sollen feststellen, ob die Image- und Secret-Verarbeitungspipeline die Angriffsfläche vor der Laufzeit wahrscheinlich vergrößert hat.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Was ist hier interessant:

- Eine verdächtige Build-Historie kann kopierte Credentials, SSH-Material oder unsichere Build-Schritte offenlegen.
- Secrets unter Pfaden für projected volumes können zu Cluster- oder Cloud-Zugriff führen, nicht nur zu lokalem Anwendungszugriff.
- Eine große Anzahl von Konfigurationsdateien mit Credentials im Klartext deutet meist darauf hin, dass das Image oder das Deployment-Modell mehr Vertrauensmaterial enthält als nötig.

## Laufzeitstandards

| Laufzeit / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Schwächung |
| --- | --- | --- | --- |
| Docker / BuildKit | Unterstützt sichere Secret-Mounts zur Build-Zeit, jedoch nicht automatisch | Secrets können während `build` flüchtig eingehängt werden; Image-Signierung und -Scanning erfordern explizite Workflow-Entscheidungen | Kopieren von Secrets in das Image, Übergeben von Secrets über `ARG` oder `ENV`, Deaktivieren von Provenance-Prüfungen |
| Podman / Buildah | Unterstützt OCI-native Builds und Secret-bewusste Workflows | Starke Build-Workflows sind verfügbar, aber Betreiber müssen sie weiterhin bewusst auswählen | Einbetten von Secrets in Containerfiles, weit gefasste Build-Kontexte, freizügige Bind-Mounts während Builds |
| Kubernetes | Native Secret-Objekte und projected volumes | Die Bereitstellung von Secrets zur Laufzeit ist ein First-Class-Feature, aber die Offenlegung hängt von RBAC, dem Pod-Design und Host-Mounts ab | Zu weit gefasste Secret-Mounts, Missbrauch von Service-Account-Tokens, `hostPath`-Zugriff auf vom Kubelet verwaltete Volumes |
| Registries | Integrität ist optional, sofern sie nicht erzwungen wird | Öffentliche und private Registries hängen gleichermaßen von Richtlinien, Signierung und Admission-Entscheidungen ab | Uneingeschränktes Abrufen unsignierter Images, schwache Admission-Kontrolle, schlechtes Schlüsselmanagement |
{{#include ../../../banners/hacktricks-training.md}}
