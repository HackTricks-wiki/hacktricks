# Image-Sicherheit, Signierung und Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Container-Sicherheit beginnt, bevor der Workload gestartet wird. Das Image bestimmt, welche Binaries, Interpreter, Libraries, Startskripte und eingebetteten Konfigurationen in die Produktion gelangen. Wenn das Image eine Backdoor enthält, veraltet ist oder mit eingebetteten Secrets gebaut wurde, arbeitet die anschließende Runtime-Härtung bereits auf einem kompromittierten Artefakt.

Deshalb gehören Image-Provenienz, Vulnerability-Scanning, Signaturprüfung und Secret-Handling in dieselbe Diskussion wie Namespaces und seccomp. Sie schützen eine andere Phase des Lebenszyklus, aber Fehler an dieser Stelle definieren oft die Angriffsfläche, die die Runtime später einschränken muss.

## Image Registries und Vertrauen

Images können aus öffentlichen Registries wie Docker Hub oder aus von einer Organisation betriebenen privaten Registries stammen. Die Sicherheitsfrage ist nicht nur, wo das Image liegt, sondern ob das Team Provenienz und Integrität nachweisen kann. Das Ziehen unsignierter oder schlecht nachverfolgter Images aus öffentlichen Quellen erhöht das Risiko, dass bösartige oder manipulierte Inhalte in die Produktion gelangen. Auch intern gehostete Registries benötigen klare Zuständigkeiten, Reviews und eine Vertrauensrichtlinie.

Docker Content Trust historisch nutzte Konzepte von Notary und TUF, um signierte Images zu verlangen. Das genaue Ökosystem hat sich weiterentwickelt, aber die bleibende Lehre ist nützlich: Image-Identität und Integrität sollten verifizierbar sein, statt sie anzunehmen.

Beispiel für einen historischen Docker Content Trust-Workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Der Punkt des Beispiels ist nicht, dass jedes Team weiterhin dasselbe tooling verwenden muss, sondern dass Signing und Key-Management operative Aufgaben sind, keine abstrakte Theorie.

## Schwachstellenscanning

Image-Scanning hilft, zwei unterschiedliche Fragen zu beantworten. Erstens: Enthält das Image bekannte verwundbare Pakete oder Bibliotheken? Zweitens: Enthält das Image unnötige Software, die die Angriffsfläche vergrößert? Ein Image, das voller debugging tools, shells, interpreters und veralteter Pakete ist, ist sowohl leichter auszunutzen als auch schwerer zu durchschauen.

Beispiele für häufig verwendete Scanner sind:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Ergebnisse dieser Tools sollten vorsichtig interpretiert werden. Eine Schwachstelle in einem ungenutzten Paket ist nicht gleichzusetzen mit einem offenliegenden RCE-Pfad, aber beide sind dennoch relevant für Hardening-Entscheidungen.

## Build-Zeit-Secrets

Einer der ältesten Fehler in Container-Build-Pipelines ist, Secrets direkt in das Image einzubetten oder sie über Umgebungsvariablen zu übergeben, die später über `docker inspect`, Build-Logs oder wiederhergestellte Layer sichtbar werden. Build-Zeit-Secrets sollten während des Builds temporär gemountet werden, statt in das Image-Dateisystem kopiert zu werden.

BuildKit hat dieses Modell verbessert, indem es eine dedizierte Handhabung von Build-Zeit-Secrets ermöglicht. Anstatt ein Secret in eine Layer zu schreiben, kann der Build-Schritt es vorübergehend konsumieren:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Das ist wichtig, weil Image-Layer dauerhafte Artefakte sind. Sobald ein Secret in eine festgeschriebene Schicht gelangt, entfernt das spätere Löschen der Datei in einer anderen Schicht die ursprüngliche Offenlegung nicht wirklich aus der Image-Historie.

## Laufzeit-Secrets

Für Secrets, die eine laufende Workload benötigt, sollte man ebenfalls ad-hoc-Muster wie einfache Umgebungsvariablen möglichst vermeiden. Volumes, dedizierte Secret-Management-Integrationen, Docker secrets und Kubernetes Secrets sind gängige Mechanismen. Keiner davon beseitigt alle Risiken, insbesondere wenn ein Angreifer bereits Codeausführung in der Workload hat; trotzdem sind sie vorzuziehen gegenüber dem dauerhaften Ablegen von Zugangsdaten im Image oder dem lässigen Offenlegen über Inspektionstools.

Eine einfache Docker Compose-artige Secret-Deklaration sieht so aus:
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
In Kubernetes erzeugen Secret objects, projected volumes, service-account tokens und cloud workload identities ein breiteres und leistungsfähigeres Modell, aber sie schaffen auch mehr Möglichkeiten für versehentliche Exposition durch host mounts, breites RBAC oder schwaches Pod-Design.

## Missbrauch

Bei der Überprüfung eines Ziels geht es darum herauszufinden, ob secrets ins Image eingebrannt wurden, leaked in die layers oder in vorhersehbare runtime-Locations gemountet wurden:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Diese Befehle helfen dabei, zwischen drei verschiedenen Problemen zu unterscheiden: application configuration leaks, image-layer leaks und runtime-injected secret files. Wenn ein secret unter `/run/secrets`, einem projected volume oder einem cloud identity token path erscheint, besteht der nächste Schritt darin zu klären, ob es nur Zugriff auf den aktuellen workload gewährt oder auf eine wesentlich größere control plane.

### Vollständiges Beispiel: Embedded Secret In Image Filesystem

Wenn eine build pipeline `.env`-Dateien oder credentials in das finale Image kopiert hat, wird post-exploitation einfach:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Die Auswirkungen hängen von der Anwendung ab, aber eingebettete Signierschlüssel, JWT-Secrets oder Cloud-Zugangsdaten können eine Kompromittierung eines Containers leicht in eine API-Kompromittierung, lateral movement oder in die Fälschung vertrauenswürdiger Anwendungstokens verwandeln.

### Vollständiges Beispiel: Build-Time Secret Leakage Check

Wenn die Befürchtung besteht, dass die Image-History eine Secret-enthaltende Schicht erfasst hat:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Diese Art der Überprüfung ist nützlich, weil ein Secret aus der finalen Dateisystemansicht gelöscht worden sein kann, während es noch in einer früheren Schicht oder in den Build-Metadaten verbleibt.

## Prüfungen

Diese Prüfungen sollen feststellen, ob das Image und die Pipeline zur Handhabung von Secrets wahrscheinlich die Angriffsfläche vor der Laufzeit vergrößert haben.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Was hier interessant ist:

- Eine verdächtige Build-Historie kann kopierte Anmeldeinformationen, SSH-Material oder unsichere Build-Schritte offenbaren.
- Secrets unter projizierten Volume-Pfaden können zu Cluster- oder Cloud-Zugriff führen, nicht nur zu lokalem Anwendungszugriff.
- Eine große Anzahl von Konfigurationsdateien mit Klartext-Anmeldeinformationen weist normalerweise darauf hin, dass das Image oder das Deployment-Modell mehr vertrauliche Informationen als nötig trägt.

## Laufzeit-Standardeinstellungen

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Unterstützt sichere Build-Time-Secret-Mounts, aber nicht automatisch | Secrets können während des `build` flüchtig gemountet werden; Image-Signierung und -Scanning erfordern explizite Workflow-Entscheidungen | Kopieren von Secrets in das Image, Weitergeben von Secrets über `ARG` oder `ENV`, Deaktivieren von Provenance-Checks |
| Podman / Buildah | Unterstützt OCI-native Builds und secret-aware Workflows | Robuste Build-Workflows sind verfügbar, aber Operatoren müssen sie bewusst auswählen | Einbetten von Secrets in Containerfiles, breite Build-Kontexte, großzügige bind mounts während Builds |
| Kubernetes | Native Secret-Objekte und projizierte Volumes | Die Laufzeitbereitstellung von Secrets ist erstklassig, aber die Exposition hängt von RBAC, Pod-Design und Host-Mounts ab | Zu breite Secret-Mounts, Missbrauch von service-account Tokens, `hostPath`-Zugriff auf von kubelet verwaltete Volumes |
| Registries | Integrität ist optional, es sei denn, sie wird erzwungen | Öffentliche und private Registries hängen beide von Policy, Signierung und Admission-Entscheidungen ab | Freies Ziehen unsignierter Images, schwache Admission-Kontrolle, schlechtes Key-Management |
