# Image-Sicherheit, Signierung und Geheimnisse

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Container-Sicherheit beginnt, bevor die Workload gestartet wird. Das Image bestimmt, welche Binärdateien, Interpreter, Bibliotheken, Startskripte und eingebettete Konfiguration in die Produktion gelangen. Wenn das Image mit einer Backdoor versehen, veraltet oder mit eingebetteten Geheimnissen gebaut wurde, arbeitet die anschließende Runtime-Härtung bereits an einem kompromittierten Artefakt.

Deshalb gehören Image-Herkunft, Vulnerability-Scanning, Signaturverifikation und der Umgang mit Secrets in die gleiche Diskussion wie namespaces und seccomp. Sie schützen eine andere Phase des Lebenszyklus, aber Fehler an dieser Stelle bestimmen oft die Angriffsfläche, die die Runtime später eindämmen muss.

## Image-Registries und Vertrauen

Images können aus öffentlichen Registries wie Docker Hub oder aus privaten, von einer Organisation betriebenen Registries stammen. Die Sicherheitsfrage ist nicht nur, wo das Image liegt, sondern ob das Team Herkunft und Integrität feststellen kann. Das Herunterziehen unsignierter oder schlecht nachverfolgter Images aus öffentlichen Quellen erhöht das Risiko, dass bösartiger oder manipulierter Inhalt in die Produktion gelangt. Selbst intern gehostete Registries benötigen klare Zuständigkeiten, Review-Prozesse und eine Vertrauenspolitik.

Docker Content Trust verwendete historisch Notary- und TUF-Konzepte, um signierte Images zu erzwingen. Das genaue Ökosystem hat sich weiterentwickelt, aber die bleibende Lehre ist nützlich: Image-Identität und Integrität sollten verifizierbar sein, nicht vorausgesetzt.

Beispielhafter historischer Docker Content Trust-Workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Der Punkt des Beispiels ist nicht, dass jedes Team weiterhin dasselbe tooling verwenden muss, sondern dass signing und key management operative Aufgaben sind, keine abstrakte Theorie.

## Vulnerability Scanning

Image scanning hilft, zwei unterschiedliche Fragen zu beantworten. Erstens: Enthält das Image bekannte verwundbare packages oder libraries? Zweitens: Enthält das Image unnötige Software, die die attack surface vergrößert? Ein Image, das voller debugging tools, shells, interpreters und veralteter packages ist, ist sowohl leichter zu exploit-en als auch schwerer zu durchschauen.

Beispiele häufig verwendeter scanners sind:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Die Ergebnisse dieser Tools sollten sorgfältig interpretiert werden. Eine Schwachstelle in einem ungenutzten Paket ist nicht identisch im Risiko mit einem exponierten RCE-Pfad, aber beide sind dennoch relevant für Härtungsentscheidungen.

## Geheimnisse zur Build-Zeit

Einer der ältesten Fehler in Container-Build-Pipelines besteht darin, Geheimnisse direkt in das Image einzubetten oder sie über Umgebungsvariablen weiterzugeben, die später durch `docker inspect`, Build-Logs oder wiederhergestellte Layer sichtbar werden. Build-Zeit-Geheimnisse sollten während des Builds vorübergehend gemountet werden, anstatt in das Image-Dateisystem kopiert zu werden.

BuildKit verbesserte dieses Modell, indem es eine dedizierte Behandlung von Build-Zeit-Geheimnissen ermöglichte. Anstatt ein Geheimnis in einen Layer zu schreiben, kann der Build-Schritt es vorübergehend konsumieren:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Das ist wichtig, weil Image-Layer dauerhafte Artefakte sind. Sobald ein secret in einen festgeschriebenen Layer gelangt, entfernt das spätere Löschen der Datei in einem anderen Layer die ursprüngliche Offenlegung nicht wirklich aus der Image-Historie.

## Secrets zur Laufzeit

Secrets, die von einem laufenden Workload benötigt werden, sollten nach Möglichkeit auch ad-hoc-Muster wie einfache Umgebungsvariablen vermeiden. Volumes, dedizierte Secret-Management-Integrationen, Docker secrets und Kubernetes Secrets sind gängige Mechanismen. Keiner dieser Ansätze beseitigt alle Risiken, besonders wenn ein Angreifer bereits Code-Ausführung im Workload hat, aber sie sind dennoch dem permanenten Speichern von Zugangsdaten im Image oder deren beiläufiger Offenlegung durch Inspektionstools vorzuziehen.

Eine einfache Docker Compose style secret declaration sieht so aus:
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
In Kubernetes schaffen Secret objects, projected volumes, service-account tokens und cloud workload identities ein breiteres und leistungsfähigeres Modell, erhöhen aber gleichzeitig die Chancen für eine versehentliche Exposition durch host mounts, broad RBAC oder weak Pod design.

## Missbrauch

Beim Überprüfen eines Ziels besteht das Ziel darin herauszufinden, ob secrets ins Image eingebacken wurden, leaked in die Layers wurden oder in vorhersehbare Laufzeitorte gemountet wurden:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Diese Befehle helfen, zwischen drei verschiedenen Problemen zu unterscheiden: Anwendungskonfigurations-leaks, Image-Layer-leaks und zur Laufzeit injizierten Secret-Dateien. Wenn ein Secret unter `/run/secrets`, in einem projected volume oder in einem cloud identity token path auftaucht, besteht der nächste Schritt darin zu verstehen, ob es nur Zugriff auf die aktuelle Workload gewährt oder auf eine deutlich größere control plane.

### Vollständiges Beispiel: Eingebettetes Secret im Image-Dateisystem

Wenn eine Build-Pipeline `.env`-Dateien oder Zugangsdaten in das finale Image kopiert hat, wird post-exploitation einfach:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Die Auswirkungen hängen von der Anwendung ab, aber embedded signing keys, JWT secrets oder cloud credentials können eine container compromise leicht in eine API compromise, lateral movement oder die Fälschung von trusted application tokens verwandeln.

### Vollständiges Beispiel: Build-Time Secret Leakage Check

Wenn die Befürchtung besteht, dass die image history eine secret-bearing layer erfasst hat:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Diese Art der Überprüfung ist nützlich, weil ein secret aus der finalen Ansicht des Dateisystems gelöscht worden sein kann, während es noch in einer früheren Schicht oder in Build-Metadaten vorhanden bleibt.

## Prüfungen

Diese Prüfungen dienen dazu festzustellen, ob das Image und die secret-handling-Pipeline wahrscheinlich die Angriffsfläche vor der Laufzeit vergrößert haben.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Was hier interessant ist:

- Eine verdächtige Build-Historie kann kopierte Anmeldeinformationen, SSH-Material oder unsichere Build-Schritte offenlegen.
- Secrets unter projected volume paths können zu Cluster- oder Cloud-Zugriff führen, nicht nur zu lokalem Anwendungszugriff.
- Eine große Anzahl von Konfigurationsdateien mit Klartext-Anmeldeinformationen deutet normalerweise darauf hin, dass das Image oder das Bereitstellungsmodell mehr Vertrauensmaterial trägt als nötig.

## Standardverhalten zur Laufzeit

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Schwächungen |
| --- | --- | --- | --- |
| Docker / BuildKit | Unterstützt sichere build-time Secret-Mounts, aber nicht automatisch | Secrets können während `build` flüchtig gemountet werden; Image-Signing und Scanning erfordern explizite Workflow-Entscheidungen | Kopieren von Secrets in das Image, Weitergabe von Secrets über `ARG` oder `ENV`, Deaktivierung von Provenance-Prüfungen |
| Podman / Buildah | Unterstützt OCI-native Builds und secret-aware Workflows | Starke Build-Workflows sind verfügbar, aber Betreiber müssen sie bewusst wählen | Einbetten von Secrets in Containerfiles, breite Build-Kontexte, permissive Bind-Mounts während Builds |
| Kubernetes | Native Secret-Objekte und projected volumes | Die Laufzeitbereitstellung von Secrets ist first-class, aber die Exposition hängt von RBAC, Pod-Design und Host-Mounts ab | Zu breite Secret-Mounts, Missbrauch von service-account tokens, `hostPath`-Zugriff auf kubelet-verwaltete Volumes |
| Registries | Integrität ist optional, sofern sie nicht erzwungen wird | Öffentliche und private Registries hängen beide von Richtlinien, Signing und Admission-Entscheidungen ab | Freies Ziehen unsigned images, schwache Admission-Kontrolle, schlechtes Key-Management |
{{#include ../../../banners/hacktricks-training.md}}
