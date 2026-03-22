# Image-Sicherheit, Signierung und Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Die Container-Sicherheit beginnt bereits vor dem Starten der Workload. Das Image bestimmt, welche Binaries, Interpreter, Bibliotheken, Startskripte und eingebetteten Konfigurationen in Produktion gelangen. Wenn das Image mit einer Backdoor versehen, veraltet oder mit eingebetteten Secrets gebaut ist, arbeitet das anschließende Runtime-Hardening bereits an einem kompromittierten Artefakt.

Deshalb gehören Image-Herkunft, Schwachstellen-Scanning, Signaturprüfung und der Umgang mit Secrets in dieselbe Diskussion wie namespaces und seccomp. Sie schützen eine andere Phase des Lifecycles, aber Fehler hier definieren oft die Angriffsfläche, die die Runtime später eingrenzen muss.

## Image-Registries und Vertrauen

Images können aus öffentlichen Registries wie Docker Hub oder aus privaten Registries stammen, die von einer Organisation betrieben werden. Die Sicherheitsfrage ist nicht allein, wo das Image gespeichert ist, sondern ob das Team Herkunft und Integrität nachweisen kann. Das Herunterladen unsignierter oder schlecht nachverfolgter Images aus öffentlichen Quellen erhöht das Risiko, dass bösartiger oder manipulierte Inhalt in die Produktion gelangt. Selbst intern gehostete Registries benötigen klare Zuständigkeiten, Review- und Vertrauensrichtlinien.

Docker Content Trust nutzte historisch Konzepte aus Notary und TUF, um signierte Images zu erzwingen. Das genaue Ökosystem hat sich weiterentwickelt, aber die dauerhafte Lehre bleibt nützlich: Image-Identität und Integrität sollten verifizierbar sein, statt vorausgesetzt zu werden.

Beispiel eines historischen Docker Content Trust Workflows:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Der Punkt des Beispiels ist nicht, dass jedes Team weiterhin dasselbe tooling verwenden muss, sondern dass signing und key management operative Aufgaben sind, keine abstrakte Theorie.

## Vulnerability Scanning

Image scanning hilft, zwei verschiedene Fragen zu beantworten. Erstens: Enthält das image bekannte vulnerable packages oder libraries? Zweitens: Enthält das image unnötige Software, die die attack surface vergrößert? Ein image voller debugging tools, shells, interpreters und veralteter packages ist sowohl leichter auszunutzen als auch schwerer nachzuvollziehen.

Beispiele für häufig verwendete Scanner sind:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Die Ergebnisse dieser Tools sollten mit Vorsicht interpretiert werden. Eine Schwachstelle in einem ungenutzten Paket stellt nicht dasselbe Risiko dar wie ein offener RCE-Pfad, aber beide sind dennoch relevant für hardening decisions.

## Geheimnisse zur Build-Zeit

Einer der ältesten Fehler in Container-Build-Pipelines ist, Geheimnisse direkt in das Image einzubetten oder sie über Umgebungsvariablen weiterzugeben, die später durch `docker inspect`, build logs oder wiederhergestellte Layers sichtbar werden. Geheimnisse zur Build-Zeit sollten während des Builds ephemerisch gemountet werden, anstatt in das Image-Dateisystem kopiert zu werden.

BuildKit hat dieses Modell verbessert, indem es eine dedizierte Handhabung von Geheimnissen zur Build-Zeit ermöglicht. Anstatt ein Geheimnis in eine Layer zu schreiben, kann der Build-Schritt es vorübergehend verwenden:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Das ist wichtig, weil Image-Layer dauerhafte Artefakte sind. Sobald ein Secret in eine committed Layer gelangt, entfernt das spätere Löschen der Datei in einer anderen Layer nicht wirklich die ursprüngliche Offenlegung aus der Image-Historie.

## Laufzeit-Secrets

Für von einem laufenden Workload benötigte Secrets sollte man ebenfalls ad-hoc-Muster wie einfache Umgebungsvariablen nach Möglichkeit vermeiden. Volumes, dedizierte Secret-Management-Integrationen, Docker secrets und Kubernetes Secrets sind gängige Mechanismen. Keiner von diesen beseitigt alle Risiken, insbesondere wenn ein Angreifer bereits Codeausführung im Workload hat, aber sie sind dennoch einer dauerhaften Speicherung von Zugangsdaten im Image oder dem beiläufigen Offenlegen durch Inspektionstools vorzuziehen.

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
In Kubernetes schaffen Secret objects, projected volumes, service-account tokens und cloud workload identities ein breiteres und leistungsfähigeres Modell, bieten aber auch mehr Möglichkeiten für unbeabsichtigte Offenlegung durch host mounts, weit gefasste RBAC-Rechte oder schwaches Pod-Design.

## Missbrauch

Bei der Überprüfung eines Ziels soll ermittelt werden, ob secrets in das image gebacken, leaked in die layers oder in vorhersehbare runtime-Locations gemountet wurden:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Diese Befehle helfen dabei, zwischen drei verschiedenen Problemen zu unterscheiden: Anwendungs-Konfigurations leaks, image-layer leaks und runtime-injected secret files. Wenn ein secret unter `/run/secrets`, einem projected volume oder einem cloud identity token path erscheint, besteht der nächste Schritt darin zu verstehen, ob es nur Zugriff auf die aktuelle workload gewährt oder auf eine deutlich größere control plane.

### Vollständiges Beispiel: Embedded Secret im Image-Filesystem

Wenn eine Build-Pipeline `.env`-Dateien oder Zugangsdaten in das finale Image kopiert hat, wird post-exploitation einfach:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Die Auswirkungen hängen von der Anwendung ab, aber eingebettete Signierschlüssel, JWT-Secrets oder Cloud-Anmeldeinformationen können eine Kompromittierung des Containers leicht in eine Kompromittierung der API, lateral movement oder die Fälschung vertrauenswürdiger Anwendungstoken verwandeln.

### Vollständiges Beispiel: Build-Time Secret Leakage Check

Wenn die Befürchtung besteht, dass die Image-History eine secret-bearing layer erfasst hat:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Diese Art der Überprüfung ist nützlich, weil ein secret aus der finalen Dateisystemansicht gelöscht worden sein kann, während es weiterhin in einer früheren Layer oder in Build-Metadaten vorhanden ist.

## Prüfungen

Diese Prüfungen sollen feststellen, ob die image- und secret-handling-Pipeline wahrscheinlich die attack surface vor runtime vergrößert hat.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Was hier auffällt:

- Eine auffällige Build-Historie kann kopierte credentials, SSH-Material oder unsichere Build-Schritte offenbaren.
- Secrets unter projected volume paths können zu Cluster- oder Cloud-Zugriff führen, nicht nur zu lokalem Anwendungszugriff.
- Eine große Anzahl von Konfigurationsdateien mit plaintext credentials deutet meist darauf hin, dass das Image oder das Deployment-Modell mehr trust material trägt als nötig.

## Laufzeit-Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Supports secure build-time secret mounts, but not automatically | Secrets can be mounted ephemerally during `build`; image signing and scanning require explicit workflow choices | copying secrets into the image, passing secrets by `ARG` or `ENV`, disabling provenance checks |
| Podman / Buildah | Supports OCI-native builds and secret-aware workflows | Strong build workflows are available, but operators must still choose them intentionally | embedding secrets in Containerfiles, broad build contexts, permissive bind mounts during builds |
| Kubernetes | Native Secret objects and projected volumes | Runtime secret delivery is first-class, but exposure depends on RBAC, pod design, and host mounts | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Integrity is optional unless enforced | Public and private registries both depend on policy, signing, and admission decisions | pulling unsigned images freely, weak admission control, poor key management |
{{#include ../../../banners/hacktricks-training.md}}
